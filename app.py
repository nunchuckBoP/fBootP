from threading import Lock
from flask import Flask, render_template, session, request, \
    copy_current_request_context
from flask_socketio import SocketIO, emit, disconnect
import random
from time import sleep

from socketio import server
from cDhcp import SyncDhcpServer
from redist import pydhcplib
from redist.pydhcplib.type_ipv4 import ipv4
import traceback

# global MAC / IP Relations for the server
# MAC address is the dictionary key
# {"mac":<MAC ADDRESS>, "ip":<IP ADDRESS>, "assigned":<assigned>}
#####################################################################
relations = [
    {'mac':'reserved','ip':'reserved','assigned':False}, # for button / input row
]

# {"mac":<MAC ADDRESS>, "count":<REQUEST COUNT>, "ip":<ASSIGNED IP>}
requests = []
server_status = "STOPPED"
pending_assignments = {}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode=None)
thread = None
thread_lock = Lock()
server_running = False

def get_mac_in_table(mac_address, table):
    table_row_count = len(table)
    for i in range(0, table_row_count):
        if table[i]['mac'] == mac_address:
            return {"row": i, "data":table[i]['mac']}
        # end if
    # end for
    return False

def update_request_count(_mac_address):

    # updates the requests dictionary and increments
    # the request count.
    # look for mac address in requests table
    result = get_mac_in_table(_mac_address, requests)
    if result:
        #data = result['data']
        row_number = result['row']
        count = requests[row_number]['count']
        requests[row_number]['count'] = count + 1

        # send the update table cell to the connected browsers
        socketio.emit('update_table', 
            {
                'table':'request', 
                'row':row_number + 1, # header is a row as well
                'data':requests[row_number]
            }
        )

    else:
        # add the record to the table
        _data = {"mac" : _mac_address, "count" : 1, "ip" : None}
        requests.append(
            _data
        )
        socketio.emit("update_table",
            {
                'table':'request',
                'row':len(requests),
                'data':_data
            }
        )

def update_ip_assignment(_mac_address, _ip_address):
    # updates both the requests and relations tables
    # to assign the IP address to the mac address
    result = get_mac_in_table(_mac_address, requests)
    if result:
        row_number = result['row']

        # updates the IP address
        requests[row_number]['ip'] = str(_ip_address)

        # send the update table cell to the connected browsers
        socketio.emit('update_table', 
            {
                'table':'request', 
                'row':row_number + 1, # header is a row as well
                'data':requests[row_number]
            }
        )

    result = get_mac_in_table(_mac_address, relations)
    if result:
        row_number = result['row']

        # updates the assigned field
        relations[row_number]['assigned'] = True

        socketio.emit('update_table',
            {
                'table':'relation',
                'row':row_number + 1,
                'data':relations[row_number]
            }
        )

def set_server_status(status):
    global server_status
    if server_status != status:
        server_status = status

        socketio.emit(
            "update_server_status",
            {'data':server_status}
        )

def background_thread():
    
    global relations
    global requests
    global server_running

    socketio.emit("server_event", {"data":"Starting DHCP Server..."})
    
    server_options = {
        'client_listen_port':"68",
        'server_listen_port': "67",
        'listen_address': "0.0.0.0"
    }
    try:
        dhcp = SyncDhcpServer(**server_options)
        server_running = True
        set_server_status("RUNNING")
    except Exception as ex:
        print("ERROR: %s" % ex)
        set_server_status("FAULTED")
        socketio.emit(
            "server_event",
            {'data': 'ERROR ON DHCP SERVER CREATION - %s \nTraceback:\n%s' % (ex, "\n".join(traceback.format_stack()))}
        )
    
    listening_printed = False

    while server_running:

        # update the server status again, so we can get this
        # every time
        set_server_status("RUNNING")

        # sleep for ten seconds. Only valid in 
        # test mode
        if not listening_printed:
            socketio.emit("server_event", {"data":"Listening for DHCP Packets..."})
            listening_printed = True
        
        ##############################################
        # Get the next dhcp packet. This is a blocking
        # call.
        ##############################################
        packet = dhcp.GetNextDhcpPacket(timeout=10) # 10 seconds?

        if packet is not None:

            if packet.IsDhcpDiscoverPacket():
                # DHCP discover, device is sending out messages
                # requesting a DHCP server provide an ip address
                discover_packet = packet

                # if the mac is in the table, create and send the
                # DHCP offer message
                print("DISCOVER PACKET = %s" % discover_packet.str())
                socketio.emit("server_event", {"data":"Received DHCP Packet from MAC address %s" % discover_packet.GetMacAddressString()})

                # update the request table and send out update socket
                # message for the browser to update the table
                update_request_count(discover_packet.GetMacAddressString())

                # check and see if the mac address is in the relations 
                # dictionary.
                result = get_mac_in_table(discover_packet.GetMacAddressString(), relations)
                if result:
                    row_number = result['row']
                    data = relations[row_number]
                    new_ip = data['ip']

                    #########################################
                    # SEND OUT DHCP MESSAGE TO THE MAC
                    #       MAC ADDRESS AND ASSIGN THE IP
                    #########################################

                    # converts the packet to an offer packet
                    packet.CreateDhcpOfferPacketFrom(discover_packet)

                    # sets the offered ip address value
                    print("new ip: %s" % new_ip)
                    _ip = ipv4(new_ip)

                    # sets the packet siaddr option to offer the client
                    # the ip address
                    _suc = packet.SetOption('yiaddr', _ip)
                    
                    # print the packet
                    print("DHCP OFFER PACKET = %s" % packet.str())

                    if _suc:                   # sends the packet
                        dhcp.SendDhcpPacketTo(packet, "", 67)

                        # add the mac address to the pending ip assignments
                        pending_assignments[packet.GetMacAddressString()] = str(_ip)
                # end if

            elif packet.IsDhcpRequestPacket():
                print("REQUEST PACKET = %s" % packet.str())
                if packet.GetMacAddressString() in pending_assignments:

                    request_packet = packet

                    # get pending ip address
                    _pending_ip = ipv4(pending_assignments[packet.GetMacAddressString()])

                    # check if the packet address is the same as what is expected
                    _requested_ip = ipv4(request_packet.GetOption('siaddr'))

                    if _pending_ip.str() == _requested_ip.str():

                        packet.CreateDhcpAckPacketFrom(request_packet)
                        dhcp.SendDhcpPacketTo(packet, '', 67)

                        # update the tables
                        update_ip_assignment(packet.GetMacAddressString(), _pending_ip)

                        # pop the ip off of the pending address
                        pending_assignments.pop(packet.GetMacAddressString())
                    else:
                        # if the requested IP address does not match, send back an 
                        # not acknowledged packet.
                        packet.CreateDhcpNackPacketFrom(request_packet)
                        dhcp.SendDhcpPacketTo(packet, '', 67)

            else:
                print("OTHER PACKET = %s" % packet.str())

        else: # if dhcp packet is None
            continue
        # end
    # end while loop
# end background thread

@app.route('/')
def index():
    return render_template('index.html', 
        title="CCS BOOTP / DHCP Server Copywrite (2022)",
        relations=relations,
        requests=requests,
        server_status=server_status
    )

@socketio.event
def connect():
    emit('server_event', {'data':'Browser connected to web socket (socketio)'})
    
@socketio.event
def start_server(msg):
    global thread
    
    print("Aquiring thread lock.")
    thread_lock.acquire()
    
    if thread is None:
        thread = socketio.start_background_task(background_thread)

@socketio.event
def stop_server(msg):
    
    global server_running
    global thread

    server_running = False

    # trigger stopping event tigger
    socketio.emit(
        "server_stopping", {"data":None}
    )
    set_server_status("STOPPING (COULD TAKE UP TO 10 SECONDS)")

    #print("Joining thread.")
    thread.join()

    thread_lock.release()
    thread = None

    socketio.emit(
        "server_stopped",{'data':None}
    )
    set_server_status("STOPPED")

@socketio.event
def disconnect():
    emit('server_event', {'data':'Browser disconnected from web socket (socketio)'})
    #disconnect()

@socketio.event
def add_relation(message):

    result = get_mac_in_table(message['mac'], relations)
    if result:
        # ignore the request because it's already in the tabls
        pass
    else:
        _data = {'mac':message['mac'], 'ip':message['ip']}
        if 'assigned' in message:
            _data['assigned'] = message['assigned']
        else:
            _data['assigned'] = False
        # end if

        relations.append(_data)

        # emit the update table routine
        emit(
            "update_table",
            {
                'table':'relation',
                'row':len(relations),
                'data':_data
            }
        )

if __name__ == '__main__':
    socketio.run(app)

