from threading import Lock
from flask import Flask, render_template, session, request, \
    copy_current_request_context
from flask_socketio import SocketIO, emit, disconnect
import random
from time import sleep
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
    if server_status != status:
        server_status = status

        socketio.emit(
            "update_server_status",
            {'data':server_status}
        )

def background_thread():
    
    global server_status
    global relations
    global requests

    socketio.emit("server_event", {"data":"Starting DHCP Server..."})
    
    dhcp_server_created = False
    server_options = {
        'client_listen_port':"68",
        'server_listen_port': "67",
        'listen_address': "0.0.0.0"
    }
    try:
        dhcp = SyncDhcpServer(**server_options)
        dhcp_server_created = True
        set_server_status("RUNNING")
    except Exception as ex:
        print("ERROR: %s" % ex)
        set_server_status("FAULTED")
        socketio.emit(
            "server_event",
            {'data': 'ERROR ON DHCP SERVER CREATION - %s \nTraceback:\n%s' % (ex, "\n".join(traceback.format_stack()))}
        )
    
    while dhcp_server_created:

        # update the server status again, so we can get this
        # every time
        set_server_status("RUNNING")

        # sleep for ten seconds. Only valid in 
        # test mode
        socketio.emit("server_event", {"data":"Listening for DHCP Packets..."})
        
        ##############################################
        # Get the next dhcp packet. This is a blocking
        # call.
        ##############################################
        packet = dhcp.GetNextDhcpPacket(timeout=60) # 60 minutes?

        if packet is not None:

            if packet.IsDhcpDiscoverPacket():
                # DHCP discover, device is sending out messages
                # requesting a DHCP server provide an ip address

                # if the mac is in the table, create and send the
                # DHCP offer message
                print("PACKET = %s" % packet.str())
                discover_packet = packet.CreateDhcpOfferPacketFrom(packet)
                socketio.emit("server_event", {"data":"Received DHCP Packet from MAC address %s" % packet.GetMacAddressString()})

                # update the request table and send out update socket
                # message for the browser to update the table
                update_request_count(packet.GetMacAddressString())

                # check and see if the mac address is in the relations 
                # dictionary.
                result = get_mac_in_table(packet.GetMacAddressString(), relations)
                if result:
                    row_number = result['row']
                    data = relations[row_number]
                    new_ip = data['ip']

                    #########################################
                    # SEND OUT DHCP MESSAGE TO THE MAC
                    #       MAC ADDRESS AND ASSIGN THE IP
                    #########################################
                    _ip = ipv4(new_ip)                
                    dhcp.SendDhcpPacketTo(discover_packet, str(_ip), 67)

                    # add the mac address to the pending ip assignments
                    pending_assignments[packet.GetMacAddressString()] = str(_ip)
                # end if

            elif packet.IsDhcpRequestPacket():
                
                if packet.GetMacAddressString() in pending_assignments:
                    # get pending ip address
                    _pending_ip = pending_assignments[packet.GetMacAddressString()]

                    dhcp_ack_packet = packet.CreateDhcpAckPacketFrom(packet)
                    dhcp.SendDhcpPacketTo(dhcp_ack_packet, _pending_ip, 67)

                    # update the tables
                    update_ip_assignment(packet.GetMacAddressString(), _pending_ip)

                    # pop the ip off of the pending address
                    pending_assignments.pop(packet.GetMacAddressString())

            else:
                print("Unsupported or ignored DHCP packet.")
                print(str(packet))

        else: # if dhcp packet is None
            pass
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
    with thread_lock:
        if thread is None:
            thread = socketio.start_background_task(background_thread)

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

