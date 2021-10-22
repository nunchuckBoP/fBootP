from threading import Lock
from flask import Flask, render_template, session, request, \
    copy_current_request_context
from flask_socketio import SocketIO, emit, disconnect
import random
from time import sleep

# global MAC / IP Relations for the server
# MAC address is the dictionary key
# {"mac":<MAC ADDRESS>, "ip":<IP ADDRESS>, "assigned":<assigned>}
#####################################################################
relations = [
    {'mac':'reserved','ip':'reserved','assigned':False}, # for button / input row
]

# {"mac":<MAC ADDRESS>, "count":<REQUEST COUNT>, "ip":<ASSIGNED IP>}
requests = []

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode=None)
thread = None
thread_lock = Lock()

def on_dhcp_discover(self):
    pass
def on_dhcp_accept(self):
    pass

def get_mac_in_table(mac_address, table):
    table_row_count = len(table)
    for i in range(0, table_row_count):
        if table[i]['mac'] == mac_address:
            return {"row": i, "data":table[i]['mac']}
        # end if
    # end for
    return False

def background_thread():
    """
        Simulation of background thread generating mac address, DHCP requests
    """
    socketio.emit("server_event", {"data":"Starting DHCP Server..."})
    socketio.sleep(1)
    socketio.emit("update_server_status", {'data':'RUNNING'})
    socketio.sleep(1)
    
    mac_addresses = [
        "12:A4:E3:B1:22",
        "12:A4:E3:B1:23",
        "12:A4:E3:B1:24",
        "12:A4:E3:B1:25"
    ]
    while True:

        # sleep for ten seconds. Only valid in 
        # test mode
        socketio.emit("server_event", {"data":"Listening for DHCP Packets..."})
        socketio.sleep(1)
        
        # pick a mac address at random
        _mac = random.choice(mac_addresses)
        ##############################################
        # TODO: LISTEN FOR A DHCP SERVER REQUEST
        #       AND PARSE THE MAC ADDRESS.
        #       **NEEDS TO BE A BLOCKING CALL**.
        #       We'll also have to monitor the DHCP
        #       ACCEPT packets so we know what mac
        #       Adresses got assigned IP addresses
        ##############################################
        socketio.emit("server_event", {"data":"Received DHCP Packet from MAC address %s" % _mac})

        # updates the requests dictionary and increments
        # the request count.
        # look for mac address in requests table
        result = get_mac_in_table(_mac, requests)
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
            _data = {"mac" : _mac, "count" : 1, "ip" : None}
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

        # check and see if the mac address is in the relations 
        # dictionary.
        result = get_mac_in_table(_mac, relations)
        if result:
            row_number = result['row']
            data = relations[row_number]
            new_ip = data['ip']

            #########################################
            # TODO: SEND OUT DHCP MESSAGE TO THE MAC
            #       MAC ADDRESS AND ASSIGN THE IP
            #########################################
            # dhcpserver.send(_mac, new_ip)

            print("ASSIGNING IP ADDRESS: %s TO %s" % (new_ip, _mac))

    # end while loop
# end background thread

@app.route('/')
def index():
    if thread:
        if thread.is_alive:
            status = "RUNNING"
        else:
            status = "STOPPED"
    else:
        status = "STOPPED"
    return render_template('index.html', 
        title="CCS BOOTP / DHCP Server Copywrite (2022)",
        relations=relations,
        requests=requests,
        status = status
    )

@socketio.event
def connect():
    global thread

    emit('server_event', {'data':'Browser connected to web socket (socketio)'})
    
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

