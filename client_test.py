from redist.pydhcplib.dhcp_network import DhcpClient

class Client(DhcpClient):
    def HandleDhcpAll(self, packet):
        print("PACKET = %s" % packet.str())

if __name__ == '__main__':

    c = Client(listen_address="enx9405bb182067", client_listen_port=68, server_listen_port=67)
    c.BindToDevice()

    while True:
        c.GetNextDhcpPacket()
