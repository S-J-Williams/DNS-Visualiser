import socket, sys, binascii
from struct import *


#----- HELPER FUNCTIONS -----#
def mac_format(a):
    return ':'.join([a[i:i + 2] for i in range(0, len(a), 2)])


#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except:
    print('Socket could not be created')
    sys.exit()


mac_addresses = []
ip_addresses = []
packet_counter = 0

for i in range(0, 99):
#while(True):

    # receive a packet
    packet = s.recvfrom(65565)
    packet_counter = packet_counter + 1
    packet = packet[0]
     
    #parse ethernet header
    eth_header_len = 14
    eth_header = packet[:eth_header_len]
    eth_header = unpack('!6s6sH' , eth_header)

    #Extract information
    dst_mac = mac_format(eth_header[0].hex())
    src_mac = mac_format(eth_header[1].hex())
    eth_protocol = eth_header[2]

    #Print information
    print("\n")
    print("+---- ETHERNET HEADER ----+")
    print("Destination MAC : " + dst_mac)
    print("Source MAC : " + src_mac)
    print("Ethernet Protocol : " + str(eth_protocol))

    #Record information
    if dst_mac not in mac_addresses:
        mac_addresses.append(dst_mac)
    if src_mac not in mac_addresses:
        mac_addresses.append(src_mac)

    if eth_protocol == 2048 : #IP
        #parse IP Packet
        ip_header = packet[14:34]
        ip_header = unpack('!BBHHHBBH4s4s' , ip_header)

        #Extract information
        version = ip_header[0] >> 4
        ihl = ip_header[0] & 0xF
        ihl = ihl * 4
        ip_header_len = ihl
        ttl = ip_header[5]
        ip_protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])

        #Print information
        print("+---- IP HEADER ----+")
        print("Version : " + str(version))
        print("IHL : " + str(ihl))
        print("Protocol : " + str(ip_protocol))
        print("TTL : " + str(ttl))
        print("Destination Address : " + dst_ip)
        print("Source Address : " + src_ip)

        #Record information
        if dst_ip not in ip_addresses:
            ip_addresses.append(dst_ip)
        if src_ip not in ip_addresses:
            ip_addresses.append(src_ip)


        if ip_protocol == 6 : #TCP
            tcp_header = ip_header_len + eth_header_len
            tcp_header = packet[tcp_header:tcp_header+20]
            tcp_header = unpack('!HHLLBBHHH' , tcp_header)

            #Extract information
            src_port = tcp_header[0]
            dst_port = tcp_header[1]
            seq_num = tcp_header[2]
            ack_num = tcp_header[3]
            tcp_header_len = (tcp_header[4] >> 4) * 4

            print("+---- TCP HEADER ----+")
            print("Source Port : " + str(src_port))
            print("Destination Port : " + str(dst_port))
            print("Sequence Number : " + str(seq_num))
            print("Acknowledgment Number : " + str(ack_num))
        
        elif ip_protocol == 17 : #UDP
            udp_header = ip_header_len + eth_header_len
            udp_header = packet[udp_header:udp_header+8]
            udp_header = unpack('!HHHH' , udp_header)

            #Extract information
            src_port = udp_header[0]
            dst_port = udp_header[1]
            length = udp_header[2]
            checksum = udp_header[3]

            print("+---- UDP HEADER ----+")
            print("Source Port : " + str(src_port))
            print("Destination Port : " + str(dst_port))
            print("Length : " +  str(length))
            print("Checksum : " + str(checksum))

            #if dst_port == 53 or src_port == 53 : #DNS ToDo

        elif ip_protocol == 1 : #ICMP
            icmp_header = ip_header_len + eth_header_len
            icmp_header = packet[icmp_header:icmp_header+4]
            icmp_header = unpack('!BBH' , icmp_header)

            #Extract information
            icmp_type = icmp_header[0]
            icmp_code = icmp_header[1]
            checksum = icmp_header[2]

            print("+---- ICMP Header ----+")
            print("Type : " + str(icmp_type))
            print("Code : " + str(icmp_code))
            print("Checksum : " + str(checksum))

        else:
            print("Protocol other than TCP/UDP/ICMP")


print("")
print("+---- Summary ----+")
print("Packets : " + str(packet_counter))
print("MAC Addresses : " + str(mac_addresses))
print("IP Addresses : " + str(ip_addresses))
