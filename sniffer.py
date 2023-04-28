from scapy.all import *


def main():
    """Driver function"""
    while True:
        print_menu()
        option = input('Choose a menu option: ')
        if option == '1':
            print("Creating and sending packets ...")
            # TODO
            num_packets = int(input("How many packets? "))
            interval = float(input("How many seconds in between sending? "))
            send_pkt(num_packets,interval)
        elif option == '2':
            print("Listening to all traffic to 8.8.4.4 for 1 minute ...")
            # TODO
            sniff(filter="host 8.8.4.4", prn=print_pkt, timeout=60)
        elif option == '3':
            print("Listening continuously to only ping commands to 8.8.4.4 ...")
            # TODO
            sniff(filter="icmp and host 8.8.4.4", prn=print_pkt)
        elif option == '4':
            print("Listening continuously to only outgoing telnet commands ...")
            # TODO
            sniff(filter="tcp and dst port 23", prn=print_pkt)
        elif option == '5':
            print("End")
            break
        else:
            print(f"\nInvalid entry\n")


def send_pkt(number, interval):
    """
    Send a custom packet with the following fields

    #### Ethernet layer
    - Source MAC address: 00:11:22:33:44:55
    - Destination MAC address: 55:44:33:22:11:00
    

    #### IP layer
    - Source address: 192.168.10.4
    - Destination address: 8.8.4.4
    - Protocol: TCP
    - TTL: 26

    #### TCP layer
    - Source port: 23
    - Destination port: 80

    #### Raw payload
    - Payload: "RISC-V Education: https://riscvedu.org/"
    """

    # TODO
    ether=Ether()
    ether.src="00:11:22:33:44:55"
    ether.dst="55:44:33:22:11:00"
    pkt = IP()
    pkt.dst = "8.8.4.4"
    pkt.src = "192.168.10.4"
    pkt.ttl=26
    ip_layer=TCP()
    ip_layer.sport=23
    ip_layer.dport=80
    payload=b"RISC-V Education: https://riscvedu.org/"
    packet=ether/pkt/ip_layer/payload
    sendp(packet,inter=interval,count=number)
    


def print_pkt(packet):
    """ 
    Print Packet fields

    - Source IP
    - Destination IP
    - Protocol number
    - TTL
    - Length in bytes
    - Raw payload (if any)
    """

    # TODO
    print("Source IP: ",packet[IP].src)
    print("Destination IP: ",packet[IP].dst)
    print("Protocol number: ",packet[IP].proto)
    print("TTL: ",packet[IP].ttl)
    print("Length in bytes: ",len(packet))
    if packet.haslayer(Raw):
        print("Raw payload: ",packet[Raw].load)
    else:
        print("Raw payload: None")
    

def print_menu():
    """Prints the menu of options"""
    print("*******************Main Menu*******************")
    print('1. Create and send packets')
    print('2. Listen to all traffic to 8.8.4.4 for 1 minute')
    print('3. Listen continuously to only ping commands to 8.8.4.4')
    print('4. Listen continuously to only outgoing telnet commands')
    print('5. Quit')
    print('***********************************************\n')


main()
