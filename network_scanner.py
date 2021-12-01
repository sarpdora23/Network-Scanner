import scapy.all as scapy
import optparse
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="IP addreses range more -r")
    (options,arguments) = parser.parse_args()
    if not options.target:
        parser.error("Please give IP range more info --help")
    else:
        return options.target
def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether("ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast,timeout = 1)[0]
    print("IP\t\t\tMAC Address\n-----------------------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t\t"+element[1].hwsrc)
        print("----------------------------------------")
scan(get_arguments())