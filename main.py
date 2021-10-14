import os.path
from binascii import hexlify

from scapy.all import *


class Packet:
    def __init__(self, id):
        self.id = id
        self.dst_mac = []
        self.src_mac = []
        self.cap_len = 0
        self.all_len = 4
        self.ether_type = 0
        self.ieee_type = 0
        self.frame_type = ""
        self.protocol = ""
        self.inner_protocol = ""
        self.inner_protocol_type = ""
        self.byte_field = bytearray()
        self.dsap = ""
        self.ssap = ""
        self.ethernetII = False
        self.ip = False
        self.tcp = False
        self.udp = False
        self.arp = False
        self.src_port = 0
        self.dst_port = 0
        self.src_ip = ""
        self.dst_ip = ""
        self.tr_ips = []
        self.mtr_ip = ""


packet_list = []
ether_types = {}
llc_types = {}
tcp_ports = {}
udp_ports = {}
icmp_types = {}
ip_protocols = {}
arps = {}
snap_types = {}
ip_dict = {}


def load_from_file(file, dictionary):
    o_file = open(file, "r")
    # for line in o_file:
    #    (key, val) = line.split()
    #    dictionary[int(key, 16)] = val
    for line in open(file, "r"):
        processed = line.split(' ', 1)
        dictionary[int(processed[0], 16)] = processed[1].replace("\n", "")


def load_types(ether_dict, llc_dict, tcp_dict, udp_dict, icmp_dict, ip_dict, snap_dict):
    load_from_file("dict/ether_types.txt", ether_dict)
    load_from_file("dict/llc_saps.txt", llc_dict)
    load_from_file("dict/tcp_ports.txt", tcp_dict)
    load_from_file("dict/udp_ports.txt", udp_dict)
    load_from_file("dict/icmp_types.txt", icmp_dict)
    load_from_file("dict/ip_protocols.txt", ip_dict)
    load_from_file("dict/snap_types.txt", snap_dict)


def getData():
    filename = input("Zadaj meno súboru ktorý chceš analyzovať: ")
    while not os.path.exists('./pcap/' + filename):
        print("Súbor " + filename + " neexistuje.")
        filename = input("Zadaj meno súboru ktorý chceš analyzovať: ")
    return rdpcap('./pcap/' + filename)


def get_data_from_bytes(frame, start_byte, end_byte, result_in_integer=False):
    if result_in_integer:
        return int(hexlify(frame[start_byte:(end_byte + 1)]), 16)
    else:
        return frame[start_byte:(end_byte + 1)]


def get_frame_type(ether_value, ieee_value):
    if ether_value >= 1500:
        return "Ethernet II"
    elif ieee_value == 0xAAAA:
        return "IEEE 802.3 LLC + SNAP"
    elif ieee_value == 0xFFFF:
        return "IEEE 802.3 RAW"
    else:
        return "IEEE 802.3 LLC"


def bytefield_to_strdict(byte_field):
    str_dict = []
    for byte in byte_field:
        str_dict.append(str(byte))
    return str_dict


def get_ip_addresses(src_adr, dst_adr, tmp):
    tmp.src_ip = ".".join(bytefield_to_strdict(src_adr))
    tmp.dst_ip = ".".join(bytefield_to_strdict(dst_adr))


def get_ip_address(src_adr):
    src_ip = ".".join(bytefield_to_strdict(src_adr))
    return src_ip


def port_set_and_check(frame, pkt, port_dict):
    # source port
    pkt.src_port = get_data_from_bytes(frame, 34, 35, True)
    if pkt.src_port in port_dict:
        pkt.inner_protocol_type = port_dict.get(pkt.src_port)
        pkt.dst_port = get_data_from_bytes(frame, 36, 37, True)
    else:
        # destination port
        pkt.dst_port = get_data_from_bytes(frame, 36, 37, True)
        if pkt.dst_port in port_dict:
            pkt.inner_protocol_type = port_dict.get(pkt.dst_port)


def insert_ip(frame, dict):
    src_ip = get_data_from_bytes(frame, 26, 29)
    if src_ip in dict:
        dict[src_ip] += 1
    else:
        dict[src_ip] = 1


def get_inner_protocol(frame, ether_value, ieee_value, pkt):
    if ether_value >= 1500:
        # zisime ethertype
        if ether_value in ether_types:
            pkt.protocol = ether_types.get(ether_value)
        else:
            pkt.protocol = "Neznámy"
            return

        # IPv4
        if ether_value == 2048:
            insert_ip(frame, ip_dict)
            # zistime IP adresy
            get_ip_addresses(get_data_from_bytes(frame, 26, 29), get_data_from_bytes(frame, 30, 33), pkt)
            # zisteni IP protocolu
            ip_head_num = get_data_from_bytes(frame, 23, 23, True)
            if ip_head_num in ip_protocols:
                pkt.inner_protocol = ip_protocols.get(ip_head_num)
                # Ked ICMP
                if ip_head_num == 1:
                    icmp_type = get_data_from_bytes(frame, 0, 0, True)
                    # zisti typ ICMP
                    if icmp_type in icmp_types:
                        pkt.inner_protocol_type = icmp_types.get(icmp_type)
                        return
                # TCP
                elif ip_head_num == 6:
                    port_set_and_check(frame, pkt, tcp_ports)
                    return

                # UDP
                elif ip_head_num == 17:
                    port_set_and_check(frame, pkt, udp_ports)
                    return
            else:
                pkt.inner_protocol = "Neznámy"
            return

        # ARP
        elif ether_value == 2054:
            if get_data_from_bytes(frame, 20, 21, True) == 1:
                pkt.inner_protocol = "ARP Request"
            else:
                pkt.inner_protocol = "ARP Reply"
            # zistime IP adresy
            get_ip_addresses(get_data_from_bytes(frame, 28, 31), get_data_from_bytes(frame, 38, 41), pkt)
            return
        else:
            pkt.inner_protocol = "Neznámy"

    # ieee + snap
    elif ieee_value == 43690:
        if ether_value in ether_types:
            pkt.protocol = ether_types.get(ether_value)
        else:
            pkt.protocol = "Neznámy"
    # ieee
    elif get_data_from_bytes(frame, 14, 14, True) in llc_types:
        pkt.protocol = llc_types.get(get_data_from_bytes(frame, 14, 14, True))
    elif ieee_value == 65535:
        pkt.protocol = "IPX"


def set_length(pkt):
    pkt.cap_len = len(pkt.byte_field)
    pkt.all_len += pkt.cap_len
    if pkt.all_len < 64:
        pkt.all_len = 64


def process_packets(p_data):
    id = 0
    for packet in p_data:
        id += 1
        pkt = Packet(id)
        pkt.byte_field = bytes(packet)
        set_length(pkt)
        pkt.dst_mac = get_data_from_bytes(pkt.byte_field, 0, 5)
        pkt.src_mac = get_data_from_bytes(pkt.byte_field, 6, 11)
        pkt.ether_type = get_data_from_bytes(pkt.byte_field, 12, 13, True)
        pkt.ieee_type = get_data_from_bytes(pkt.byte_field, 14, 15, True)
        pkt.frame_type = get_frame_type(pkt.ether_type, pkt.ieee_type)
        get_inner_protocol(pkt.byte_field, pkt.ether_type, pkt.ieee_type, pkt)
        packet_list.append(pkt)


def print_packet(packet_in_bytes, file):
    counter = 0
    for byte in packet_in_bytes:
        counter += 1
        file.write('%02x ' % byte)
        if counter % 8 == 0:
            if counter % 16 == 0:
                file.write("\n")
            else:
                file.write("\t")
    file.write("\n")


def print_macs(src_mac, dst_mac, file):
    file.write("Zdrojová MAC adresa: ")
    for i in range(6):
        file.write('%02x ' % src_mac[i])
    file.write("\nCieľová  MAC adresa: ")
    for i in range(6):
        file.write('%02x ' % dst_mac[i])
    file.write("\n")


def print_packet_info(file):
    for pkt in packet_list:
        file.write(55 * "-" + "\n")
        file.write("Rámec č. " + pkt.id.__str__() + "\n")
        file.write("Dĺžka rámca poskytnutá pcap API – " + pkt.cap_len.__str__() + "\n")
        file.write("Dĺžka rámca prenášaného po médiu - " + pkt.all_len.__str__() + "\n")
        file.write("Typ rámca: " + pkt.frame_type + "\n")
        print_macs(pkt.src_mac, pkt.dst_mac, file)
        file.write("Typ protokolu: " + pkt.protocol + "\n")
        if pkt.protocol != "Neznámy" and pkt.protocol != "" and pkt.ether_type >= 1500:
            file.write("Typ vnoreneho protokolu: " + pkt.inner_protocol + "\n")
            if pkt.inner_protocol == "UDP" or pkt.inner_protocol == "TCP":
                file.write("Zdrojová IP adresa: " + pkt.src_ip + "\n")
                file.write("Cielova IP adresa: " + pkt.dst_ip + "\n")
            if pkt.inner_protocol != "Neznámy" and pkt.inner_protocol_type != "":
                file.write(pkt.inner_protocol_type + "\n")
                if pkt.inner_protocol_type == "HTTP":
                    file.write("Zdrojový port: " + pkt.src_port.__str__() + "\n")
                    file.write("Cieľový port: " + pkt.dst_port.__str__() + "\n")

        print_packet(pkt.byte_field, file)


def get_output():
    filename = input("Zadaj meno výstupného súboru bez txt: ")
    filename += ".txt"
    return open(filename, "w", encoding="utf-8")


def print_ip_dict(file):
    file.write("IP adresy vysielajúcich uzlov:\n")
    for ip in ip_dict:
        file.write(get_ip_address(ip) + "\n")
    file.write("\nAdresa uzla s najväčším počtom odoslaných paketov:\n")
    file.write(get_ip_address(max(ip_dict, key=ip_dict.get)) + "\t" + ip_dict.get(max(ip_dict, key=ip_dict.get)).__str__() + " paketov\n")


load_types(ether_types, llc_types, tcp_ports, udp_ports, icmp_types, ip_protocols, snap_types)
packet_data = getData()
output_file = get_output()
process_packets(packet_data)
print_packet_info(output_file)
print_ip_dict(output_file)
