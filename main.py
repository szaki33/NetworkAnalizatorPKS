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


class ArpCommunication:
    frames = []
    dst_ip = ""
    src_ip = ""
    src_mac = []
    close = False

    def __init__(self, frame, ip_src, ip_dst, mac_src, close=False):
        self.frames = []
        self.frames.append(frame)
        self.src_ip = ip_src
        self.dst_ip = ip_dst
        self.src_mac = mac_src
        self.close = close


class TFTPCommunication:
    frames = []
    client_ip = ""
    server_ip = ""
    src_port = 0
    dst_port = 0
    opcode = ""
    wait_for_ack = False
    close = False
    success = False
    blocks = []

    def __init__(self, frame, srv_ip, client_ip, src_port, opcode):
        self.frames = []
        self.frames.append(frame)
        self.server_ip = srv_ip
        self.client_ip = client_ip
        self.src_mac = src_port
        self.type = opcode
        if opcode == "Read request":
            self.wait_for_ack = False
        if opcode == "Write request":
            self.wait_for_ack = True


class Block:
    def __init__(self, id):
        self.id = id
        self.acknowledged = False


packet_list = []
arp_communications = []
tftp_communications = []
ether_types = {}
llc_types = {}
tcp_ports = {}
udp_ports = {}
icmp_types = {}
ip_protocols = {}
arps = {}
snap_types = {}
ip_dict = {}
tftp_dict = {}
tftp_packets = []

def load_from_file(file, dictionary):
    o_file = open(file, "r")
    for line in o_file:
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
    load_from_file("dict/tftp_opcodes.txt", tftp_dict)


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


def print_packet_list(file):
    for pkt in packet_list:
        file.write(55 * "-" + "\n")
        file.write("Rámec č. " + pkt.id.__str__() + "\n")
        file.write("Dĺžka rámca poskytnutá pcap API – " + pkt.cap_len.__str__() + "B\n")
        file.write("Dĺžka rámca prenášaného po médiu - " + pkt.all_len.__str__() + "B\n")
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


def add_to_arp_com(communications, frame, src_ip, dst_ip, src_mac):
    # kontrola ci existuje uz komunikacia
    for a in communications:
        # kontrola ci je uz uzavreta komunikacia
        if a.close:
            continue
        # patri ramec k danej komunikacii?
        if (a.src_ip == src_ip and a.dst_ip == dst_ip and a.src_mac == src_mac) or (
                a.src_ip == dst_ip and a.dst_ip == src_ip and a.src_mac == src_mac):
            a.frames.append(frame)
            # je ramec odpoved?
            if frame.inner_protocol == "ARP Reply":
                a.close = True
                return
    # neexistuje este komunikacia
    if frame.inner_protocol == "ARP Reply":
        communications.append(ArpCommunication(frame, src_ip, dst_ip, src_mac, True))
    else:
        communications.append(ArpCommunication(frame, src_ip, dst_ip, src_mac))


def arp_communication(file):
    for pkt in packet_list:
        if pkt.protocol == "ARP (Address Resolution Protocol)":
            if pkt.inner_protocol == "ARP Request":
                add_to_arp_com(arp_communications, pkt, pkt.src_ip, pkt.dst_ip, pkt.src_mac)
            else:
                add_to_arp_com(arp_communications, pkt, pkt.src_ip, pkt.dst_ip, pkt.dst_mac)
    print_arp_communications(file)


def print_mac(src_mac, file):
    for i in range(6):
        file.write('%02x ' % src_mac[i])


def print_arp_header(frame, file):
    if frame.inner_protocol == "ARP Reply":
        file.write("ARP-Reply, IP adresa: " + frame.src_ip + ",\t MAC adresa: ")
        print_mac(frame.src_mac, file)
        file.write("\nZdrojová IP: " + frame.src_ip + ",\tCieľová IP: " + frame.dst_ip + "\n")
    else:
        file.write("ARP-Request, IP adresa: " + frame.dst_ip + ",\t MAC adresa: ???")
        file.write("\nZdrojová IP: " + frame.src_ip + ",\tCieľová IP: " + frame.dst_ip + "\n")


def print_packet_info(file, pkt):
    file.write("Rámec č. " + pkt.id.__str__() + "\n")
    file.write("Dĺžka rámca poskytnutá pcap API – " + pkt.cap_len.__str__() + "B\n")
    file.write("Dĺžka rámca prenášaného po médiu - " + pkt.all_len.__str__() + "B\n")
    file.write("Typ protokolu: " + pkt.protocol + "\n")
    file.write("Typ rámca: " + pkt.frame_type + "\n")
    print_macs(pkt.src_mac, pkt.dst_mac, file)
    print_packet(pkt.byte_field, file)
    file.write("\n\n")


def print_arp_communications(file):
    count = 1
    if len(arp_communications) > 0:
        tmp = False
        for a in arp_communications:
            if a.close and (len(a.frames) > 1):
                file.write(55 * "-" + "\n")
                file.write("Komunikácia č. " + count.__str__() + "\n")
                count += 1
                print_arp_header(a.frames[0], file)
                for frame in a.frames:
                    if frame.inner_protocol == "ARP Reply":
                        print_arp_header(frame, file)
                    print_packet_info(file, frame)
            else:
                tmp = True
        if tmp:
            file.write(55 * "-" + "\nZbytok ARP:\n")
            for a in arp_communications:
                if len(a.frames) == 1 and a.close is False:
                    for frame in a.frames:
                        print_arp_header(frame, file)
                        print_packet_info(file, frame)
            file.write(55 * "-")


def print_ip_dict(file):
    file.write("\n \nIP adresy vysielajúcich uzlov:\n")
    for ip in ip_dict:
        file.write(get_ip_address(ip) + "\n")
    file.write("\nAdresa uzla s najväčším počtom odoslaných paketov:\n")
    file.write(get_ip_address(max(ip_dict, key=ip_dict.get)) + "\t" + ip_dict.get(
        max(ip_dict, key=ip_dict.get)).__str__() + " paketov\n")


def print_tftp_header(a, file):
    file.write("TFTP " + a.opcode + "pripojenie\n")
    file.write("IP adresa Servera: " + a.server_ip + "\tIP adresa Klienta: " + a.client_ip)
    file.write(
        "\nKomunikačný port Servera: " + a.dst_port.__str__() + "\tKomunikačný port Klienta: " + a.src_port.__str__())
    if a.close:
        if a.success:
            file.write("\nKomunikácia bola úspešne ukončena")
        else:
            file.write("\nKomunikácia nebola úspešne ukončena")
    else:
        file.write("\nKomunikácia nebola ukončena")
    # file.write("Rámce komunikácie")


def print_tftp_communications(file):
    file.write(55 * "-" + "\n")
    file.write("TFTP\n")
    file.write(55 * "-" + "\n\n")
    count = 1
    if len(tftp_communications) > 0:
        for a in tftp_communications:
            file.write(55 * "-" + "\n")
            file.write("Komunikácia č." + count.__str__() + "\n")
            count += 1
            print_tftp_header(a, file)
            for frame in a.frames:
                print_packet_info(file, frame)


def get_tftp_opcode(frame):
    tftp_type = get_data_from_bytes(frame.byte_field, 42, 43, True)
    if tftp_type in tftp_dict:
        return tftp_dict.get(tftp_type)
    else:
        "Wrong opcode"


def add_to_tftp_com(communications, frame):
    src_ip = frame.src_ip
    dst_ip = frame.dst_ip
    src_port = frame.src_port
    dst_port = frame.dst_port
    opcode = get_tftp_opcode(frame)
    # ked target port je 69 jedna sa o novu komunikaciu
    if dst_port == 69:
        communications.append(TFTPCommunication(frame, dst_ip, src_ip, src_port, opcode))
        return
    block_id = get_data_from_bytes(frame.byte_field, 44, 45, True)
    # kontrola ci uz existuje
    for a in communications:
        # kontrola ci je uz uzavreta komunikacia
        if a.close:
            continue
        # patri ramec k danej komunikacii?
        if (a.src_ip == src_ip and a.dst_ip == dst_ip and a.src_port == src_port) or (
                a.src_ip == dst_ip and a.dst_ip == src_ip and a.src_port == dst_port):
            # je ramec druhy v poradi?
            if len(a.frames == 1):
                if a.opcode == "Write request" and opcode == "Acknowledgment":
                    a.frames.append(frame)
                    a.dst_port = frame.src_port
                    a.wait_for_ack = False
                elif a.opcode == "Read request" and opcode == "Data Packet":
                    a.frames.append(frame)
                    a.dst_port = frame.src_port
                    a.wait_for_ack = True
                else:
                    return
            if opcode == "Data Packet":
                a.blocks.append(Block(block_id))
            if opcode == "Acknowledgment":
                a.blocks[block_id].acknowledgement = True
            if frame.cap_len < 558:
                a.close = True
            if a.wait_for_ack is False:
                a.success = True


def tftp_communication(file):
    for pkt in packet_list:
        if pkt.inner_protocol_type == "TFTP":
            add_to_tftp_com(tftp_communications, pkt)
    print_tftp_communications(file)


load_types(ether_types, llc_types, tcp_ports, udp_ports, icmp_types, ip_protocols, snap_types)
packet_data = getData()
output_file = get_output()
process_packets(packet_data)
arp_communication(output_file)
tftp_communication(output_file)
print_packet_list(output_file)
print_ip_dict(output_file)
