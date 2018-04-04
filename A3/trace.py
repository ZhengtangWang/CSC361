"""
Name: Raymond Wang
ID:	  V00802086
Date: MAR 25, 2018
"""

import pcapy
import socket
import sys
from struct import *
import math

read_next = 0
protocols = []

all_incoming = []
all_outgoing = []
all_routers = []

first_id = 0
fragments = 0
last_frag = 0
lines = 0
src_ip = ""
dst_ip = ""


def read_input():
    try:
        processor = pcapy.open_offline(sys.argv[1])
        return processor
    except Exception as e:
        print('Can not open file ' + sys.argv[1] + ', details: ' + str(e))


def get_ip_header_length(iph):
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    return iph_length


def add_protocol(new_add):
    if new_add in protocols:
        return
    protocols.append(new_add)


def add_router(ip_src):
    found = False
    for item in all_routers:
        if item['ip'] == ip_src:
            found = True
    if not found:
        all_routers.append({
            "ip": ip_src
        })


def add_outgoing(ip_dst, id, src_port, ts):
    all_outgoing.append({
        "ip": ip_dst,
        "src_port": src_port,
        "id": id,
        "time": ts
    })


def add_incoming(ip_src, id, src_port, ts):
    all_incoming.append({
        "ip": ip_src,
        "time": ts,
        "src_port": src_port,
        "id": id
    })


def analyze_packet(ip_h, start_pos, ts, current_packet):
    global lines, read_next, first_id, fragments, last_frag, src_ip, dst_ip
    protocol = ip_h[6]
    ttl = ip_h[5]
    off = socket.ntohs(ip_h[4])

    tmp_id = ip_h[3]
    packet_id = ((tmp_id >> 8) | (tmp_id << 8))
    if protocol == 17:
        udp_header = current_packet[start_pos:start_pos + 8]
        udp_h = unpack('!HHHH', udp_header)
        port = udp_h[0]
        dst_port = udp_h[1]
        ip_dst = socket.inet_ntoa(ip_h[9])

        # for udp traceroute datagrams, dst_port must between 33434 and 33534
        if not (33434 <= dst_port <= 33534 or read_next != 0):
            return

        add_protocol(protocol)
        if ttl == 1 and first_id == 0:
            src_ip = socket.inet_ntoa(ip_h[8])
            dst_ip = ip_dst
            add_outgoing(ip_dst, -1, port, ts)
            first_id = packet_id
            mf = (off & 0x0020) >> 5
            if mf == 1:
                read_next = 1
                fragments += 1
        elif packet_id == first_id:
            mf = (off & 0x0020) >> 5
            fragments += 1
            tmp = off & 0xff1f
            offset = socket.ntohs(tmp)
            if mf == 0:
                last_frag = offset * 8
                read_next = 0
            add_outgoing(ip_dst, -1, port, ts)
        else:
            mf = (off & 0x0020) >> 5
            if mf == 1:
                read_next = 1
            else:
                read_next = 0

            add_outgoing(ip_dst, -1, port, ts)
    elif protocol == 1:
        icmp_header = current_packet[start_pos:start_pos + 8]
        icmp_h = unpack('!BBHHH', icmp_header)

        start_pos += 8
        ip_h2 = unpack('!BBHHHBBH4s4s', current_packet[start_pos: start_pos + 20])
        ip_h2_length = get_ip_header_length(ip_h2)

        start_pos += ip_h2_length
        udp_h = unpack('!HHHH', current_packet[start_pos:start_pos + 8])
        ip_dst = socket.inet_ntoa(ip_h[9])
        ip_src = socket.inet_ntoa(ip_h[8])

        if ip_h2[6] == 17:
            port = udp_h[0]
        else:
            port = 0
        icmp_h2 = unpack('!BBHHH', current_packet[start_pos:start_pos + 8])

        add_protocol(ip_h[6])

        icmp_type = icmp_h[0]
        if icmp_type == 11:
            add_router(ip_src)
            add_incoming(ip_src, icmp_h2[4], port, ts)
        elif icmp_type == 8 and ttl == 1 and first_id == 0:
            src_ip = ip_src
            dst_ip = ip_dst
            add_outgoing(ip_dst, icmp_h[4], port, ts)
            first_id = packet_id
            mf = (off & 0x0020) >> 5
            if mf == 1:
                fragments += 1
        elif packet_id == first_id:
            mf = (off & 0x0020) >> 5
            fragments += 1
            tmp = off & 0xff1f
            offset = socket.ntohs(tmp)
            if mf == 0:
                last_frag = offset * 8
            add_outgoing(ip_dst, icmp_h[4], port, ts)
        elif icmp_type == 8:
            add_outgoing(ip_dst, icmp_h[4], port, ts)
        elif icmp_type == 0 or icmp_type == 3:
            add_router(ip_src)
            add_incoming(ip_src, icmp_h[4], port, ts)


def parse_packet(current_packet, ts, capture_len):
    eth_length = 14

    eth_header = current_packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # only parse IP packets, ignore others
    if eth_protocol == 8:
        if 20 + eth_length > capture_len:
            return

        # take first 20 characters for the ip header
        ip_header = current_packet[eth_length:20 + eth_length]
        ip_h = unpack('!BBHHHBBH4s4s', ip_header)

        iph_length = get_ip_header_length(ip_h)
        analyze_packet(ip_h, eth_length + iph_length, ts, current_packet)


def ts_subtract(x, y):
    x0 = x[0]
    x1 = x[1]
    y0 = y[0]
    y1 = y[1]
    if x1 < y1:
        nsec = (y1 - x1) / 1000000 + 1
        y1 -= 1000000 * nsec
        y0 += nsec
    elif x1 - y1 > 1000000:
        nsec = (x1 - y1) / 1000000
        y1 += 1000000 * nsec
        y0 -= nsec

    return (x0 - y0) + 0.000001 * (x1 - y1)


def cal_rtt():
    for outgoing in all_outgoing:
        for incoming in all_incoming:
            if (outgoing['id'] == incoming['id'] and outgoing['id'] != 0) or \
                    (outgoing['src_port'] == incoming['src_port'] and outgoing['src_port'] != 0):

                for router in all_routers:
                    if router['ip'] == incoming['ip']:
                        diff = ts_subtract(incoming['time'], outgoing['time'])
                        if 'rtt' in router:
                            router['rtt'].append(diff)
                        else:
                            router['rtt'] = [diff]

    for router in all_routers:
        if 'rtt' in router:
            tmp_sum = 0.0
            for rtt in router['rtt']:
                tmp_sum += rtt
            if len(router['rtt']) > 0:
                router['avg_rtt'] = tmp_sum / len(router['rtt']) * 1000

    for router in all_routers:
        if 'rtt' in router:
            sd = 0.0
            for rtt in router['rtt']:
                diff = router['avg_rtt'] - rtt * 1000
                sd += diff * diff
            sd = sd / len(router['rtt'])
            sd = math.sqrt(sd)
            router['sd_rtt'] = sd


def output():
    print('The IP address of the source node: %s' % src_ip)
    print('The IP address of the ultimate destination node: %s' % dst_ip)
    print('The IP addresses of the intermediate destination nodes:')

    index = 1
    for router in all_routers:
        if router['ip'] != dst_ip:
            print('\trouter %d: %s' % (index, router['ip']))
            index += 1

    print('\nThe values in the protocol field of IP headers:')
    for protocol in protocols:
        if protocol == 1:
            print('\t1: ICMP')
        if protocol == 17:
            print('\t17: UDP')

    print('\nThe number of fragments created from the original datagram is: %d' % fragments)
    print('The offset of the last fragment is: %d\n' % last_frag)

    dest = None
    for router in all_routers:
        if router['ip'] != dst_ip:
            print('The avg RTT between %s and %s is: %.2f ms, the s.d. is: %.2f ms' % \
                  (src_ip, router['ip'], router['avg_rtt'], router['sd_rtt']))
        else:
            dest = router
    if dest:
        print('The avg RTT between %s and %s is: %.2f ms, the s.d. is: %.2f ms' % \
              (src_ip, dest['ip'], dest['avg_rtt'], dest['sd_rtt']))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: ./trace.py <file>')
        sys.exit(-1)

    processor = read_input()

    while True:
        (header, packet) = processor.next()
        if not packet:
            break
        lines += 1
        parse_packet(packet, header.getts(), header.getcaplen())

    cal_rtt()
    output()
