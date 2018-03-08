"""
Name: Raymond Wang
ID:	  V00802086
Date: FEB 28, 2018
"""

import pcapy
import socket
import sys
from struct import *

first_time = None
debug_mode = True
connections = []
total_connections = 0

TH_FIN = 0x01
TH_SYN = 0x02
TH_RST = 0x04
TH_PUSH = 0x08
TH_ACK = 0x10
TH_URG = 0x20
TH_ECE = 0x40
TH_CWR = 0x80

mean_duration = 0
max_duration = 0
min_duration = 0

mean_packets = 0
min_packets = 0
max_packets = 0

mean_window = 0
total_window = 0
max_window = 0
min_window = -1

mean_rtt = 0
min_rtt = -1
max_rtt = 0
rtt_total = 0

complete_tcp = 0
reset_tcp = 0
open_tcp = 0


def read_input():
    try:
        processor = pcapy.open_offline(sys.argv[1])
        return processor
    except Exception as e:
        print('Can not open file ' + sys.argv[1] + ', details: ' + str(e))


class RttInfo:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.first_seq = 0
        self.syn_cnt = 0
        self.fin = 0
        self.looking_syn_ack = 0
        self.looking_for_seq = 0
        self.looking_for_ack = 0
        self.looking_for = 0
        self.first = 0


class TcpConnection:
    def __init__(self):
        self.ip_src = None
        self.ip_dst = None
        self.port_src = None
        self.port_dst = None
        self.syn_cnt = 0
        self.fin_cnt = 0
        self.rst_cnt = 0
        self.start_time = None
        self.end_time = None
        self.duration = None
        self.num_packet_src = 0
        self.num_packet_dst = 0
        self.num_total_packets = 0
        self.cur_data_len_src = 0
        self.cur_data_len_dst = 0
        self.cur_total_data_len = 0
        self.max_win_size = 0
        self.min_win_size = 0
        self.sum_win_size = 0
        self.rtt_array = []
        self.is_set = 0


def is_the_same_connection(ip_src1, ip_dst1, port_src1, port_dst1, ip_src2, ip_dst2, port_src2, port_dst2):
    if ip_src1 == ip_src2 and ip_dst1 == ip_dst2 and port_src1 == port_src2 and port_dst1 == port_dst2:
        return True
    if ip_src1 == ip_dst2 and ip_dst1 == ip_src2 and port_src1 == port_dst2 and port_dst1 == port_src2:
        return True
    return False


def check_connection(iph, tcph, ts, data, data_size):
    if len(connections) == 0:
        conn = TcpConnection()
        conn.ip_src = socket.inet_ntoa(iph[8])
        conn.ip_dst = socket.inet_ntoa(iph[9])
        conn.port_src = tcph[0]
        conn.port_dst = tcph[1]
        conn.is_set = 1
        conn.start_time = ts
        global first_time
        first_time = ts

        th_flags = tcph[5]
        if th_flags & TH_FIN:
            conn.fin_cnt += 1
        elif th_flags & TH_SYN:
            conn.syn_cnt += 1
            rtt_info = RttInfo()
            rtt_info.start_time = ts
            rtt_info.syn_cnt += 1
            rtt_info.first_seq = tcph[2]
            rtt_info.looking_syn_ack = 1
            rtt_info.looking_for = tcph[2]
            conn.rtt_array.append(rtt_info)
        elif th_flags & TH_RST:
            conn.rst_cnt += 1

        conn.num_packet_src += 1
        conn.num_total_packets += 1
        conn.cur_data_len_src += data_size
        conn.cur_total_data_len += data_size
        conn.max_win_size = tcph[6]
        conn.min_win_size = tcph[6]
        conn.sum_win_size += tcph[6]
        connections.append(conn)
        return

    found = False
    index = 0
    for i, conn in enumerate(connections):
        tmp_ip_src = socket.inet_ntoa(iph[8])
        tmp_ip_dst = socket.inet_ntoa(iph[9])
        tmp_port_src = tcph[0]
        tmp_port_dst = tcph[1]
        if is_the_same_connection(conn.ip_src, conn.ip_dst, conn.port_src, conn.port_dst, tmp_ip_src, tmp_ip_dst,
                                  tmp_port_src, tmp_port_dst):
            found = True
            index = i
            break

    if found:
        first = connections[index].rtt_array[-1].first
        if first == 1:
            connections[index].rtt_array[-1].start_time = ts
            connections[index].rtt_array[-1].first = 0
            connections[index].rtt_array[-1].looking_for = tcph[2]
            connections[index].rtt_array[-1].looking_for_ack = 1
            connections[index].rtt_array[-1].looking_for_seq = 0
        th_flags = tcph[5]
        if th_flags & TH_FIN:
            connections[index].fin_cnt += 1
            connections[index].rtt_array[-1].start_time = ts
            connections[index].rtt_array[-1].fin = 1
        elif th_flags & TH_SYN:
            connections[index].syn_cnt += 1
            if th_flags & TH_ACK:
                if connections[index].rtt_array[-1].looking_for + 1 == tcph[3] and \
                                connections[index].rtt_array[-1].looking_syn_ack == 1:
                    connections[index].rtt_array[-1].end_time = ts
                    connections[index].rtt_array[-1].syn_cnt += 1
                    connections[index].rtt_array[-1].looking_syn_ack = 0

                    rtt_info = RttInfo()
                    rtt_info.looking_for = tcph[3]
                    rtt_info.start_time = ts
                    rtt_info.looking_for_seq = 1
                    connections[index].rtt_array.append(rtt_info)
        elif th_flags & TH_RST:
            connections[index].rst_cnt += 1

        if th_flags & TH_ACK:
            if connections[index].rtt_array[-1].looking_for_seq == 1:
                if connections[index].rtt_array[-1].looking_for == tcph[2]:
                    connections[index].rtt_array[-1].end_time = ts
                    rtt_info = RttInfo()
                    rtt_info.looking_for = tcph[2]
                    rtt_info.first = 1
                    rtt_info.looking_for_ack = 1
                    connections[index].rtt_array.append(rtt_info)
            elif connections[index].rtt_array[-1].looking_for_ack == 1:
                if connections[index].rtt_array[-1].looking_for == tcph[3]:
                    connections[index].rtt_array[-1].end_time = ts
                    rtt_info = RttInfo()
                    rtt_info.looking_for = tcph[3]
                    rtt_info.first = 1
                    rtt_info.looking_for_seq = 1

            connections[index].end_time = ts
            if connections[index].port_src == tcph[1] and connections[index].port_dst == tcph[0] \
                    and connections[index].ip_dst == socket.inet_ntoa(iph[8]):
                connections[index].num_packet_dst += 1
                connections[index].num_total_packets += 1
                connections[index].cur_data_len_dst += data_size
                connections[index].cur_total_data_len += data_size
            else:
                connections[index].num_packet_src += 1
                connections[index].num_total_packets += 1
                connections[index].cur_data_len_src += data_size
                connections[index].cur_total_data_len += data_size

            if tcph[6] > connections[index].max_win_size:
                connections[index].max_win_size = tcph[6]
            if tcph[6] < connections[index].min_win_size:
                connections[index].min_win_size = tcph[6]
            connections[index].sum_win_size += tcph[6]
    else:
        conn = TcpConnection()
        conn.ip_src = socket.inet_ntoa(iph[8])
        conn.ip_dst = socket.inet_ntoa(iph[9])
        conn.port_src = tcph[0]
        conn.port_dst = tcph[1]
        conn.is_set = 1
        conn.start_time = ts

        th_flags = tcph[5]
        if th_flags & TH_FIN:
            conn.fin_cnt += 1
        elif th_flags & TH_SYN:
            conn.syn_cnt += 1
            rtt_info = RttInfo()
            rtt_info.start_time = ts
            rtt_info.syn_cnt += 1
            rtt_info.first_seq = tcph[2]
            rtt_info.looking_syn_ack = 1
            rtt_info.looking_for = tcph[2]
            conn.rtt_array.append(rtt_info)
        elif th_flags & TH_RST:
            conn.rst_cnt += 1

        conn.num_packet_src += 1
        conn.num_total_packets += 1
        conn.cur_data_len_src += data_size
        conn.cur_total_data_len += data_size
        conn.max_win_size = tcph[6]
        conn.min_win_size = tcph[6]
        conn.sum_win_size += tcph[6]
        connections.append(conn)


def parse_packet(current_packet, ts, capture_len):
    eth_length = 14

    eth_header = current_packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # Only parse IP packets, ignore others
    if eth_protocol == 8:
        if 20 + eth_length > capture_len:
            return

        # Take first 20 characters for the ip header
        ip_header = current_packet[eth_length:20 + eth_length]
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        protocol = iph[6]

        # Only deal with TCP protocol
        if protocol == 6:
            tcp_header_length = iph_length + eth_length
            if tcp_header_length + 20 > capture_len:
                return

            # Take first 20 characters for the TCP header
            tcp_header = current_packet[tcp_header_length:tcp_header_length + 20]
            tcph = unpack('!HHLLBBHHH', tcp_header)

            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(current_packet) - h_size

            # Get data from the packet
            data = current_packet[h_size:]
            check_connection(iph, tcph, ts, data, data_size)


def print_connection_details():
    init_time = float(first_time[0]) + 0.000001 * first_time[1]

    for i, item in enumerate(connections):
        if i > 0:
            print('++++++++++++++++++++++++++++++++++++++++++++++++++')

        print('Connection %s: ' % str(i + 1))
        print('Source Address: %s' % item.ip_src)
        print('Destination address: %s' % item.ip_dst)
        print('Source Port: %s' % item.port_src)
        print('Destination Port: %s' % item.port_dst)

        syn = item.syn_cnt
        fin = item.fin_cnt
        rst = item.rst_cnt
        if rst > 0:
            print('Status: R')
        else:
            print('Status: S%dF%d' % (syn, fin))

        if syn > 0 and fin > 0:
            start_time = float(item.start_time[0]) + 0.000001 * item.start_time[1]
            start_time -= init_time

            end_time = float(item.end_time[0]) + 0.000001 * item.end_time[1]
            end_time -= init_time

            duration = end_time - start_time

            if duration < 0.0:
                print('##################### %f %f ##################' % (start_time, end_time))


            global mean_duration, max_duration, min_duration
            mean_duration += duration
            if duration > max_duration:
                max_duration = duration
            if min_duration == 0:
                min_duration = duration
            elif duration < min_duration:
                min_duration = duration

            global mean_packets, min_packets, max_packets
            mean_packets += item.num_total_packets
            if item.num_total_packets > max_packets:
                max_packets = item.num_total_packets
            if min_packets == 0:
                min_packets = item.num_total_packets
            elif item.num_total_packets < min_packets:
                min_packets = item.num_total_packets

            global max_window, min_window, mean_window, total_window
            if item.max_win_size > max_window:
                max_window = item.max_win_size

            if min_window == -1:
                min_window = item.min_win_size
            elif item.min_win_size < min_window:
                min_window = item.min_win_size
            total_window += item.num_total_packets
            mean_window += item.sum_win_size

            print('Start Time: %f' % start_time)
            print('End Time: %f' % end_time)
            print('Number of packets sent from Source to Destination: %d' % item.num_packet_src)
            print('Number of Packets sent from Destination to Source: %d' % item.num_packet_dst)
            print('Total number of packets: %d' % item.num_total_packets)
            print('Number of data bytes sent from Source to Destination: %d' % item.cur_data_len_src)
            print('Number of data bytes sent from Destination to Source: %d' % item.cur_data_len_dst)
            print('Total number of data bytes: %d' % item.cur_total_data_len)
        print('END')


def print_general():
    global complete_tcp, reset_tcp, open_tcp
    for i, item in enumerate(connections):
        if item.rst_cnt > 0:
            reset_tcp += 1
        if item.syn_cnt > 0 and item.fin_cnt > 0:
            complete_tcp += 1
        else:
            open_tcp += 1
    print('Total number of complete TCP connections: %d' % complete_tcp)
    print('Number of reset TCP connections: %d' % reset_tcp)
    print('Number of TCP connections that were still open when the trace capture ended: %d' % open_tcp)


def print_complete():
    calculate_rtt()

    print('Minimum time durations: %f' % min_duration)
    print('Mean time durations: %f' % (mean_duration / complete_tcp))
    print('Maximum time durations: %f\n' % max_duration)
    print('Minimum RTT value: %f' % min_rtt)
    print('Mean RTT value: %f' % (mean_rtt / rtt_total))
    print('Maximum RTT value: %f\n' % max_rtt)
    print('Minimum number of packets including both send/received: %d' % min_packets)
    print('Mean number of packets including both send/received: %d' % (mean_packets / complete_tcp))
    print('Maximum number of packets including both send/received: %d\n' % max_packets)
    print('Minimum received window size including both send/received: %d' % min_window)
    print('Mean received window size including both send/received: %d' % (mean_window / total_window))
    print('Maximum received window size including both send/received: %d' % max_window)


def calculate_rtt():
    init_time = float(first_time[0]) + 0.000001 * first_time[1]

    for i, item in enumerate(connections):
        j = 0
        if item.syn_cnt > 0 and item.fin_cnt > 0:
            while j < len(item.rtt_array):
                start_time = item.rtt_array[j].start_time
                end_time = item.rtt_array[j].end_time
                if not start_time or not end_time:
                    j += 1
                    continue

                begin = float(start_time[0]) + 0.000001 * start_time[1]
                begin -= init_time
                end = float(end_time[0]) + 0.000001 * end_time[1]
                end -= init_time

                duration = end - begin

                global mean_rtt, rtt_total, max_rtt, min_rtt
                mean_rtt += duration
                rtt_total += 1
                if duration > max_rtt:
                    max_rtt = duration
                if min_rtt == -1:
                    min_rtt = duration
                elif min_rtt > duration:
                    min_rtt = duration
                j += 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: ./parser.py <file>')
        sys.exit(-1)

    processor = read_input()

    while True:
        (header, packet) = processor.next()
        if not packet:
            break
        parse_packet(packet, header.getts(), header.getcaplen())

    print('A) Total number of connections: ', len(connections))

    print('\n__________________________________________________\n')
    print('B) Connections details: \n')
    print_connection_details()

    print('\n__________________________________________________\n')
    print('C) General: \n')
    print_general()

    print('\n__________________________________________________\n')
    print('D) Complete TCP connections: \n')
    print_complete()

    print('\n__________________________________________________')

