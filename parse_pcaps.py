from scapy.all import *

packets = rdpcap('captures/temporary.pcapng')

schema = dict.fromkeys([
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "start_ts", "end_ts", "duration_s",
    "packet_count_fwd", "packet_count_rev",
    "byte_count_fwd", "byte_count_rev",
    "tcp_flags_seq", "app_protocol", "handshake_complete",
    "retransmissions", "source_file", "stream_id"])
for packet in packets:
    if packet.haslayer(TCP):
        
        schema["src_ip"] = packet[IP].src
        
        schema["dst_ip"] = packet[IP].dst
        schema["src_port"]= packet[TCP].sport
        schema["dst_port"] = packet[TCP].dport
        with open("temporary.txt", "a") as t:
            t.write(str(schema))
            

