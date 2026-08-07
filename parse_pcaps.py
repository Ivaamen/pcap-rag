import argparse
import secrets
from scapy.all import rdpcap, TCP, IP, Raw

DEFAULT_PCAP = "captures/temporary.pcapng"

# Well-known / commonly used port -> application protocol mapping.
# TLS/SSL variants are listed alongside their plaintext counterparts
# so that connections on those ports are correctly labeled. A
# connection is classified by whichever side uses a known port; the
# client port (typically the higher-numbered / ephemeral one) takes
# priority when both sides are well-known.
APP_PORTS = {
    # Remote access / shell
    22: "SSH",
    23: "Telnet",
    992: "TelnetS",
    3389: "RDP",
    5900: "VNC",

    # Mail
    25: "SMTP",
    465: "SMTPS",
    587: "SMTP-Submission",
    109: "POP2",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",

    # Name / config / time
    53: "DNS",
    67: "DHCP", 68: "DHCP",
    69: "TFTP",
    123: "NTP",
    161: "SNMP", 162: "SNMP",
    514: "Syslog",
    6514: "Syslog-TLS",

    # Web / proxy
    80: "HTTP",
    443: "HTTPS",
    591: "HTTP-Alt",          # FileMaker / HTTP admin
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS",

    # File / print / directory
    21: "FTP", 990: "FTPS",
    989: "FTPS-Data",
    139: "NetBIOS",
    445: "SMB",
    389: "LDAP",
    636: "LDAPS",
    3268: "LDAP-GC", 3269: "LDAPS-GC",
    2049: "NFS",

    # Messaging / collaboration
    119: "NNTP",
    563: "NNTPS",
    5222: "XMPP", 5223: "XMPP",
    5269: "XMPP-S2S",

    # Databases
    1433: "MSSQL",
    1521: "Oracle",
    1812: "RADIUS", 1813: "RADIUS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",

    # VoIP / streaming
    5060: "SIP", 5061: "SIPS",

    # Other
    1080: "SOCKS",
    1883: "MQTT",
    5672: "AMQP", 5671: "AMQPS",
    6667: "IRC", 6697: "IRC-TLS",
}


def canonical_key(src_ip, src_port, dst_ip, dst_port):
    """Return a direction-independent 4-tuple key so that both directions
    of the same TCP flow are grouped into a single connection entry.

    The endpoint with the lexicographically smaller (ip, port) pair is
    forced to the front so the tuple is symmetric."""
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (a[0], a[1], b[0], b[1])
    return (b[0], b[1], a[0], a[1])


def detect_app_protocol(src_port, dst_port):
    """Guess the application protocol from the port numbers. The
    server-side port is conventionally the well-known one, but we check
    both so it works in either direction."""
    if src_port in APP_PORTS:
        return APP_PORTS[src_port]
    if dst_port in APP_PORTS:
        return APP_PORTS[dst_port]
    return None


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Parse a pcap/pcapng capture into a per-connection text summary.",
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default=DEFAULT_PCAP,
        help="Path to the .pcap or .pcapng file to parse (default: %(default)s).",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Path to write the connections summary to. "
             "Defaults to '<input-stem>_connections_summary.txt' next to the input.",
    )
    return parser.parse_args(argv)


def default_output_for(start_ts, end_ts):
    """Build a unique default output filename rooted in the repo, derived
    from the capture's time range and a short random suffix so each run
    produces a fresh file instead of clobbering an earlier one."""
    rand = secrets.token_hex(4)  # 8 hex chars
    return f"connections_summary_{int(start_ts)}-{int(end_ts)}_{rand}.txt"


def main(pcap_path=None, output_path=None):
    if pcap_path is None:
        args = parse_args()
        pcap_path = args.pcap
        output_path = args.output

    packets = rdpcap(pcap_path)

    # Capture-wide time range. scapy does NOT guarantee time-ordered
    # packet lists, so derive start/end from min/max timestamps across
    # every packet rather than trusting packets[0] / packets[-1].
    all_times = [p.time for p in packets]
    capture_start = min(all_times)
    capture_end = max(all_times)

    if output_path is None:
        output_path = default_output_for(capture_start, capture_end)

    # Stage 1: bucket packets by direction-independent connection key.
    buckets = {}
    for pkt in packets:
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        key = canonical_key(ip.src, tcp.sport, ip.dst, tcp.dport)
        buckets.setdefault(key, []).append(pkt)

    # Stage 2: per-bucket, decide the canonical endpoint ordering and
    # compute the metrics for every connection in the capture.
    connections = []
    for key, pkts in buckets.items():
        # Sort once so the rest of the analysis can rely on time order.
        pkts.sort(key=lambda p: p.time)

        first = pkts[0]
        first_ip = first[IP]
        first_tcp = first[TCP]

        # The very first packet in a TCP flow is almost always the
        # client (the side that sent the SYN), so use it as the
        # canonical "forward" endpoint.
        fwd_ip, fwd_port = first_ip.src, first_tcp.sport
        rev_ip, rev_port = first_ip.dst, first_tcp.dport

        conn = {
            "src_ip": fwd_ip,
            "src_port": fwd_port,
            "dst_ip": rev_ip,
            "dst_port": rev_port,
            "start_ts": pkts[0].time,
            "end_ts": pkts[-1].time,
            "duration_s": pkts[-1].time - pkts[0].time,
            "packet_count_fwd": 0,
            "packet_count_rev": 0,
            "byte_count_fwd": 0,
            "byte_count_rev": 0,
            "tcp_flags_seq": [],
            "app_protocol": detect_app_protocol(fwd_port, rev_port),
            "handshake_complete": False,
            "retransmissions": 0,
            "stream_id": f"{pkts[0].time:.6f}-{len(connections)+1}",
            "packet_summary": [],
        }

        # Per-direction last-seen sequence numbers are the standard way
        # to spot TCP retransmissions. A retransmission is a packet
        # whose SEQ is <= the highest SEQ already observed on that
        # direction AND whose length is non-zero (pure ACKs do not
        # count as retransmissions).
        last_seq = {"fwd": None, "rev": None}
        seen_flags = set()

        for pkt in pkts:
            ip = pkt[IP]
            tcp = pkt[TCP]
            direction = "fwd" if (ip.src == fwd_ip and tcp.sport == fwd_port) else "rev"

            pkt_len = len(pkt)
            flags = str(tcp.flags)
            tcp_payload_len = max(0, pkt_len - len(ip) - len(tcp))

            conn[f"packet_count_{direction}"] += 1
            conn[f"byte_count_{direction}"] += pkt_len

            if flags not in seen_flags:
                seen_flags.add(flags)
                conn["tcp_flags_seq"].append(flags)

            # Three-way handshake: client SYN, server SYN+ACK, client ACK.
            # Track which steps we have observed for this direction.
            if not conn["handshake_complete"]:
                if direction == "fwd" and tcp.flags & 0x02 and not (tcp.flags & 0x10):
                    # Client sent a bare SYN.
                    conn["_syn_seen"] = True
                if direction == "rev" and (tcp.flags & 0x12) == 0x12:
                    # Server replied with SYN+ACK.
                    conn["_synack_seen"] = True
                if direction == "fwd" and (tcp.flags & 0x12) == 0x10 and conn.get("_synack_seen"):
                    # Client completed the ACK.
                    conn["handshake_complete"] = True

            # Retransmission: same direction, same or earlier SEQ, and
            # the segment carries payload (ACKs with the same SEQ are
            # not retransmissions).
            if last_seq[direction] is not None and tcp_payload_len > 0 and tcp.seq <= last_seq[direction]:
                conn["retransmissions"] += 1

            if tcp.seq > (last_seq[direction] or 0):
                last_seq[direction] = tcp.seq

            conn["packet_summary"].append({
                "time": pkt.time,
                "src": ip.src,
                "dst": ip.dst,
                "sport": tcp.sport,
                "dport": tcp.dport,
                "len": pkt_len,
                "flags": flags,
            })

        # Drop scratch flags from the final record.
        conn.pop("_syn_seen", None)
        conn.pop("_synack_seen", None)

        connections.append((key, conn))

    # Stage 3: emit a human-readable summary.
    with open(output_path, "w") as f:
        for conn_key, conn in connections:
            f.write(
                f"Connection: {conn['stream_id']} "
                f"({conn_key[0]}:{conn_key[1]} <-> {conn_key[2]}:{conn_key[3]})\n"
            )
            for key, value in conn.items():
                if key == "packet_summary":
                    continue
                f.write(f"  {key}: {value}\n")
            f.write("\n")


if __name__ == "__main__":
    main()
