import dpkt
import socket

# Open the pcap file captured with Wireshark
f = open("capture.pcap", "rb")
pcap = dpkt.pcap.Reader(f)

# Counters and storage
total_packets = 0
tcp_packets = 0
udp_packets = 0

src_ips = set()
dst_ips = set()
tcp_ports = set()
udp_ports = set()

sizes = []
first_time = None
last_time = None

for timestamp, buf in pcap:
    total_packets += 1
    sizes.append(len(buf))

    # Track first and last timestamp for duration
    if first_time is None:
        first_time = timestamp
    last_time = timestamp

    try:
        eth = dpkt.ethernet.Ethernet(buf)

        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data

            src_ips.add(socket.inet_ntoa(ip.src))
            dst_ips.add(socket.inet_ntoa(ip.dst))

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                tcp_packets += 1
                tcp_ports.add(tcp.sport)
                tcp_ports.add(tcp.dport)

            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                udp_packets += 1
                udp_ports.add(udp.sport)
                udp_ports.add(udp.dport)

    except (dpkt.dpkt.UnpackError, ValueError):
        continue

f.close()

# ---------- 1. Packet Statistics ----------
print("===== Packet Statistics =====")
print("Total packets:", total_packets)
print("TCP packets:", tcp_packets)
print("UDP datagrams:", udp_packets)
if total_packets > 0:
    print("Capture duration (seconds):", round(last_time - first_time, 2))

# ---------- 2. Address and Port Extraction ----------
print("\n===== Unique Source IPs =====")
for ip in sorted(src_ips):
    print(ip)

print("\n===== Unique Destination IPs =====")
for ip in sorted(dst_ips):
    print(ip)

print("\n===== Unique TCP Ports =====")
print(sorted(tcp_ports))

print("\n===== Unique UDP Ports =====")
print(sorted(udp_ports))

# ---------- 3. Packet Size Analysis ----------
if total_packets > 0:
    print("\n===== Packet Size Analysis =====")
    print("Minimum size:", min(sizes), "bytes")
    print("Maximum size:", max(sizes), "bytes")
    print("Average size:", round(sum(sizes) / len(sizes), 2), "bytes")