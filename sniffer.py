import socket
import struct
import time
import threading

# Global counters and storage
packet_count = 0
http_requests = 0
http_data = []
log_file = None
running = True  # Flag for graceful exit

# Ethernet frame parser
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return (
        ':'.join(format(b, '02x') for b in dest_mac),
        ':'.join(format(b, '02x') for b in src_mac),
        socket.ntohs(proto),
        data[14:]
    )

# IPv4 packet parser
def ipv4_packet(data):
    ttl, proto, src_ip, dest_ip = struct.unpack('!8x B B 2x 4s 4s', data[:20])
    return (
        ttl,
        proto,
        socket.inet_ntoa(src_ip),
        socket.inet_ntoa(dest_ip),
        data[20:]
    )

# TCP segment parser
def tcp_segment(data):
    if len(data) < 20:
        return None  # Incomplete header
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgement, data[offset:]

# Capture and process packets
def capture_packets():
    global packet_count, http_requests, http_data, log_file, running

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Open log file
    log_file = open("network_log.txt", "a")
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_file.write(f"\n\n--- Sniffer Run Started at {current_time} ---\n")
    
    print("{:<7} {:<21} {:<21} {:<7} {:<8}".format("PROTO", "SOURCE", "DESTINATION", "TYPE", "INFO"))
    print("-" * 70)

    while running:
        try:
            raw_data, _ = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            if eth_proto == 8:  # IPv4
                ttl, proto, src_ip, dest_ip, ip_data = ipv4_packet(data)

                if proto == 6:  # TCP
                    tcp_info = tcp_segment(ip_data)
                    if tcp_info is None:
                        continue

                    src_port, dest_port, sequence, acknowledgement, tcp_data = tcp_info

                    # HTTP or HTTPS detection
                    if dest_port in (80, 443) or src_port in (80, 443):
                        if dest_port == 80 or src_port == 80:
                            if b"GET" in tcp_data or b"POST" in tcp_data:
                                http_requests += 1
                                http_data.append((src_ip, dest_ip, tcp_data[:50]))  # Store preview

                        log_entry = "{:<7} {:<21} {:<21} {:<7} Src:{:<5} Dst:{:<5} Seq:{:<6}".format(
                            "IPv4", f"{src_ip}:{src_port}", f"{dest_ip}:{dest_port}", "TCP", src_port, dest_port, sequence
                        )
                        print(log_entry)
                        log_file.write(log_entry + "\n")

                packet_count += 1

        except Exception as e:
            continue

# Graceful exit function
def graceful_exit():
    global running, log_file
    running = False
    print("\n\nExiting sniffer... Finalizing log.")
    time.sleep(1)

    print(f"\nTotal Packets Captured: {packet_count}")
    print(f"HTTP Requests Detected: {http_requests}")
    if http_data:
        print(f"Last HTTP Request Preview:\n{http_data[-1]}")
        log_file.write(f"\nLast HTTP Request Preview:\n{http_data[-1]}\n")

    if log_file:
        log_file.write(f"\n--- Sniffer Run Ended ---\n")
        log_file.close()

# Start sniffer in thread
capture_thread = threading.Thread(target=capture_packets)
capture_thread.daemon = True
capture_thread.start()

# Main loop
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    graceful_exit()
