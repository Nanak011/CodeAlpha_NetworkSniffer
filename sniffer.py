import socket
import struct
import time
import threading

# Global counters
packet_count = 0
http_requests = 0
http_data = []

# Parse Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    proto = socket.ntohs(proto)
    return dest_mac, src_mac, proto, data[14:]

# Parse IPv4 packet
def ipv4_packet(data):
    ttl, proto, src_ip, dest_ip = struct.unpack('!8x B B 2x 4s 4s', data[:20])
    src_ip = socket.inet_ntoa(src_ip)
    dest_ip = socket.inet_ntoa(dest_ip)
    return ttl, proto, src_ip, dest_ip, data[20:]

# Parse TCP segment
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgement, data[offset:]

# Packet capture function
def capture_packets():
    global packet_count, http_requests, http_data

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    log_file = open("network_log.txt", "a")
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_file.write(f"\n\n--- Sniffer Run Started at {current_time} ---\n")

    print("{:<7} {:<21} {:<21} {:<7} {:<8}".format("PROTO", "SOURCE", "DESTINATION", "TYPE", "INFO"))
    print("-" * 70)

    while True:
        raw_data, _ = conn.recvfrom(65535)
        _, _, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:  # IPv4
            ttl, proto, src_ip, dest_ip, ip_data = ipv4_packet(data)

            if proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgement, tcp_data = tcp_segment(ip_data)

                if src_port == 80 or dest_port == 80:  # HTTP
                    http_requests += 1

                    # Save and print HTTP request
                    if b"GET" in tcp_data or b"POST" in tcp_data:
                        http_data.append((src_ip, dest_ip, tcp_data))
                        try:
                            decoded_data = tcp_data.decode('utf-8', errors='ignore')
                            print("\n---- HTTP Request ----")
                            print(decoded_data)
                            print("----------------------\n")
                            log_file.write("\nHTTP Request:\n" + decoded_data + "\n")
                            log_file.flush()  # Ensure immediate flush to the file
                        except Exception as e:
                            print("Error decoding HTTP data:", e)

                    # General log line
                    log_entry = "{:<7} {:<21} {:<21} {:<7} Src:{:<5} Dst:{:<5} Seq:{:<6}".format(
                        "IPv4", f"{src_ip}:{src_port}", f"{dest_ip}:{dest_port}", "TCP", src_port, dest_port, sequence)
                    print(log_entry)
                    log_file.write(log_entry + "\n")
                    log_file.flush()  # Ensure immediate flush to the file

                    packet_count += 1

# Exit function
def graceful_exit():
    print("\nExiting sniffer... Please wait.")
    print(f"Captured Packets: {packet_count} | HTTP Requests: {http_requests}")
    if http_requests > 0:
        print(f"\nLast HTTP request:\n{http_data[-1][2].decode('utf-8', errors='ignore')}")
    exit(0)

# Start capture in thread
capture_thread = threading.Thread(target=capture_packets)
capture_thread.daemon = True
capture_thread.start()

# Keep alive and handle Ctrl+C
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    graceful_exit()
