import argparse
import logging
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from colorama import init, Fore, Style

# Initialize colorama for guaranteed Windows color support
init()

# ==========================================
# Global state for Port Scan Detection (IDS)
# ==========================================
port_scan_tracker = defaultdict(set)
port_scan_timestamps = defaultdict(float)
SCAN_PORT_THRESHOLD = 15  # Alert if > 15 unique ports are hit...
SCAN_TIME_WINDOW = 3      # ...within 3 seconds

# ==========================================
# 1. Setup Logging
# This tells recruiters you know how to save 
# output for later analysis (crucial in security)
# ==========================================
logging.basicConfig(
    filename='network_traffic.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ==========================================
# 2. Core Analysis Function
# This function processes every single packet
# ==========================================
def analyze_packet(packet):
    """
    Analyzes a network packet, logs its details, and flags insecure protocols.
    """
    # We only care about IP packets for this tool
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Handle TCP Connections (Web, SSH, FTP, etc.)
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            
            log_msg = f"TCP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            print(log_msg)
            logging.info(log_msg)
            
            # --- NEW FEATURE: Port Scan Detection (IDS) ---
            current_time = time.time()
            # Reset tracker if outside the time window
            if current_time - port_scan_timestamps[src_ip] > SCAN_TIME_WINDOW:
                port_scan_tracker[src_ip].clear()
                port_scan_timestamps[src_ip] = current_time
            
            port_scan_tracker[src_ip].add(dst_port)

            if len(port_scan_tracker[src_ip]) >= SCAN_PORT_THRESHOLD:
                ids_msg = f"[!!!] PORT SCAN DETECTED from {src_ip}: {len(port_scan_tracker[src_ip])} ports hit in < {SCAN_TIME_WINDOW}s"
                print(f"{Fore.MAGENTA}{Style.BRIGHT}{ids_msg}{Style.RESET_ALL}")
                logging.critical(ids_msg)
                port_scan_tracker[src_ip].clear() # Reset to avoid spamming the console
            
            # --- RECRUITER HIGHLIGHT: Basic Threat Detection ---
            # Flagging plaintext/insecure protocols
            insecure_ports = {
                21: "FTP (Plaintext File Transfer)",
                23: "Telnet (Plaintext Remote Login)",
                80: "HTTP (Unencrypted Web Traffic)"
            }
            
            # Check BOTH source and destination ports to catch requests and responses
            if dst_port in insecure_ports or src_port in insecure_ports:
                port = dst_port if dst_port in insecure_ports else src_port
                alert_msg = f"[!] INSECURE TRAFFIC DETECTED: {insecure_ports[port]} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                print(f"{Fore.RED}{Style.BRIGHT}{alert_msg}{Style.RESET_ALL}") # Prints in bright red in the terminal
                logging.warning(alert_msg)

                # --- NEW FEATURE: Payload Extraction ---
                # Check if the insecure packet carries raw data (like HTML, passwords, etc.)
                if packet.haslayer('Raw'):
                    try:
                        # Decode bytes to a string, ignoring binary gibberish
                        payload = packet.getlayer('Raw').load.decode('utf-8', errors='ignore')
                        # Clean it up to fit on the screen nicely (first 150 characters)
                        snippet = payload[:150].replace('\n', ' ').replace('\r', '')
                        if snippet.strip():
                            payload_msg = f"    [>] PAYLOAD SNIPPET: {snippet}..."
                            print(f"{Fore.YELLOW}{payload_msg}{Style.RESET_ALL}")
                            logging.warning(payload_msg)
                    except Exception:
                        # If we can't decode it, just ignore it and move on
                        pass

        # Handle UDP Connections (DNS, Video Streaming, etc.)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            log_msg = f"UDP | {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            print(log_msg)
            logging.info(log_msg)

# ==========================================
# 3. Main Execution Block
# Uses argparse to make the script a real tool
# ==========================================
def main():
    # Setup command-line arguments
    parser = argparse.ArgumentParser(description="Professional Network Traffic Analyzer")
    parser.add_argument("-c", "--count", type=int, default=50, help="Number of packets to capture (default: 50. Use 0 for infinite)")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Network interface to sniff on (e.g., eth0, wlan0)")
    args = parser.parse_args()

    print("=" * 50)
    print("🛡️  Starting Network Traffic Analyzer...")
    print(f"📡 Interface: {args.interface if args.interface else 'Default (All)'}")
    print(f"📦 Packets to capture: {args.count if args.count > 0 else 'Infinite'}")
    print("📝 Logging to: network_traffic.log")
    print("=" * 50)
    print("Press Ctrl+C to stop manually.\n")

    try:
        # Start sniffing
        # store=False keeps it from eating up all your computer's RAM
        sniff(
            iface=args.interface, 
            prn=analyze_packet, 
            count=args.count, 
            store=False
        )
        print("\n[+] Packet capture complete. Check 'network_traffic.log' for details.")
    except PermissionError:
        print("\n[!] ERROR: You need administrator/root privileges to capture network packets.")
        print("Try running with 'sudo python traffic_analyzer.py' (Linux/Mac) or run Command Prompt as Admin (Windows).")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")

if __name__ == "__main__":
    main()