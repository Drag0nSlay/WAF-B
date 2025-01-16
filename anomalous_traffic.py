import pyperclip
from scapy.all import TCP, IP, ICMP, sniff
import time
from collections import defaultdict

# Dictionary to track the number of SYN packets for SYN flood detection
syn_counter = defaultdict(int)
syn_threshold = 100  # Threshold for SYN flood detection (adjust as needed)
icmp_counter = defaultdict(int)
icmp_threshold = 100  # Threshold for ICMP flood detection (adjust as needed)
port_scan_counter = defaultdict(int)
scan_threshold = 10  # Threshold for port scanning detection (adjust as needed)
time_interval = 60  # Time interval in seconds to consider for anomaly detection

def get_input_from_clipboard():
    """
    This function retrieves content from the clipboard.
    It returns the clipboard text if available.
    """
    clipboard_text = pyperclip.paste()
    if clipboard_text:
        print("Text successfully pasted from clipboard:")
        print(clipboard_text)
        return clipboard_text
    else:
        print("No text found in clipboard.")
        return None

def get_input_manually(prompt):
    """
    This function retrieves content manually from the user.
    It allows the user to input text manually.
    """
    return input(f"{prompt}: ")

def detect_syn_flood(packet):
    """
    Detect SYN flood by monitoring SYN packets.
    """
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        ip_src = packet[IP].src
        syn_counter[ip_src] += 1
        if syn_counter[ip_src] > syn_threshold:
            print(f"SYN flood detected from {ip_src}!")
            return True
    return False

def detect_icmp_flood(packet):
    """
    Detect ICMP flood by monitoring ICMP Echo Request packets (ping).
    """
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Echo Request
        ip_src = packet[IP].src
        icmp_counter[ip_src] += 1
        if icmp_counter[ip_src] > icmp_threshold:
            print(f"ICMP flood detected from {ip_src}!")
            return True
    return False

def detect_port_scanning(packet):
    """
    Detect port scanning by monitoring multiple attempts to different ports from a single IP.
    """
    if packet.haslayer(TCP):
        ip_src = packet[IP].src
        dport = packet[TCP].dport
        port_scan_counter[ip_src, dport] += 1
        if port_scan_counter[ip_src, dport] > scan_threshold:
            print(f"Port scan detected from {ip_src} targeting port {dport}!")
            return True
    return False

def detect_anomalous_traffic(packet):
    """
    Main function to detect anomalous traffic based on multiple criteria.
    """
    if detect_syn_flood(packet):
        return True
    if detect_icmp_flood(packet):
        return True
    if detect_port_scanning(packet):
        return True
    return False

def reset_counters():
    """
    Reset the counters at regular intervals to prevent memory buildup and to check for new patterns.
    """
    global syn_counter, icmp_counter, port_scan_counter
    syn_counter = defaultdict(int)
    icmp_counter = defaultdict(int)
    port_scan_counter = defaultdict(int)
    print(f"Counters reset at {time.ctime()}")

# Function to sniff the network and analyze packets
def sniff_network(interface="wlan0"):
    print("Starting packet sniffing on interface:", interface)
    try:
        sniff(iface=interface, prn=lambda x: detect_anomalous_traffic(x), store=0)
    except Exception as e:
        print(f"Error sniffing the network: {e}")

def prompt_user_for_input_method():
    """
    Prompt the user to choose between using clipboard or manual input for payload.
    """
    choice = input("Do you want to paste text from clipboard? (yes/no): ").strip().lower()
    if choice == 'yes':
        return get_input_from_clipboard()
    elif choice == 'no':
        return get_input_manually("Enter the payload manually")
    else:
        print("Invalid choice. Please enter 'yes' or 'no'.")
        return prompt_user_for_input_method()

def test_copy_paste_functionality():
    """
    Example function to get a payload or text from the clipboard and use it in network sniffing tasks.
    """
    print("You can now choose to paste text using Ctrl+V for payloads or enter it manually.")
    text_from_input = prompt_user_for_input_method()

    if text_from_input:
        print(f"Proceeding with the input text: {text_from_input}")
        # Add further processing if needed (e.g., using the pasted text in the sniffing or attack functions)
    else:
        print("No valid input to process.")

if __name__ == "__main__":
    # Prompt the user to choose input method (clipboard or manual)
    test_copy_paste_functionality()

    # Optionally, schedule periodic reset of counters
    while True:
        sniff_network()  # Start sniffing on the default network interface (change "eth0" as needed)
        time.sleep(time_interval)  # Sleep before resetting counters
        reset_counters()