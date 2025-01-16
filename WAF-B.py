from decoding import decode_text
from exploitation import exploit_sql_injection
from anomalous_traffic import detect_anomalous_traffic
from tunneling import establish_ssh_tunnel
from hpp import manipulate_http_parameters
from scapy.all import sniff
import pyperclip
import base64
import urllib.parse
import requests

def display_logo():
    logo = r"""
        ...                                                                    
                            ...                                                                    
                            :*+-#@.%==**-=#:%=-#--@+* -+-*.@**#=:%-@=+=@.#.:+                       
                         ....................................................                        
                         #@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@::@@@@#=..                   
                         *@@+=========================================- =+%@@@@@@@#:                
                         #@@:                                                .:#@@@.                
                         #@@:  +@@@*  -@@@  .@@@@+   *@@@@@@@+          .+@@@@@@@@*                 
                         #@@: :@@@@* .%@@. .#@@@@+  .@@@=----.        .@@@@@%@@@:                   
                         #@@:.#@@@@*.*@@+  =@@=@@+  -@@#.             :*-.   :@@*                   
                         *@@:+@@.@@+.@@#  .@@@=@@+  +@@@@@@= -%%%%%%-.:-:.   *@@:                   
                         *@@:@@+.@@-%@@.  %@@.#@@+ .@@@@@@@: %@@@@@@...:.    %@%.                   
                         *@@@@# .@@=@@= .*@@@@@@@+ =@@%.             ....   :@@*.                   
                         *@@@@: :@@@@%  :@@%**@@@+ #@@.             .:::.  .#@@:                    
                         *@@@=  :@@@@: .@@@:  #@@=.@@@.             ..:.   .@@#                     
                         +%%%:  .....  ....   .........             :...   :@@+                     
                         *@@@-                  .... .   .   .  ....... . .%@@:                     
                         *@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=                      
                         -+++***+++++++++++++++++**+++**+++*+++***++***++++:.    ..                 
                             .%.@:# +:          :==- .+.. .=- ..=. :==:--                           
                             =+:%+=.@.          ::*..-:...=#:  =: .*:*.:.                           
                                                                       . Created By:- @Drag0nSlay
                            Follow me on - https://github.com/Drag0nSlay 
                                                                                                      

                                                                                                  
                                                                        
    """
    print(logo)
    print("CAPTURES FIREWALL TILL D.E.A.T.H!\n")
    print("\t*D* - Decoding\n", "\t*E* - Exploitation\n", "\t*A* - Anomalous Traffic\n", "\t*T* - Tunneling\n", "\t*H* - HPP\n")

def decode_text(encoded_text, encoding_type):
    try:
        if encoding_type.lower() == "base64":
            return base64.b64decode(encoded_text).decode('utf-8')

        elif encoding_type.lower() == "ascii":
            return ''.join(chr(int(code)) for code in encoded_text.split())

        elif encoding_type.lower() == "unicode":
            return ''.join(chr(int(code, 16)) for code in encoded_text.split())

        elif encoding_type.lower() == "url":
            return urllib.parse.unquote(encoded_text)

        elif encoding_type.lower() == "binary":
            return ''.join(chr(int(code, 2)) for code in encoded_text.split())

        else:
            return "Unsupported encoding type. Please choose from Base64, ASCII, Unicode, URL, or Binary."
    except Exception as e:
        return f"Error decoding text: {e}"

def handle_decoding():
    print("Do you want to paste the encoded text from clipboard? (yes/no):")
    use_clipboard = input().strip().lower()

    if use_clipboard == "yes":
        user_input = pyperclip.paste()
        print(f"Encoded Text from Clipboard: {user_input}")
    else:
        print("Enter the encoded text:")
        user_input = input()

    print("Enter the encoding type (Base64, ASCII, Unicode, URL, Binary):")
    encoding_type = input().strip()

    # Call the decode_text function with both the encoded text and encoding type
    decoded_message = decode_text(user_input, encoding_type)

    print(f"Decoded Message: {decoded_message}")

# Example usage for SQL Injection Exploitation
def handle_sql_injection():
    print("Enter the URL for SQL injection test:")
    url = input().strip()
    print("Enter the payload for SQL injection (e.g., '1' OR '1'='1'):")
    payload = input().strip()

    is_vulnerable = exploit_sql_injection(url, payload)
    print(f"SQL injection vulnerability detected: {is_vulnerable}")

# Example usage for Anomalous Traffic Detection
def handle_anomalous_traffic():
    print("Sniffing network traffic for anomalous patterns...")
    packet = sniff(count=1)[0]  # Sniff one packet for testing
    anomaly_detected = detect_anomalous_traffic(packet)
    print(f"Anomalous traffic detected: {anomaly_detected}")

# Example usage for SSH Tunneling
def handle_ssh_tunneling():
    print("Enter the SSH host address (e.g., example.com):")
    ssh_host = input().strip()
    print("Enter the SSH port (default is 22):")
    ssh_port = int(input().strip() or 22)
    print("Enter SSH username:")
    ssh_username = input().strip()
    print("Enter SSH password:")
    ssh_password = input().strip()
    print("Enter the local port to forward (e.g., 8080):")
    local_port = int(input().strip())
    print("Enter the remote host to forward to:")
    remote_host = input().strip()
    print("Enter the remote port to forward to:")
    remote_port = int(input().strip())

    tunnel = establish_ssh_tunnel(ssh_host, ssh_port, ssh_username, ssh_password, local_port, remote_host, remote_port)
    tunnel.close()  # Close the tunnel after use

# Example usage for HTTP Parameter Pollution (HPP)
def handle_hpp():
    print("Enter the URL for HTTP Parameter Pollution test:")
    url = input().strip()
    print("Enter the original parameters (key=value):")
    original_params = {}
    while True:
        key = input("Parameter Key (or press Enter to stop): ").strip()
        if not key:
            break
        value = input(f"Value for {key}: ").strip()
        original_params[key] = value

    print("Enter the manipulated parameters (key=value):")
    manipulated_params = {}
    while True:
        key = input("Manipulated Parameter Key (or press Enter to stop): ").strip()
        if not key:
            break
        value = input(f"Value for {key}: ").strip()
        manipulated_params[key] = value

    is_vulnerable = manipulate_http_parameters(url, original_params, manipulated_params)
    print(f"HTTP parameter pollution detected: {is_vulnerable}")

def bypass_waf_test(url, payloads, headers=None):
    """
    Test if payloads bypass WAF using different HTTP methods and headers.
    
    :param url: The target URL.
    :param payloads: List of payloads to test.
    :param headers: Optional headers to manipulate.
    
    :return: None
    """
    for payload in payloads:
        print(f"\nTesting GET with payload: {payload}")
        response = requests.get(url, params={'input': payload}, headers=headers)
        
        if "error" not in response.text and "403" not in str(response.status_code) and "blocked" not in response.text.lower():
            print(f"Payload '{payload}' bypassed the WAF (GET Method) - Response Status: {response.status_code}")
        else:
            print(f"Payload '{payload}' blocked by WAF (GET Method) - Response Status: {response.status_code}")
        
        print(f"\nTesting POST with payload: {payload}")
        response = requests.post(url, data={'input': payload}, headers=headers)
        
        if "error" not in response.text and "403" not in str(response.status_code) and "blocked" not in response.text.lower():
            print(f"Payload '{payload}' bypassed the WAF (POST Method) - Response Status: {response.status_code}")
        else:
            print(f"Payload '{payload}' blocked by WAF (POST Method) - Response Status: {response.status_code}")

# Main Functionality to Choose Between Tools
def main():
    display_logo()

    print("Select an option:")
    print("\tD - Decoding\n\tE - Exploitation\n\tA - Anomalous Traffic Detection\n\tT - SSH Tunneling\n\tH - HTTP Parameter Pollution\n\tW - WAF Bypass Testing")

    choice = input("Enter your choice (D/E/A/T/H/W): ").strip().upper()

    if choice == "D":
        handle_decoding()
    elif choice == "E":
        handle_sql_injection()
    elif choice == "A":
        handle_anomalous_traffic()
    elif choice == "T":
        handle_ssh_tunneling()
    elif choice == "H":
        handle_hpp()
    elif choice == "W":
        print("Enter the target URL for WAF bypass testing (e.g., http://example.com):")
        url = input().strip()
        print("Enter the payloads you want to test (press Enter to stop):")
        payloads = []
        while True:
            payload = input("Enter Payload: ").strip()
            if not payload:
                break
            payloads.append(payload)

        print("Enter custom headers (key=value), leave blank to skip:")
        headers = {}
        while True:
            key = input("Header Key (or press Enter to stop): ").strip()
            if not key:
                break
            value = input(f"Value for {key}: ").strip()
            headers[key] = value

        bypass_waf_test(url, payloads, headers)

    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
