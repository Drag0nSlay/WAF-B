import requests

def get_target_url():
    """
    Prompt the user to enter the target URL (domain) for testing.
    """
    url = input("Enter the target URL for WAF bypass testing (e.g., http://example.com/login): ").strip()
    if not url:
        print("URL cannot be empty. Please provide a valid URL.")
        return get_target_url()
    return url

def get_payloads():
    """
    Allow the user to input payloads they want to test.
    """
    payloads = []
    print("Enter the payloads you want to test (press Enter to stop):")
    while True:
        payload = input("Enter Payload: ").strip()
        if not payload:
            break
        payloads.append(payload)
    return payloads

def get_headers():
    """
    Allow the user to input custom headers (e.g., User-Agent) for testing.
    """
    headers = {}
    print("Enter custom headers (key=value), leave blank to skip:")
    while True:
        header_key = input("Header Key (or press Enter to stop): ").strip()
        if not header_key:
            break
        header_value = input(f"Value for {header_key}: ").strip()
        headers[header_key] = header_value
    return headers

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
        
        # If the content of the response seems unchanged, treat it as blocked
        if "error" not in response.text and "403" not in str(response.status_code) and "blocked" not in response.text.lower():
            print(f"Payload '{payload}' bypassed the WAF (GET Method) - Response Status: {response.status_code}")
        else:
            print(f"Payload '{payload}' blocked by WAF (GET Method) - Response Status: {response.status_code}")
        
        print(f"\nTesting POST with payload: {payload}")
        response = requests.post(url, data={'input': payload}, headers=headers)
        
        # Again, check for response body content to identify if the WAF is blocking it
        if "error" not in response.text and "403" not in str(response.status_code) and "blocked" not in response.text.lower():
            print(f"Payload '{payload}' bypassed the WAF (POST Method) - Response Status: {response.status_code}")
        else:
            print(f"Payload '{payload}' blocked by WAF (POST Method) - Response Status: {response.status_code}")

def main():
    print("Welcome to the WAF Bypass Testing Tool!\n")

    # Get user input for the target URL, payloads, and headers
    target_url = get_target_url()
    payloads = get_payloads()
    headers = get_headers()

    # Perform the WAF bypass tests with the provided information
    bypass_waf_test(target_url, payloads, headers)

if __name__ == "__main__":
    main()