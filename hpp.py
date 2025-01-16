import requests

def manipulate_http_parameters(url, original_params, manipulated_params):
    """
    Function to manipulate HTTP parameters and check the effect on the response.
    
    :param url: The target URL to send the GET requests to.
    :param original_params: The original parameters in the URL query string.
    :param manipulated_params: The manipulated parameters for testing.
    
    :return: A tuple containing:
             - A boolean indicating if the response changed (True if no change, False if change occurred).
             - The status code and response body of both requests.
    """
    try:
        # Send GET request with original parameters
        response_original = requests.get(url, params=original_params)
        response_original_status = response_original.status_code
        response_original_text = response_original.text

        # Send GET request with manipulated parameters
        response_manipulated = requests.get(url, params=manipulated_params)
        response_manipulated_status = response_manipulated.status_code
        response_manipulated_text = response_manipulated.text

        # Compare both responses and check for changes in status or content
        if response_original_status == response_manipulated_status and response_original_text == response_manipulated_text:
            print(f"No significant change detected in the response (Status: {response_original_status})")
            return True, response_original_status, response_original_text, response_manipulated_status, response_manipulated_text
        else:
            print(f"Change detected in the response (Original Status: {response_original_status}, Manipulated Status: {response_manipulated_status})")
            return False, response_original_status, response_original_text, response_manipulated_status, response_manipulated_text

    except requests.RequestException as e:
        print(f"Error while making requests: {e}")
        return None, None, None, None, None


def get_user_input():
    """
    Function to get URL and parameters from the user.
    
    :return: The URL, original parameters, and manipulated parameters as dictionaries.
    """
    url = input("Enter the target URL (e.g., http://example.com): ").strip()
    
    # Get original parameters from the user
    original_params = {}
    print("Enter the original parameters (key=value), leave blank to stop:")
    while True:
        key = input("Original Parameter Key (or press Enter to stop): ").strip()
        if not key:
            break
        value = input(f"Value for {key}: ").strip()
        original_params[key] = value
    
    # Get manipulated parameters from the user
    manipulated_params = {}
    print("Enter the manipulated parameters (key=value), leave blank to stop:")
    while True:
        key = input("Manipulated Parameter Key (or press Enter to stop): ").strip()
        if not key:
            break
        value = input(f"Value for {key}: ").strip()
        manipulated_params[key] = value
    
    return url, original_params, manipulated_params


def main():
    # Get the URL and parameters from the user
    url, original_params, manipulated_params = get_user_input()

    # Perform the manipulation and compare the responses
    result, original_status, original_body, manipulated_status, manipulated_body = manipulate_http_parameters(
        url, original_params, manipulated_params
    )

    if result is None:
        print("An error occurred while making the requests.")
    elif result:
        print(f"The responses are identical (Status: {original_status})")
        print("Original Response Body (First 500 chars):", original_body[:500])
        print("Manipulated Response Body (First 500 chars):", manipulated_body[:500])
    else:
        print(f"Responses differ (Original Status: {original_status}, Manipulated Status: {manipulated_status})")
        print("Original Response Body (First 500 chars):", original_body[:500])
        print("Manipulated Response Body (First 500 chars):", manipulated_body[:500])


if __name__ == "__main__":
    main()