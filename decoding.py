import base64
import urllib.parse
import pyperclip

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

# Example Usage
if __name__ == "__main__":
    print("Do you want to paste the encoded text from clipboard? (yes/no):")
    use_clipboard = input().strip().lower()

    if use_clipboard == "yes":
        user_input = pyperclip.paste()
        print(f"Encoded Text from Clipboard: {user_input}")
    else:
        print("Enter the encoded text:")
        user_input = input()

    print("Enter the encoding type (Base64, ASCII, Unicode, URL, Binary):")
    encoding_type = input()

    decoded_message = decode_text(user_input, encoding_type)
    print(f"Decoded Message: {decoded_message}")
