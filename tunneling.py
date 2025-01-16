import paramiko
from paramiko import SSHClient
import socket

def establish_ssh_tunnel(host, port, username, password, local_port, remote_host, remote_port):
    """
    Establishes an SSH tunnel by connecting to the given SSH server and forwarding a local port to a remote service.
    
    :param host: SSH server IP address or hostname.
    :param port: SSH server port (default is 22).
    :param username: SSH username.
    :param password: SSH password.
    :param local_port: The local port to bind to for the tunnel.
    :param remote_host: The remote host to forward traffic to.
    :param remote_port: The remote port to forward traffic to.
    :return: An SSHClient object.
    """
    client = SSHClient()
    client.load_system_host_keys()
    
    # Automatically add the host key if it's not already in known hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Establish SSH connection
        print(f"Connecting to {host} on port {port}...")
        client.connect(host, port=port, username=username, password=password)
        print(f"SSH connection established to {host}.")

        # Forward the local port to the remote host and port
        print(f"Setting up port forwarding: Local Port {local_port} -> {remote_host}:{remote_port}")
        client.get_transport().open_channel("direct-tcpip", (remote_host, remote_port), ("127.0.0.1", local_port))
        print(f"Port forwarding established: Local Port {local_port} -> {remote_host}:{remote_port}")

        # Tunnel established, can now interact with the remote service through the local port
    except Exception as e:
        print(f"Error: {e}")
        client.close()

    return client

def execute_ssh_command(client, command):
    """
    Executes a command on the remote server through the established SSH connection.
    
    :param client: The SSHClient object.
    :param command: The command to execute.
    :return: The command output.
    """
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        print(f"Command Output: {output}")
        return output
    except Exception as e:
        print(f"Error executing command: {e}")
        return None

def close_ssh_connection(client):
    """
    Closes the SSH connection.
    
    :param client: The SSHClient object.
    """
    print("Closing SSH connection.")
    client.close()

def prompt_user_for_choice():
    """
    Prompts the user to choose what action they want to perform: SSH Tunnel or Execute Command.
    """
    print("Please choose an option:")
    print("1. Establish SSH Tunnel")
    print("2. Execute a Command Remotely")
    
    choice = input("Enter 1 or 2: ").strip()
    
    if choice == "1":
        return establish_ssh_tunnel_option()
    elif choice == "2":
        return execute_command_option()
    else:
        print("Invalid choice. Please enter 1 or 2.")
        return prompt_user_for_choice()

def establish_ssh_tunnel_option():
    """
    Prompts the user for SSH tunnel connection details and sets up the tunnel.
    """
    ssh_host = input("Enter the SSH server IP or Hostname: ")
    ssh_port = int(input("Enter the SSH port (default is 22): ") or 22)
    ssh_username = input("Enter your SSH username: ")
    ssh_password = input("Enter your SSH password: ")

    # Port forwarding details
    local_port = int(input("Enter the local port to forward: "))
    remote_host = input("Enter the remote host to forward to: ")
    remote_port = int(input("Enter the remote port to forward to: "))

    # Establish SSH Tunnel
    ssh_client = establish_ssh_tunnel(ssh_host, ssh_port, ssh_username, ssh_password, local_port, remote_host, remote_port)

    return ssh_client

def execute_command_option():
    """
    Prompts the user for SSH connection details and command to execute.
    """
    ssh_host = input("Enter the SSH server IP or Hostname: ")
    ssh_port = int(input("Enter the SSH port (default is 22): ") or 22)
    ssh_username = input("Enter your SSH username: ")
    ssh_password = input("Enter your SSH password: ")

    # Command to execute
    command = input("Enter the command to execute remotely: ")

    # Establish SSH connection
    ssh_client = establish_ssh_tunnel(ssh_host, ssh_port, ssh_username, ssh_password, 22, "localhost", 22)  # Tunnel for command execution

    # Execute Command
    execute_ssh_command(ssh_client, command)

    # Close SSH connection
    close_ssh_connection(ssh_client)

if __name__ == "__main__":
    prompt_user_for_choice()