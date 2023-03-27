import socket
import subprocess

# Define a function to check if a given port is open
def check_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error checking port {port} on {ip}: {str(e)}")
        return False

# Define a function to ping a given IP address
def ping_ip(ip):
    try:
        output = subprocess.check_output(["ping", "-c", "1", "-W", "2", ip])
        return True
    except Exception as e:
        print(f"Error pinging {ip}: {str(e)}")
        return False

# Define a function to scan a given subnet for open ports
def scan_subnet(subnet, start_port, end_port):
    for i in range(start_port, end_port+1):
        ip = f"{subnet}.{i}"
        if ping_ip(ip):
            for port in range(start_port, end_port+1):
                if check_port(ip, port):
                    print(f"Port {port} is open on {ip}")

# Define a function to perform a traceroute to a given host
def traceroute(host):
    try:
        output = subprocess.check_output(["traceroute", host])
        print(output.decode())
    except Exception as e:
        print(f"Error performing traceroute to {host}: {str(e)}")

# Define a function to test download and upload speeds
def test_speed(url):
    try:
        output = subprocess.check_output(["speedtest-cli", "--simple", "--timeout", "10", "--server", url])
        print(output.decode())
    except Exception as e:
        print(f"Error testing speed: {str(e)}")

# Define a function to display network interfaces and their configurations
def show_interfaces():
    try:
        output = subprocess.check_output(["ifconfig"])
        print(output.decode())
    except Exception as e:
        print(f"Error showing network interfaces: {str(e)}")

# Define a function to display the routing table
def show_routes():
    try:
        output = subprocess.check_output(["netstat", "-nr"])
        print(output.decode())
    except Exception as e:
        print(f"Error showing routing table: {str(e)}")

def ping_check(ip_address):
    """
    Pings an IP address to check if it's reachable.
    Returns True if reachable, False otherwise.
    """
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "2", ip_address])
        return True
    except subprocess.CalledProcessError:
        return False

def port_scan(ip_address, start_port, end_port):
    """
    Scans a range of ports on an IP address to check if they're open.
    Returns a list of open ports.
    """
    open_ports = []
    for port in range(start_port, end_port+1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def traceroute(ip_address):
    """
    Performs a traceroute to an IP address and returns the results.
    """
    traceroute_output = subprocess.check_output(["traceroute", "-w", "2", ip_address])
    return traceroute_output.decode()

def nslookup(hostname):
    """
    Performs an nslookup on a hostname and returns the IP address.
    """
    nslookup_output = subprocess.check_output(["nslookup", hostname])
    nslookup_lines = nslookup_output.decode().splitlines()
    ip_address = None
    for line in nslookup_lines:
        if line.startswith("Address:"):
            ip_address = line.split(":")[1].strip()
            break
    return ip_address

def whois(ip_address):
    """
    Performs a whois lookup on an IP address and returns the results.
    """
    whois_output = subprocess.check_output(["whois", ip_address])
    return whois_output.decode()


