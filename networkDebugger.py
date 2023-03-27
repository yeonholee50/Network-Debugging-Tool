import speedtest
import nmap
import socket
import ssl
import logging
import requests
import platform
import subprocess

class NetworkDebugger:
    def __init__(self):
        self.logger = logging.getLogger('network_debugger')
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler('network_debugger.log')
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

    def speed_test(self):
        speedtester = speedtest.Speedtest()
        speedtester.get_best_server()
        download_speed = speedtester.download()
        upload_speed = speedtester.upload()
        return download_speed, upload_speed

    def network_monitoring(self, target_ip):
        nm = nmap.PortScanner()
        nm.scan(target_ip, arguments='-sT -O')
        return nm[target_ip].all_tcp()

    def network_security_check(self, target_ip):
        context = ssl.create_default_context()
        with socket.create_connection((target_ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target_ip) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                return subject

    def dns_resolution_check(self, target_url):
        try:
            socket.gethostbyname(target_url)
        except socket.gaierror:
            return False
        return True

    def ticket_creation(self, ticket_system_url, ticket_data):
        response = requests.post(ticket_system_url, data=ticket_data)
        return response.status_code

    def network_troubleshooting(self, target_ip):
        # Check if the target IP is valid
        try:
            socket.inet_aton(target_ip)
        except socket.error:
            print(f"{target_ip} is an invalid IP address.")
            return
        
        # Ping the target IP to check for basic connectivity
        print("Pinging target IP...")
        response = subprocess.Popen(['ping', '-c', '3', target_ip], stdout=subprocess.PIPE).communicate()[0]
        if "100% packet loss" in response.decode('utf-8'):
            print("Failed to connect to target IP.")
            return
        else:
            print("Ping successful!")
        
        # Check for open ports on the target IP
        print("Checking for open ports...")
        open_ports = []
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        if len(open_ports) == 0:
            print("No open ports found.")
        else:
            print("Open ports found:", open_ports)
        
        # Check the DNS resolution for the target IP
        print("Checking DNS resolution...")
        try:
            hostname = socket.gethostbyaddr(target_ip)
            print(f"DNS resolved to {hostname[0]}")
        except socket.herror:
            print("Failed to resolve DNS.")
        
        # Check the local TCP/IP configuration
        print("Checking local TCP/IP configuration...")
        if platform.system() == "Windows":
            response = subprocess.Popen(['ipconfig', '/all'], stdout=subprocess.PIPE).communicate()[0]
            print(response.decode('utf-8'))
        elif platform.system() == "Linux":
            response = subprocess.Popen(['ifconfig'], stdout=subprocess.PIPE).communicate()[0]
            print(response.decode('utf-8'))
        else:
            print("Unsupported operating system.")
        
        # Perform additional troubleshooting steps here
        
        print("Network troubleshooting complete.")

    def log_network_activity(self, log_message):
        self.logger.info(log_message)

    def machine_learning_analysis(self, network_data):
        # Prepare data for analysis
        features = network_data.drop(columns=['target'])
        target = network_data['target']
        X_train, X_test, y_train, y_test = train_test_split(features, target, test_size=0.3, random_state=42)
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)
        
        # Train a neural network classifier using the data
        clf = MLPClassifier(hidden_layer_sizes=(10,10), max_iter=1000)
        clf.fit(X_train, y_train)
        
        # Make predictions on the test data
        y_pred = clf.predict(X_test)
        
        # Compute accuracy and return results
        accuracy = np.mean(y_pred == y_test)
        return {
            'accuracy': accuracy,
            'model': clf
        }
	  """Uses neural network classifer on the input network data - returns the accuracy of classifier and trained model for usage"""
