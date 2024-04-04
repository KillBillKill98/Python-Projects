import subprocess
import socket
import ipaddress

def find_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_socket:
            temp_socket.connect(("8.8.8.8", 80))
            return temp_socket.getsockname()[0]
    except Exception as e:
        print(f"Error: {e}")

def find_subnet_range(ip):
    return ipaddress.ip_network(f"{ip}/24", strict=False)

def scan_subnet(subnet, ports="1-65535", script=None):
    command = f'nmap -p {ports}{" -sV" if ports != "1-65535" else ""}{' --script ' + script if script else ""} {subnet}'
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error occurred: {e}")

def ip_range(subnet):
    print(f"The IP range is {subnet.network_address} - {subnet.broadcast_address} ({len(list(subnet.hosts()))} hosts)")

if __name__ == "__main__":
    local_ip = find_local_ip()
    if local_ip:
        print(f"Your local IP Address is: {local_ip}")
        subnet = find_subnet_range(local_ip)
        print(f"The calculated CIDR notation is: {subnet}")
        ip_range(subnet)

        choices = {
            "1": ("Scan all active hosts for open ports", ""),
            "2": ("Scan all active hosts for the first 1000 ports and determine the running services", "1-1000"),
            "3": ("Scan all hosts on all open ports to determine if any running services have vulnerabilities", "", "vuln"),
            "4": ("Scan all active hosts for the first 1000 ports to identify if any services have vulnerabilities", "1-1000", "vuln"),
        }

        while True:
            for key, (desc, _) in choices.items():
                print(f"{key}. {desc}")
            choice = input("\nEnter your choice (1/2/3/4): ")

            if choice in choices:
                description, ports, script = choices[choice]
                print(f"\n{description}.....")
                scan_result = scan_subnet(subnet, ports, script)
                print("Scan Results:\n" + scan_result if scan_result else "Scan failed or no vulnerabilities found.")
            else:
                print("Invalid choice.")

            if input("\nDo you want to run the program again? (yes/no): ").lower() != 'yes':
                break
    else:
        print("Unable to retrieve local IP address.")
