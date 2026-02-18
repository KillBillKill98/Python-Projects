import subprocess
import socket
import ipaddress


def find_local_ip():
    """Detect the local machine's IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as temp_socket:
            temp_socket.connect(("8.8.8.8", 80))
            return temp_socket.getsockname()[0]
    except Exception as e:
        print(f"Error retrieving local IP: {e}")
        return None


def find_subnet_range(ip):
    """Calculate the /24 subnet from a given IP."""
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def scan_subnet(subnet, ports="1-65535", script=None):
    """
    Build and run an nmap command against the given subnet.

    FIX 1: Replaced the broken nested-quote f-string with explicit string
            concatenation — Python 3.11 and earlier do not allow the same
            quote character inside an f-string expression.
    """
    cmd_parts = ["nmap", "-p", ports]

    # Only add service-version detection when NOT doing a full port sweep
    if ports != "1-65535":
        cmd_parts.append("-sV")

    if script:
        cmd_parts += ["--script", script]

    cmd_parts.append(str(subnet))

    try:
        result = subprocess.run(
            cmd_parts,          # Pass as a list — safer than shell=True
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        print(f"Error occurred during scan: {e}")
        return None


def ip_range(subnet):
    """Print the human-readable IP range for the subnet."""
    host_count = len(list(subnet.hosts()))
    print(
        f"IP range : {subnet.network_address} – {subnet.broadcast_address} "
        f"({host_count} hosts)"
    )


def print_menu(choices):
    """Display the numbered scan menu."""
    print("\n" + "=" * 55)
    print("  Select a scan type:")
    print("=" * 55)
    for key, (desc, _, _) in choices.items():
        print(f"  {key}. {desc}")
    print("=" * 55)


if __name__ == "__main__":
    local_ip = find_local_ip()

    if not local_ip:
        print("Unable to retrieve local IP address. Exiting.")
        raise SystemExit(1)

    print(f"\n[*] Your local IP address : {local_ip}")
    subnet = find_subnet_range(local_ip)
    print(f"[*] Calculated CIDR       : {subnet}")
    ip_range(subnet)

    
    choices = {
        "1": (
            "Scan all active hosts for open ports (all ports)",
            "1-65535",
            None,
        ),
        "2": (
            "Scan first 1000 ports and identify running services",
            "1-1000",
            None,
        ),
        "3": (
            "Scan all ports and check for vulnerabilities",
            "1-65535",
            "vuln",
        ),
        "4": (
            "Scan first 1000 ports and check for vulnerabilities",
            "1-1000",
            "vuln",
        ),
    }

    while True:
        
        print_menu(choices)
        choice = input("\nEnter your choice (1/2/3/4): ").strip()

        if choice in choices:
            description, ports, script = choices[choice]
            print(f"\n[*] {description} — this may take a while...\n")
            scan_result = scan_subnet(subnet, ports, script)
            if scan_result:
                print("Scan Results:\n" + scan_result)
            else:
                print("Scan failed or returned no results.")
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

        again = input("\nRun another scan? (yes/no): ").strip().lower()
        if again != "yes":
            print("\n[*] Exiting scanner. Goodbye!")
            break
