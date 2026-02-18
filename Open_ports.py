import nmap
import sys

def get_user_input():
    """Prompt the user for scan target and port range."""
    print("=" * 50)
    print("       Interactive Nmap Port Scanner")
    print("=" * 50)

    target = input("\nEnter target IP or hostname (default: 127.0.0.1): ").strip()
    if not target:
        target = "127.0.0.1"

    port_range = input("Enter port range (default: 21-443): ").strip()
    if not port_range:
        port_range = "21-443"

    print(f"\n[*] Scanning {target} on ports {port_range}...")
    print("-" * 50)
    return target, port_range


def run_scan(target, port_range):
    """Run the nmap scan and display results."""
    try:
        nm_scan = nmap.PortScanner()
        nm_scan.scan(target, port_range)

        if not nm_scan.all_hosts():
            print("[!] No hosts found. The target may be unreachable or all ports are filtered.")
            return

        for host in nm_scan.all_hosts():
            print(f"\nHost  : {host} ({nm_scan[host].hostname()})")
            print(f"State : {nm_scan[host].state()}")

            for proto in nm_scan[host].all_protocols():
                print("\n" + "-" * 30)
                print(f"Protocol : {proto}")
                print("-" * 30)

                # FIX: dict_keys in Python 3 has no .sort(); convert to sorted list
                lport = sorted(nm_scan[host][proto].keys())

                for port in lport:
                    state = nm_scan[host][proto][port]["state"]
                    print(f"  Port : {port:<6}  State : {state}")

    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        print("    Make sure nmap is installed on your system.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


def main():
    while True:
        target, port_range = get_user_input()
        run_scan(target, port_range)

        print("\n" + "=" * 50)
        again = input("Run another scan? (yes/no, default: no): ").strip().lower()
        if again not in ("yes", "y"):
            print("\n[*] Exiting scanner. Goodbye!")
            break


if __name__ == "__main__":
    main()
