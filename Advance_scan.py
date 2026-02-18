import nmap
import sys


# ---------------------------------------------------------------------------
# Scan profile definitions
# Each entry: (label, nmap_arguments, requires_root)
# ---------------------------------------------------------------------------
SCAN_PROFILES = {
    "1": (
        "SYN + Service + OS + Aggressive scan (ports 1-1000)  [requires root]",
        "-sS -sV -O -A -p 1-1000",
        True,
    ),
    "2": (
        "TCP Connect + Service detection (ports 1-1000)",
        "-sT -sV -p 1-1000",
        False,
    ),
    "3": (
        "Fast scan — top 100 ports only",
        "-F",
        False,
    ),
    "4": (
        "Aggressive scan — all ports with version + script detection  [requires root]",
        "-A -p 1-65535",
        True,
    ),
    "5": (
        "Vulnerability script scan (ports 1-1000)  [requires root]",
        "-sV --script vuln -p 1-1000",
        True,
    ),
    "6": (
        "Custom — enter your own nmap arguments",
        None,   # filled in at runtime
        False,
    ),
}


def print_banner():
    print("\n" + "=" * 60)
    print("          Advanced Interactive Nmap Scanner")
    print("=" * 60)


def print_menu():
    print("\nAvailable scan profiles:")
    print("-" * 60)
    for key, (label, _, root) in SCAN_PROFILES.items():
        print(f"  {key}. {label}")
    print("-" * 60)


def get_target() -> str:
    """Prompt the user for a target and validate it is not empty."""
    while True:
        
        target = input(
            "\nEnter target IP or hostname (e.g. scanme.nmap.org): "
        ).strip()
        if target:
            return target
        print("[!] Target cannot be empty. Please try again.")


def get_profile() -> tuple[str, bool]:
    """Return (nmap_arguments, requires_root) for the chosen profile."""
    print_menu()
    while True:
        choice = input("Select a profile (1-6): ").strip()
        if choice not in SCAN_PROFILES:
            print(f"[!] Invalid choice. Enter a number between 1 and 6.")
            continue

        label, args, root = SCAN_PROFILES[choice]

        if choice == "6":
            # Custom profile — let the user type their own flags
            args = input("Enter custom nmap arguments (e.g. -sV -p 22,80,443): ").strip()
            if not args:
                print("[!] Arguments cannot be empty.")
                continue

        return args, root


def run_scan(target: str, arguments: str) -> None:
    """Execute the nmap scan and print structured results."""
    print(f"\n[*] Scanning '{target}' with options: {arguments}")
    print("[*] Please wait — this may take a while...\n")

    try:
        scanner = nmap.PortScanner()
       
        scanner.scan(hosts=target, arguments=arguments)

    except nmap.PortScannerError as exc:
        print(f"[!] Nmap error: {exc}")
        print("    Make sure nmap is installed and — for privileged scans — run as root/sudo.")
        return
    except Exception as exc:
        print(f"[!] Unexpected error: {exc}")
        return

    if not scanner.all_hosts():
        print("[!] No hosts responded. The target may be unreachable or filtered.")
        return

    for host in scanner.all_hosts():
        print("=" * 55)
        print(f"  Host     : {host} ({scanner[host].hostname()})")
        print(f"  State    : {scanner[host].state()}")

        for proto in scanner[host].all_protocols():
            print(f"\n  Protocol : {proto}")
            print("  " + "-" * 40)

           
            for port in sorted(scanner[host][proto].keys()):
                state = scanner[host][proto][port]["state"]
                service = scanner[host][proto][port].get("name", "unknown")
                version = scanner[host][proto][port].get("version", "")
                version_str = f" ({version})" if version else ""
                print(f"  Port {port:<6} | {state:<12} | {service}{version_str}")

    print("\n" + "=" * 55)
    print("[*] Scan complete.")


def main():
    print_banner()

    while True:
        target = get_target()
        arguments, requires_root = get_profile()

        if requires_root:
            print(
                "\n[!] WARNING: The selected profile uses privileged nmap options\n"
                "    (-sS, -O, -A, etc.) that require root/administrator access.\n"
                "    Re-run this script with 'sudo python advanced_scan.py' if the\n"
                "    scan fails or returns no results."
            )

        run_scan(target, arguments)

        again = input("\nRun another scan? (yes/no): ").strip().lower()
        if again not in ("yes", "y"):
            print("\n[*] Exiting. Goodbye!")
            sys.exit(0)


if __name__ == "__main__":
    main()
