import nmap

scanner = nmap.PortScanner()

# Define target IP address or hostname
target = "scanme.nmap.com"

# Define Nmap options
options = "-sS -sV -O -A -p 1-1000"

# Run the Nmap scan with the specified options
scanner.scan(target, arguments=options)

# Print the scan results
for host in scanner.all_hosts():
    print("Host: ", host)
    print("State: ", scanner[host].state())
    for proto in scanner[host].all_protocols():
        print("Protocol: ", proto)
        ports = scanner[host][proto].keys()
        for port in ports:
            print("Port: ", port, "State: ", scanner[host][proto][port]['state'])