import socket
import sys
from datetime import datetime

# Common port services
PORT_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "ISAKMP",
    514: "Syslog",
    515: "LPD",
    587: "SMTP Submission",
    636: "LDAPS",
    989: "FTPS",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2181: "Zookeeper",
    2483: "Oracle DB SSL",
    2484: "Oracle DB SSL",
    3000: "Dev Server",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion",
    4444: "Metasploit",
    5000: "Flask Dev",
    5432: "PostgreSQL",
    5601: "Kibana",
    5672: "RabbitMQ",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM SSL",
    6379: "Redis",
    6667: "IRC",
    7001: "WebLogic",
    7002: "WebLogic SSL",
    8000: "HTTP Alt",
    8008: "HTTP Alt",
    8080: "HTTP Proxy",
    8081: "HTTP Alt",
    8443: "HTTPS Alt",
    9000: "SonarQube",
    9042: "Cassandra",
    9092: "Kafka",
    9200: "Elasticsearch",
    9418: "Git",
    27017: "MongoDB"
}


def scan_ports(target, start_port, end_port):

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("❌ Hostname could not be resolved.")
        return

    print("\n====================================")
    print("        PYTHON PORT SCANNER")
    print("====================================")
    print(f"Target       : {target}")
    print(f"IP Address   : {target_ip}")
    print(f"Port Range   : {start_port}-{end_port}")
    print("Scan Start   :", datetime.now())
    print("------------------------------------")

    open_ports = []

    try:
        for port in range(start_port, end_port + 1):

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)

            result = sock.connect_ex((target_ip, port))

            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown Service")
                print(f"[OPEN] Port {port:<6} | Service: {service}")
                open_ports.append((port, service))

            sock.close()

    except KeyboardInterrupt:
        print("\n⚠ Scan stopped by user.")
        sys.exit()

    except socket.error:
        print("\n⚠ Network error occurred.")
        sys.exit()

    print("------------------------------------")
    print("Scan End     :", datetime.now())

    if open_ports:
        print("\nOpen Ports Found:")
        for port, service in open_ports:
            print(f"Port {port} - {service}")
    else:
        print("\nNo open ports found.")

    save_results(target, open_ports)


def save_results(target, ports):

    if not ports:
        return

    filename = "scan_results.txt"

    with open(filename, "a") as file:
        file.write(f"\nScan results for {target} - {datetime.now()}\n")
        file.write("-------------------------------------\n")
        for port, service in ports:
            file.write(f"Port {port} - {service}\n")

    print(f"\nResults saved to {filename}")


def menu():

    while True:

        print("\n====================================")
        print("     CYBERSECURITY PORT SCANNER")
        print("====================================")
        print("1. Scan common ports (1-1024)")
        print("2. Custom port scan")
        print("3. Exit")

        choice = input("Select option (1-3): ")

        if choice == "1":

            target = input("\nEnter target domain or IP: ")
            scan_ports(target, 1, 1024)

        elif choice == "2":

            target = input("\nEnter target domain or IP: ")

            try:
                start = int(input("Start port: "))
                end = int(input("End port: "))
            except ValueError:
                print("⚠ Invalid port number.")
                continue

            scan_ports(target, start, end)

        elif choice == "3":

            print("\nExiting program...")
            break

        else:

            print("⚠ Invalid option. Try again.")


if __name__ == "__main__":
    menu()
