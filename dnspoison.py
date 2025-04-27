from scapy.all import sniff, send, IP, UDP, DNS, DNSQR, DNSRR
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
    # TODO:


def dns_spoof(pkt):
    """
    Callback function triggered when a DNS query is sniffed.
    Decide whether to spoof and send a fake response.
    """
    # TODO:

def create_and_send(pkt, ipaddr):
    """
    1. Build a fake DNS response packet 
    2. Clean up length and checksum (let scapy auto-fill)
    3. Send it back to the victim.
    """
    # TODO: 


def sniff_pkts(iface, bpf):
    """
    Start sniffing packets on the network and apply DNS spoofing logic.
    """
    # TODO:


# ========== Main Program ==========

iface, file, bpf = get_arguments()

# TODO: Load hostnames file if provided
if file:
    file_to_dict(file)

# TODO: Start sniffing and spoofing
sniff_pkts(iface, bpf)