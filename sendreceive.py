#!/usr/bin/python3
import sys
import random
import time
from scapy.all import *

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        print(i)
        if "eth0" in i:
            iface=i
            break
    if not iface:
        exit(1)
    return iface

cpkt = 0

def handle_pkt(pkt):
    global counter1, counter2, cpkt
    # bind_layers( TCP, Stragflow, dport=1234 )
    cpkt += 1
    print("Got a packet, num: {}".format(cpkt))
    
    # pkt.show2()
    assert(pkt[IP].dst == "10.0.0.1")

def main():
    iface = "veth6"
    print("Setting up async sniffer...")
    asniff = AsyncSniffer(iface = iface, prn = lambda x: handle_pkt(x))
    asniff.start()
    print("...done")

    dst_addr = "10.0.0.1"
    src_addr = "10.0.0.2"

    print("Sending on interface %s to %s" % (iface, str(src_addr)))
    print("-" * 100)
    for _ in range(4000):
        pkt =  Ether(dst=get_if_hwaddr(iface), src='ff:ff:ff:ff:ff:ff', type=0x800)
        pkt1 = pkt /IP(dst=dst_addr, src=src_addr, tos=46, proto=17) / UDP(dport=1234, sport=random.randint(49152,65535)) / Raw(randstring(length=16)) # / sys.argv[2]
        sendp(pkt1, iface=iface, verbose=False)


if __name__ == "__main__":
    main()
    time.sleep(10)
