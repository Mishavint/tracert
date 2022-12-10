import socket
import sys

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import *

MAX_HOPS = 50


def main():
    target = str(input("Enter target:\n"))

    try:
        target_ip = socket.gethostbyname(target)
    except Exception:
        print(f"Please enter valid target", file=sys.stderr)
        exit(0)

    for current_hop in range(1, MAX_HOPS):
        response = sr1(
            IP(dst=target_ip, ttl=current_hop) / ICMP(),
            verbose=0,
            timeout=5
        )
        if response is None:
            print(f"{current_hop}: timeout")
        elif response.type == 0:
            print(f"{current_hop}: {response.src}")
            break
        else:
            print(f"{current_hop}: {response.src}")


if __name__ == '__main__':
    main()
