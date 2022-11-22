import socket
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import *

MAX_HOPS = 50


def main():
    target = str(input("Enter target:\n"))
    target_ip = socket.gethostbyname(target)

    for current_hop in range(MAX_HOPS):
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
