#!/usr/bin/env python3
"""
Basic Network Sniffer
CodeAlpha - Cyber Security Internship - Task 1

Capture les paquets circulant sur l'interface réseau et affiche :
- IP source / destination
- Protocole (TCP / UDP / ICMP)
- Ports source / destination (pour TCP/UDP)
- Un extrait du payload (donnees applicatives)

Necessite les droits administrateur (root / sudo) pour capturer le trafic reseau.

Installation :
    pip install scapy

Utilisation :
    sudo python3 network_sniffer.py                # capture sur l'interface par defaut
    sudo python3 network_sniffer.py -i eth0         # capture sur une interface precise
    sudo python3 network_sniffer.py -c 50           # s'arrete apres 50 paquets
    sudo python3 network_sniffer.py -f "tcp"        # filtre BPF (ex: "tcp", "udp", "port 80")
"""

import argparse
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def format_payload(packet, max_len=60):
    """Retourne un apercu lisible du payload (ou None s'il n'y en a pas)."""
    if Raw in packet:
        raw_bytes = bytes(packet[Raw].load)
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            text = str(raw_bytes)
        text = text.replace("\n", " ").replace("\r", " ")
        return text[:max_len] + ("..." if len(text) > max_len else "")
    return None


def handle_packet(packet):
    """Callback appele pour chaque paquet capture par scapy."""
    if IP not in packet:
        return  # on ignore les paquets non-IP (ARP, etc.) pour rester simple

    ip_layer = packet[IP]
    proto_name = PROTOCOLS.get(ip_layer.proto, str(ip_layer.proto))
    timestamp = datetime.now().strftime("%H:%M:%S")

    src_port = dst_port = None
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    print(f"[{timestamp}] {proto_name:<5} "
          f"{ip_layer.src}:{src_port if src_port else '-'} "
          f"-> {ip_layer.dst}:{dst_port if dst_port else '-'} "
          f"| len={len(packet)}")

    payload = format_payload(packet)
    if payload:
        print(f"          payload: {payload}")


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (CodeAlpha Task 1)")
    parser.add_argument("-i", "--interface", default=None,
                         help="Interface reseau a ecouter (ex: eth0, wlan0). Par defaut: interface par defaut du systeme.")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Nombre de paquets a capturer (0 = illimite, arret avec Ctrl+C).")
    parser.add_argument("-f", "--filter", default=None,
                         help='Filtre BPF, ex: "tcp", "udp", "port 80", "host 8.8.8.8".')
    args = parser.parse_args()

    print("=== Basic Network Sniffer - CodeAlpha ===")
    print(f"Interface : {args.interface or 'defaut'}")
    print(f"Filtre    : {args.filter or 'aucun'}")
    print("Appuyez sur Ctrl+C pour arreter.\n")

    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=handle_packet,
        store=False,
        count=args.count if args.count > 0 else 0,
    )


if __name__ == "__main__":
    main()

