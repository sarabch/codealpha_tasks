# Task 1 — Basic Network Sniffer

**CodeAlpha — Cyber Security Internship**
**Auteur :** Sarah Boucherou

## Objectif

Créer un programme Python capable de capturer les paquets circulant sur le réseau
et d'afficher les informations essentielles : adresses IP source/destination,
protocole utilisé (TCP/UDP/ICMP), ports, et un extrait du payload.

## Fonctionnement

Le script utilise la librairie [Scapy](https://scapy.net/) pour capturer les
paquets en direct sur une interface réseau. Pour chaque paquet IP capturé, il affiche :

- l'heure de capture
- le protocole (TCP, UDP, ICMP)
- l'IP et le port source
- l'IP et le port destination
- la taille du paquet
- un aperçu du payload (si présent)

## Installation

```bash
pip install scapy
```

## Utilisation

```bash
# Capture sur l'interface par défaut (nécessite les droits admin)
sudo python3 network_sniffer.py

# Capture sur une interface précise
sudo python3 network_sniffer.py -i eth0

# S'arrêter après 50 paquets
sudo python3 network_sniffer.py -c 50

# Filtrer uniquement le trafic TCP
sudo python3 network_sniffer.py -f "tcp"

# Filtrer un port précis (ex: trafic web)
sudo python3 network_sniffer.py -f "port 80"
```

> ⚠️ La capture de paquets nécessite des privilèges administrateur (root/sudo),
> car elle demande un accès direct à l'interface réseau.

## Exemple de sortie

```
=== Basic Network Sniffer - CodeAlpha ===
Interface : defaut
Filtre    : aucun
Appuyez sur Ctrl+C pour arreter.

[14:32:10] TCP   192.168.1.10:52344 -> 142.250.75.14:443 | len=66
[14:32:11] UDP   192.168.1.10:59321 -> 8.8.8.8:53 | len=71
          payload: google.com
```

## Ce que j'ai appris

- La structure d'un paquet réseau (couches IP, TCP/UDP, payload).
- La différence entre TCP et UDP et leur utilisation.
- Comment utiliser Scapy pour capturer et analyser du trafic réseau en direct.
- L'importance des filtres BPF pour cibler un trafic précis.

## Avertissement éthique

Ce script est destiné à un usage éducatif, uniquement sur des réseaux dont vous
êtes propriétaire ou pour lesquels vous avez une autorisation explicite. La
capture de trafic sur un réseau tiers sans autorisation est illégale.
