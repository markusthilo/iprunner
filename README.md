# iprunner
IP statistics from PCAP files

Written by Markus Thilo
GPL-3

Runs through PCAP files and statistically analyzes IP packets. Other packets are ignored.
Adresses, ports (on -g), oldest timestamp, youngest timestamp (first seen / last seen), the quantity
of packets and the sum of the packet volumes (as given in PCAP files as orig_len) are listed.

This software might not work with all PCAP files. Ethernet link layer should work.
PCAPNG is not supported.

All you need is in the source file: iprunner.c

## Compile:

gcc -o iprunner iprunner.c

(or use make)

## Usage:
./pcaprunner -h (to get the Options)

## Examples:
./iprunner -r -w out.tsv dump1.pcap dump2.pcap dump3.pcap

./iprunner -g ff02:::::::fb dump.pcap

./iprunner -g 192.168.1.7-216.58.207.78 -w out.tsv dump.pcap

Use this piece of software on your own risk. Accuracy is not garanteed.

Report bugs to: markus.thilo@gmail.com

Project page: https://github.com/markusthilo/iprunner
