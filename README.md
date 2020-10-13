# iprunner
IP statistics from PCAP files

Written by Markus Thilo
GPL-3
Runs through PCAP files and statistically analyzes IP packets. Other packets are ignored.
Adresses, ports (on -g), oldest timestamp, youngest timestamp (first seen / last seen), the quantity
of packets and the sum of the packet volumes (as given in PCAP files as orig_len) are listed.

IPRUNNER might not work with all PCAP files. Ethernet link layer should work.

Usage:

iprunner [--help] [-h] [-r] [-c] [-w CSV_OUTFILE] PCAP_INFILE1 [PCAP_INFILE2 ...]

Input file format ist PCAP. PCAPNG does not work.

Options:

--help, -h	Print this help.
-c		Print headlines for the columns (fields).
-r		Print timestamps and traffic volumes in human readable format.
		The time stamps are taken from the PCAP files without any validation or adjustment.

-i		Invert sort output data (from small to large).
-n		Sort by number of packets instead of transfered bytes.
-g		tGrep (filter) for one or two IP addresses.
		Patterns:
		ADDRESS	Copy packets if source or destination address matches.
		ADDRESS-ADDRESS	Copy packets if one address is source and one is the destination.
		Compression of IPv6 addresses removing colons does not work.

Examples:
iprunner -c -r -w out.tsv dump1.pcap dump2.pcap dump3.pcap
iprunner -g ff02:::::::fb dump.pcap
iprunner -g 192.168.1.7-216.58.207.78 -w out.tsv dump.pcap

Use this piece of software on your own risk. Accuracy is not garanteed.

Report bugs to: markus.thilo@gmail.com

Project page: https://github.com/markusthilo/iprunner
