/* IPRUNNER v0.2-20201016 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
//#include <ctype.h>

/* Print help */
void help(int r){
	printf("\nIPPRUNNER v0.1-20201014n\n");
	printf("Written by Markus Thilo\n");
	printf("GPL-3\n");
	printf("Runs through PCAP files and statistically analyzes IP packets. Other packets are ignored.\n");
	printf("Adresses, ports (on -g), oldest timestamp, youngest timestamp (first seen / last seen), the quantity\n");
	printf("of packets and the sum of the packet volumes (as given in PCAP files as orig_len) are listed.\n\n");
	printf("IPRUNNER might not work with all PCAP files. Ethernet link layer should work.\n\n");
	printf("Usage:\n\n");
	printf("iprunner [--help] [-h] [-r] [-c] [-i] [-n] [-g PATTERN] [-w CSV_OUTFILE] PCAP_INFILE1 [PCAP_INFILE2 ...]\n");
	printf("\nInput file format ist PCAP. PCAPNG does not work.\n");
	printf("\nOptions:\n\n");
	printf("--help, -h\tPrint this help.\n");
	printf("-c\t\tPrint headlines for the columns (fields).\n");
	printf("-r\t\tPrint timestamps and traffic volumes in human readable format.\n");
	printf("\t\tThe time stamps are taken from the PCAP files without any validation or adjustment.\n\n");
	printf("-i\t\tInvert sort output data (from small to large).\n");
	printf("-n\t\tSort by number of packets instead of transfered bytes.\n");
	printf("-s\t\tSum up all traffic regardless the transport layer and create a shortel list.\n");
	printf("\t\tThis is ignored on -g (grep).\n");
	printf("-g\t\ttGrep (filter) for one or two IP addresses.\n");
	printf("\t\tPatterns:\n");
	printf("\t\tADDRESS\tCopy packets if source or destination address matches.\n");
	printf("\t\tADDRESS-ADDRESS\tCopy packets if one address is source and one is the destination.\n");
	printf("\t\tCompression of IPv6 addresses removing colons does not work.\n\n");
	printf("Examples:\n");
	printf("iprunner -c -r -w out.tsv dump1.pcap dump2.pcap dump3.pcap\n");
	printf("iprunner -g ff02:::::::fb dump.pcap\n");
	printf("iprunner -g 192.168.1.7-216.58.207.78 -w out.tsv dump.pcap\n\n");
	printf("Use this piece of software on your own risk. Accuracy is not garanteed.\n\n");
	printf("Report bugs to: markus.thilo@gmail.com\n\n");
	printf("Project page: https://github.com/markusthilo/iprunner\n\n");
	exit(r);
}

/* Write error */
void writeerror() {
	fprintf(stderr, "Error while writing to file.\n");
	exit(1);
}

/* Error while allocating memory */
void memerror() {
	fprintf(stderr, "Error while allocating memory.\n");
	exit(1);
}

/* Wrong grep pattern syntax */
void greperror() {
	fprintf(stderr, "Error: wrong syntax in grep pattern (-g).\n");
	exit(1);
}

/* Read 16 bits from array */
uint16_t readuint16(uint8_t *a, int pos) {
	return ( ( ( (uint16_t) a[pos] ) << 8 )
			| ( (uint16_t) a[pos+1] ) );
}

/* Read 32 bits from array */
uint32_t readuint32(uint8_t *a, int pos) {
	return ( ( ( (uint32_t) a[pos] ) << 24 )
			| ( ( (uint32_t) a[pos+1] ) << 16 )
			| ( ( (uint32_t) a[pos+2] ) << 8 )
			| ( (uint32_t) a[pos+3] ) );
}

/* Read 32 bits from file in swapped byte order */
uint32_t readuint32swapped(uint8_t *a, int pos) {
	return ( ( ((uint32_t) a[pos+3] ) << 24 )
			| ( ( (uint32_t) a[pos+2] ) << 16 )
			| ( ( (uint32_t) a[pos+1] ) << 8 )
			| ( (uint32_t) a[pos] ) );
}

/* Read 64 bits from array */
uint64_t readuint64(uint8_t *a, int pos) {
	return ( ( ( (uint64_t) a[pos] ) << 56 )
		| ( ( (uint64_t) a[pos+1] ) << 48 )
		| ( ( (uint64_t) a[pos+2] ) << 40 )
		| ( ( (uint64_t) a[pos+3] ) << 32 )
		| ( ( (uint64_t) a[pos+4] ) << 24 )
		| ( ( (uint64_t) a[pos+5] ) << 16 )
		| ( ( (uint64_t) a[pos+6] ) << 8 )
		| ( (uint64_t) a[pos+7] ) );
}

/* Structure for IP address */
struct ipaddr {
	uint64_t addr[2];
};

/* Read IPv4 address from array and parse to v6 */
struct ipaddr readipv4(uint8_t *a, int pos) {
	struct ipaddr ip = {0, 0};
	ip.addr[1] = (uint64_t) ( readuint32(a, pos) & 0xffffffff | 0xffff00000000); // read 32 bits = 4 octets
	return ip;
}

/* Read IPv6 address from array */
struct ipaddr readipv6(uint8_t *a, int pos) {
	struct ipaddr ip;
	ip.addr[0] = readuint64(a, pos);	// read first 8 octets
	ip.addr[1] = readuint64(a, pos+8);	// read 2nd 8 octets
	return ip;
}

/* Give IP address version - 4 or 6 */
int ipversion(struct ipaddr ip) {
	if (( ip.addr[0] == 0 ) && ( ( ip.addr[1] & 0xffffffff00000000 ) == 0xffff00000000 )) return 4;
	return 6;
}

/* Check if 2 IP adresses are equal */
int eqaddr(struct ipaddr ip1, struct ipaddr ip2) {
	if ( ( ip1.addr[0] == ip2.addr[0] )
		&& ( ip1.addr[1] == ip2.addr[1] ) ) return 1;
	return 0;
}

/* Check for 0 IP adresses */
int nulladdr(struct ipaddr ip) {
	if ( ip.addr[0] == 0 && ip.addr[1] == 0 ) return 1;
	return 0;
}

/* Convert given decimal number (char) integer */
int dec2int(char c) {
	if ( ( c >= '0' ) && (  c <= '9' ) ) return c - '0';
	return -1;
}

/* Convert given hexadecimal number (0-9a-fA-F) integer */
int hex2int(char c) {
	int n = dec2int(c);
	if ( n >= 0 ) return n;
	if ( ( c >= 'a' ) && (  c <= 'f' ) ) return c - ('a'-0xa);
	if ( ( c >= 'A' ) && (  c <= 'F' ) ) return c - ('A'-0xa);
	return -1;
}

/* Convert decimal byte in string to integer inbetween 0 and 255 */
int decbyte2int(char *string, int *s_pos) {
	if ( string[*s_pos] < '0' || string[*s_pos] > '9'  ) return -1;
	int byte = 0, cifer;
	while ( string[*s_pos] != 0 && string[*s_pos] != '.' && string[*s_pos] != '-' ) {
		cifer = dec2int(string[*s_pos]);
		*s_pos += 1;
		if ( cifer < 0 ) return -1;
		byte = ( byte * 10 ) + cifer;
	}
	if ( byte > 255 ) return -1;
	return byte;
}

/* Convert 2 hexadecimal bytes in string to long integer inbetween 0 and 0xffff */
long hexbytes2long(char *string, int *s_pos) {
	long bytes = 0;
	int cifer;
	while ( string[*s_pos] != 0 && string[*s_pos] != ':' && string[*s_pos] != '-' ) {
		cifer = hex2int(string[*s_pos]);
		*s_pos += 1;
		if ( cifer < 0 ) return -1;
		bytes = ( bytes << 4 ) + cifer;
	}
	if ( bytes > 0xffff ) return -1;
	return bytes;
}

/* Convert string to binary IP address */
struct ipaddr str2ip(char *string, int *s_pos) {
	struct ipaddr ip;
	ip.addr[0] = 0;
	ip.addr[1] = 0;
	int new_pos = *s_pos, p_cnt = 0, byte;
	while (1) {
		byte = decbyte2int(string, &new_pos);
		if ( byte < 0 ) {
			p_cnt = 0;
			break;
		}
		ip.addr[1] = ( ip.addr[1] << 8 ) + byte;
		if ( string[new_pos] == 0 || string[new_pos] == '-' || p_cnt++ > 3 ) break;
		new_pos++;
	}
	if ( p_cnt == 3 ) {
		ip.addr[1] = ip.addr[1] + 0xffff00000000;	// v4 in v6 is 0000::ffff:xxxx:xxxx
		*s_pos = new_pos;
		return ip;
	}
	ip.addr[1] = 0;	// reset 2nd byte that might have changed
	new_pos = *s_pos;
	p_cnt = 0;
	int i = 0;
	long bytes;
	while (1) {
		bytes = hexbytes2long(string, &new_pos);
		if ( bytes < 0 ) {
			ip.addr[0] = 0;
			ip.addr[1] = 0;
			return ip;
		}
		ip.addr[i] = ( ip.addr[i] << 16 ) + bytes;
		if ( string[new_pos] == 0 || string[new_pos] == '-' || p_cnt++ > 7 ) break;
		new_pos++;
		if ( p_cnt == 4 ) i = 1;
	}
	if ( p_cnt != 7 ) {
		ip.addr[0] = 0;
		ip.addr[1] = 0;
	}
	*s_pos = new_pos;
	return ip;
}

/* Structure for grep pattern */
struct gpattern {
	struct ipaddr ip1, ip2;
	char type;
};

/* Get grep pattern */
struct gpattern getgrep(char *string) {
	struct gpattern gp;	// to return
	int s_pos = 0;
	gp.ip1 = str2ip(string, &s_pos);
	if ( nulladdr(gp.ip1) == 1 ) greperror();
	if ( string[s_pos] == 0 ) {
		gp.type = 't';
		return gp;
	}
	if ( string[s_pos++] != '-' ) greperror();
	gp.ip2 = str2ip(string, &s_pos);
	if ( nulladdr(gp.ip2) == 1 || string[s_pos] != 0 ) greperror();
	gp.type = 'l';
	return gp;
}

/* Print address */
void fprintaddr(FILE *wfd, struct ipaddr ip) {
	if ( ipversion(ip) == 4 )	/* ip v4 */
		fprintf(wfd, "%lu.%lu.%lu.%lu",
			( ip.addr[1] >> 24 ) & 0xff,
			( ip.addr[1] >> 16 ) & 0xff,
			( ip.addr[1] >> 8 ) & 0xff,
			ip.addr[1] & 0xff
		);
	else {	/* ip v6 */
		fprintf(wfd, "%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx",
			( ip.addr[0] >> 48 ) & 0xffff,
			( ip.addr[0] >> 32 ) & 0xffff,
			( ip.addr[0] >> 16 ) & 0xffff,
			ip.addr[0] & 0xffff,
			( ip.addr[1] >> 48 ) & 0xffff,
			( ip.addr[1] >> 32 ) & 0xffff,
			( ip.addr[1] >> 16 ) & 0xffff,
			ip.addr[1] & 0xffff
		);
	}
}

/* Print port number if grep pattern is given */
void fprintport(FILE *wfd, uint16_t port, char set_type, char protocol) {
	if ( set_type == 'b' || set_type == 's' ) return;
	if ( protocol == 'o' ) fprintf(wfd, "\t-");
	else fprintf(wfd, "\t%u", port);
}

/* Print timestamp regardless timezone - just as it is stored in the PCAP file */
void fprintts(FILE *wfd, uint64_t ts, char format) {
	if ( format == 'r' ) {	// print in human readable format, might be GMT
		struct tm *ts_info;
		time_t ts_sec;
		ts_sec = (time_t)(ts >> 32);
		char ts_str[32];
		strftime(ts_str, 20, "%Y-%m-%d %X", localtime(&ts_sec));
		fprintf(wfd, "\t%s", ts_str);
	} else fprintf(wfd, "\t%lu", ts >> 32);	// seconds since 1970
	fprintf(wfd, ".%06lu", ts & 0xffffffff);	// add microseconds
}

/* Print bytes */
void fprintbytes(FILE *wfd, uint64_t sum, char format) {
	if ( format == 'r' ) {	// print in human readable format
		uint64_t tmp = sum / 1000000000000000;
		if ( tmp > 9 ) fprintf(wfd, "\t%lu PB", tmp);
		else {
			tmp = sum / 1000000000000;
			if ( tmp > 9 ) fprintf(wfd, "\t%lu TB", tmp);
			else {
				tmp = sum / 1000000000;
				if ( tmp > 9 ) fprintf(wfd, "\t%lu GB", tmp);
				else {
					tmp = sum / 1000000;
					if ( tmp > 9 ) fprintf(wfd, "\t%lu MB", tmp);
					else {
						tmp = sum / 1000;
						if ( tmp > 9 ) fprintf(wfd, "\t%lu kB", tmp);
						else fprintf(wfd, "%\tu B", sum);
					}
				}
			}
		}
	} else  fprintf(wfd, "\t%lu", sum);
}

/* Print head line*/
void fprinthead(FILE *wfd, char set_type) {
	switch (set_type) {
		case 'b': fprintf(wfd, "SRC_ADDR\tDST_ADDR"); break;
		case 's': fprintf(wfd, "ADDR"); break;
		default: fprintf(wfd, "SRC_ADDR\tSRC_PORT\tDST_ADDR\tDST_PORT\tPROTOCOL");
	}
	if (set_type != 's' ) fprintf(wfd, "\tPROTOCOL");
	fprintf(wfd, "\tFIRST_TS\tLAST_TS");
	if ( set_type == 's' ) fprintf(wfd, "\tPACKETS_IN\tPACKETS_OUT\tVOLUME_IN\tVOLUME_OUT\n");
	else fprintf(wfd, "\tPACKETS\tVOLUME\n");
}

/* Structure for one statistical data set */
struct statset {
	struct ipaddr src_addr, dst_addr;
	uint16_t src_port, dst_port;
	char protocol;
	uint64_t first_seen, last_seen, cnt, sum;
};

/* Print statistical data set structure */
void fprintset(FILE *wfd, struct statset set, char set_type, char format) {
	if ( set_type == 's' ) return;
	fprintaddr(wfd, set.src_addr);
	fprintport(wfd, set.src_port, set_type, set.protocol);
	fprintf(wfd, "\t");
	fprintaddr(wfd, set.dst_addr);
	fprintport(wfd, set.dst_port, set_type, set.protocol);
	switch (set.protocol) {
		case 't': fprintf(wfd, "\ttcp"); break;
		case 'u': fprintf(wfd, "\tudp"); break;
		default: fprintf(wfd, "\tother");
	}
	fprintts(wfd, set.first_seen, format);
	fprintts(wfd, set.last_seen, format);
	fprintf(wfd, "\t%lu", set.cnt);
	fprintbytes(wfd, set.sum, format);
	fprintf(wfd, "\n");
}

/* Structure for single address, number of packets and traffic volume */
struct single {
	struct ipaddr addr;
	uint64_t first_seen, last_seen, cnt_in, cnt_out, cnt, sum_in, sum_out, sum;
};

/* Print single ip address structure */
void fprintsingle(FILE *wfd, struct single set, char format) {
	fprintaddr(wfd, set.addr);
	fprintf(wfd, "\t");
	fprintts(wfd, set.first_seen, format);
	fprintts(wfd, set.last_seen, format);
	fprintf(wfd, "\t%lu\t%lu", set.cnt_in, set.cnt_out);
	fprintbytes(wfd, set.sum_in, format);
	fprintbytes(wfd, set.sum_out, format);
	fprintf(wfd, "\n");
}

/* Structure for pcap file header */
struct pcapheader {
	uint32_t magic_number, network;
	int error;
};

/* Read pcap file header */
struct pcapheader readpcapheader(FILE *fd) {
	struct pcapheader header;
	uint8_t b[24];
	header.error = -1;	// go to next pcap file
	if ( fread(&b, 24, 1, fd) != 1 ) return header;
	header.magic_number = readuint32(b, 0);
	if ( header.magic_number != 0xa1b2c3d4 && header.magic_number != 0xd4c3b2a1 ) {	// check for pcap file type
		header.error = 2;
		return header;
	}
	if ( header.magic_number == 0xa1b2c3d4 ) header.network = readuint32(b, 20);
	else header.network = readuint32swapped(b, 20);

	if ( header.network > 1 ) {	// check for pcap file type
		header.error = 3;
		return header;
	}
	header.error = 0;
	return header;
}

/* Structure for one packet in pcap file*/
struct packetdata {
	uint64_t ts;
	uint32_t incl_len, orig_len, seek2next;
	char protocol;
	struct ipaddr src_addr, dst_addr;
	uint16_t src_port, dst_port;
	int ipv, error;
};

/* Read packet header */
struct packetdata readframe(FILE *fd, uint32_t magic_number) {
	struct packetdata packet;
	uint8_t b[16];
	packet.error = 1;
	if (fread(&b, 16, 1, fd) != 1) return packet;	// read packet header from pcap file
	if ( magic_number == 0xa1b2c3d4 ) {	// normal byte order
		packet.ts = readuint64(b, 0);
		packet.incl_len = readuint32(b, 8);
		packet.orig_len = readuint32(b, 4);
	} else {	// swapped byte order
		packet.ts = ( (uint64_t) readuint32swapped(b, 0) << 32 )
			| ( (uint64_t) readuint32swapped(b, 4) & 0xffffffff );
		packet.incl_len = readuint32swapped(b, 8);
		packet.orig_len = readuint32swapped(b, 12);
	}
	packet.seek2next = packet.incl_len;
	packet.error = 0;	// no errors
	return packet;
}

/* Read null or data link layer */
struct packetdata readlayer2(FILE *fd, struct packetdata packet, uint32_t network) {
	packet.error = 1;	//	1 means something went wrong
	packet.ipv = 0;
	uint8_t b[14];
	switch (network) {	// data link type
		case 0:	// null
			if (fread(&b, 4, 1, fd) != 1) return packet;	// family and version
			packet.error = 0;
			packet.seek2next -= 4;
			uint32_t family = readuint32(b, 0);
			switch (family) {
				case 0x2000000: packet.ipv = 4; break;	// ipv4
				case 0x1800000: packet.ipv = 6;	// ipv6
			}
			break;
		case 1:	// ethernet
			if (fread(&b, 14, 1, fd) != 1) return packet;	// ethernet layer
			packet.error = 0;
			packet.seek2next -= 14;
			uint16_t type = readuint16(b, 12);	// get type
			switch (type) {
				case 0x0800: packet.ipv = 4; break;	// ipv4
				case 0x86dd: packet.ipv = 6;	// ipv6
			}
	}
	return packet;
}

/* Read IP layer */
struct packetdata readlayer3(FILE *fd, struct packetdata packet) {
	packet.error = 1;
	uint8_t b[40], protocol;
	switch (packet.ipv) {
		case 4:	// ipv4
			if ( fread(&b, 20, 1, fd) != 1 ) return packet;	// read ip layer
			packet.seek2next -= 20;	// to jump to next packet in pcap file later
			if ( b[0] == 0x45 ) {	// ipv4 with header length 20
				protocol = b[9];	// ip.proto
				packet.src_addr = readipv4(b, 12);	// read source address
				packet.dst_addr = readipv4(b, 16);	// read destination address
			}
			break;
		case 6:	// ipv6
			if ( fread(&b, 40, 1, fd) != 1 ) return packet;	// read ip layer
			packet.seek2next -= 40;
			protocol = b[6];	// iv6.next
			packet.src_addr = readipv6(b, 8);	// read source address
			packet.dst_addr = readipv6(b, 24);	// read destination address
			break;
	}
	switch (protocol) {
		case 0x06: packet.protocol = 't'; break;
		case 0x11: packet.protocol = 'u'; break;
		default: packet.protocol = 'o';
	}
	packet.error = 0;
	return packet;
}

/* Read transport layer */
struct packetdata readlayer4(FILE *fd, struct packetdata packet) {
	packet.error = 1;	
	if ( packet.protocol != 'o' ) {	// TCP or UDP
		uint8_t b[4];
		if (fread(&b, 4, 1, fd) != 1) return packet;	// read ip layer
		packet.seek2next -= 4;		
		packet.src_port = readuint16(b, 0);	// read source port
		packet.dst_port = readuint16(b, 2);	// read destination port
	}
	packet.error = 0;
	return packet;
}

/* Read packet from pcap file */
struct packetdata readpacket(FILE *fd, struct pcapheader pcap) {
	struct packetdata packet = readframe(fd, pcap.magic_number);
	if ( packet.error != 0 ) return packet;
	packet = readlayer2(fd, packet, pcap.network);	
	if ( packet.error != 0 || packet.ipv == 0 ) return packet;
	packet = readlayer3(fd, packet);	
	if ( packet.error != 0 || packet.protocol == 'o' ) return packet;
	packet = readlayer4(fd, packet);
	if ( packet.error != 0 ) return packet;
	if ( fseek(fd, packet.seek2next, SEEK_CUR) != 0 ) packet.error = -1;	// go to next pcap file
	else packet.error = 0;
	return packet;	// all done in the packet
}

/* Structure for array to store statistics */
struct sarray {
	struct statset *array;
	uint64_t cnt, size, blk;
};

/* Create data set and append to array */
void appendset(struct sarray *stats, struct packetdata packet) {
	if ( stats->cnt == stats->size) {
		stats->size *= stats->blk;
		stats->array = realloc(stats->array, stats->size * sizeof(struct statset));	/* get more memory */
		if ( stats->array == NULL ) memerror();	// just in case...
	}
	stats->array[stats->cnt].src_addr = packet.src_addr;	// store the data from PCAP file in the dynamic array
	stats->array[stats->cnt].dst_addr = packet.dst_addr;
	stats->array[stats->cnt].src_port = packet.src_port;
	stats->array[stats->cnt].dst_port = packet.dst_port;
	stats->array[stats->cnt].protocol = packet.protocol;
	stats->array[stats->cnt].first_seen = packet.ts;
	stats->array[stats->cnt].last_seen = packet.ts;
	stats->array[stats->cnt].cnt = 1;
	stats->array[stats->cnt].sum = packet.orig_len;
	stats->cnt += 1;	// updatet counter
}

/* Update timestamps, packet counters and volume */
void updatetscntsum(struct statset *set, struct packetdata packet) {
	if ( packet.ts > set->last_seen ) set->last_seen = packet.ts;	// update timestamps
	else if ( packet.ts < set->first_seen ) set->first_seen = packet.ts;
	set->cnt += 1;
	set->sum += packet.orig_len;
}

/* Check if protocol, source and destination addresses matches */
int chckproaddr(struct statset set, struct packetdata packet) {
	if ( ( packet.protocol == set.protocol )	// identical protocol?
		&& ( eqaddr(packet.src_addr, set.src_addr) == 1 )	// identical addresses?
		&& ( eqaddr(packet.dst_addr, set.dst_addr) == 1 )
	) return 1;
	return 0;
}

/* Check if ports matches */
int chckports(struct statset set, struct packetdata packet) {
	if ( ( packet.src_port == set.src_port ) && ( packet.dst_port == set.dst_port ) ) return 1;
	return 0;
}

/* Update array with basic address to address statistics, port is ignored */
void searchset(struct sarray *stats, struct packetdata packet, char set_type) {
	for (uint64_t i=0; i<stats->cnt; i++) {	// loop through the array
		if ( chckproaddr(stats->array[i], packet) == 0 ) continue;	// different protocol or addresses?
		if ( ( set_type != 'b' )	// if other than basic statistics: different ports?
			&& ( ( packet.src_port != stats->array[i].src_port )
				|| ( packet.dst_port != stats->array[i].dst_port )
			)
		) continue;
		updatetscntsum(&stats->array[i], packet);
		return;
	}
	appendset(stats, packet);	// no match -> append new data set to array
}

/* Main function - program starts here*/
int main(int argc, char **argv) {
	if ( ( argc > 1 )	// show help
	&& ( ( ( argv[1][0] == '-' ) && ( argv[1][1] == '-' ) && ( argv[1][2] == 'h' ) )
	|| ( ( argv[1][0] == '-' ) && ( argv[1][1] == 'h' ) ) ) ) help(0);
	else if ( argc < 2 ) help(1);	// also show help if no argument is given but return with exit(1)
	char opt;	// command line options
	char readable_format = ' ', col_head_line = ' ', sort_invert = ' ', sort_cnt = ' ', shorter = 'b';	// switches
	char *gvalue = NULL, *wvalue = NULL;	// pointer to command line arguments
	while ((opt = getopt(argc, argv, "rcinsg:w:")) != -1)	// command line arguments
		switch (opt) {
			case 'r': readable_format = 'r'; break;	// human readable output format
			case 'c': col_head_line = 'c'; break;	// show meanings of columns in a head line
			case 'i': sort_invert = 'i'; break;	// human readable output format
			case 'n': sort_cnt = 'n'; break;	// sort by number of packets
			case 's': shorter = 's'; break;	// shorter = sum tcp + udp + other
			case 'g': gvalue = optarg; break;	// get grep argument
			case 'w': wvalue = optarg; break;	// set output file
			case '?':
				switch (optopt) {
					case 'w': fprintf(stderr, "Error: option -w requires a file to write.\n"); exit(1);
					case 'g': fprintf(stderr, "Error: option -g requires IP address(es) to grep.\n"); exit(1);
					default: fprintf(stderr, "Use -h to get instructions.\n"); exit(1);
				}
			default: help(1);
		}
	if ( argv[optind] == NULL ) {	// check if there are input files, at least one
		fprintf(stderr, "Error: at least one input file is required.\n");
		exit(1);
	}
	struct gpattern grep;	// grep pattern
	if ( shorter == 's' && gvalue != NULL ) {
		fprintf(stderr, "Error: -s does not work with -g.\n");
		exit(1);
	}
	if ( gvalue != NULL ) grep = getgrep(gvalue);	// option -g = grep
	else grep.type = shorter;
	FILE *wfd = stdout;	// destination file pointer
	if ( wvalue != NULL ) {	// option -w
		if ( access(wvalue, F_OK) != -1 ) {	// check for existing file
			fprintf(stderr, "Error: output file %s exists.\n", wvalue);
			exit(1);
		}
		wfd = fopen(wvalue, "w");	// open output file
		if ( wfd == NULL ) {
			fprintf(stderr, "Error: could not open output file %s.\n", argv[2]);
			exit(1);
		}
	}
	struct sarray stats;	// all calculated data goes in stats
	stats.blk =  100;
	stats.cnt = 0;
	stats.size = stats.blk;
	stats.array = malloc(sizeof(struct statset)*stats.blk);	// allocate ram for the arrays to store data
	if ( stats.array == NULL ) memerror();	// just in case...
	struct pcapheader pcap;	// head infos from pcap file(s)
	FILE *fd = NULL;	// pcap file pointer
	uint8_t filetype[8];	// to get file type / magic number
	struct packetdata packet;	// packet from pcap file
	int readerror;	// to get read error
	for (int i = optind; i < argc; i++) {	// go throught the input pcap files
		fd = fopen(argv[i], "rb");	// open input pcap file
		if ( fd == NULL ) {
			fprintf(stderr, "Error: could not open file %s.\n", argv[i]);
			exit(1);
		}
		pcap = readpcapheader(fd);	// read pcap file header
		switch (pcap.error) {
			case 1 : fprintf(stderr, "Error: could not read file header: %s.\n", argv[i]); exit(1);
			case 2 : fprintf(stderr, "Error: wrong file type: %s.\n", argv[i]); exit(1);
			case 3 : fprintf(stderr, "Error: wrong link-layer: %s\n", argv[i]); exit(1);
		}
		do {	// loop through packets (endless until skipping by return)
			packet = readpacket(fd, pcap);	// read one packet from pcap file
			if ( packet.error > 0 ) break;	// end of file might be reached
			if ( packet.error == 1 ) {
				fprintf(stderr, "Error while reading from file %s.\n", argv[i]);
				exit(1);
			}
			if ( packet.ipv == 0 ) continue;	// do not count and go to next packet - no ip packet
			switch (grep.type) {	// calculation depends on grep method (or none)
				case 't':
					if ( ( eqaddr(packet.src_addr, grep.ip1) == 1 )	// src or dst address is target?
						|| ( eqaddr(packet.dst_addr, grep.ip1) == 1 )	
					) searchset(&stats, packet, 't');
					break;
				case 'l':
					if ( ( eqaddr(packet.src_addr, grep.ip1) == 1
							&& eqaddr(packet.dst_addr, grep.ip2) == 1 )	// if src is target1 and dst is target2
						|| ( eqaddr(packet.src_addr, grep.ip2) == 1
							&& eqaddr(packet.dst_addr, grep.ip1) == 1 )	// or src ist target2 and dst is target1
					) searchset(&stats, packet, 'l');
					break;
				default: searchset(&stats, packet, 'b');
			}
		} while ( packet.error == 0 );	// until end of pcap file
		fclose(fd);	// close pcap file
	}
	if ( col_head_line == 'c' ) {	// option -c
		fprinthead(wfd, grep.type);
	}
	if ( stats.cnt > 0 ) {	// without ip traffic nothing is to generate
		struct single *addresses;
		uint64_t addr_cnt;
		int addr_blk = 100;
		addresses = malloc(sizeof(struct single)*addr_blk);	// allocate ram for the arrays to store data
		for (uint64_t i=0; i<stats.cnt; i++) {
			for (uint64_t j=0; j<addr_cnt; j++) {

		}

		uint64_t swapped;	// sort data sets
		struct statset tmp;
		if ( sort_cnt == 'n' ) {
			if ( sort_invert == 'i' ) {
				do {	// bubblesort cnt little to big
					swapped = 0;
					for (uint64_t i=1; i<stats.cnt; i++) {
						if ( stats.array[i-1].cnt > stats.array[i].cnt ) {
							tmp = stats.array[i-1];
							stats.array[i-1] = stats.array[i];
							stats.array[i] = tmp;
							swapped++;
						}
					}
				} while ( swapped > 0 );
			
			} else {
				do {	// bubblesort cnt big to little
					swapped = 0;
					for (uint64_t i=1; i<stats.cnt; i++) {
						if ( stats.array[i-1].cnt < stats.array[i].cnt ) {
							tmp = stats.array[i-1];
							stats.array[i-1] = stats.array[i];
							stats.array[i] = tmp;
							swapped++;
						}
					}
				} while ( swapped > 0 );
			}
		} else {
			if ( sort_invert == 'i' ) {
				do {	// bubblesort sum little to big
					swapped = 0;
					for (uint64_t i=1; i<stats.cnt; i++) {
						if ( stats.array[i-1].sum > stats.array[i].sum ) {
							tmp = stats.array[i-1];
							stats.array[i-1] = stats.array[i];
							stats.array[i] = tmp;
							swapped++;
						}
					}
				} while ( swapped > 0 );
			
			} else {
				do {	// bubblesort sum big to little
					swapped = 0;
					for (uint64_t i=1; i<stats.cnt; i++) {
						if ( stats.array[i-1].sum < stats.array[i].sum ) {
							tmp = stats.array[i-1];
							stats.array[i-1] = stats.array[i];
							stats.array[i] = tmp;
							swapped++;
						}
					}
				} while ( swapped > 0 );
			}
		}
		if ( grep.type == 's' ) for (uint64_t i=0; i<addr_cnt; i++)
			fprintsingle(wfd, addresses[i], readable_format);
		else for (uint64_t i=0; i<stats.cnt; i++) fprintset(wfd, stats.array[i], grep.type, readable_format);
	}
	free(stats.array);	// might be redundant before exit
	if ( wfd != NULL ) fclose(wfd);	// close output file on -w
	exit(0);
}
