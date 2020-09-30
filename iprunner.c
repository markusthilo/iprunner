/* IPRUNNER v0.1-20200930 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <time.h>

/* Structure for IP address */
struct ipaddr {
	uint64_t addr[2];
};

/* Structure for header of one packet */
struct packetheader {
	uint64_t ts;
	uint32_t incl_len, orig_len;
	int error;
};

/* Structure for the infos of one packet */
struct packetdata {
	struct ipaddr src_addr, dst_addr;
	uint8_t protocol;
	uint16_t type;
	uint64_t src_port, dst_port;
	int error;
};

/* Structure for grep pattern */
struct gpattern {
	struct ipaddr ip1, ip2;
	char type;
};

/* Structure for one statistical data set */
struct statset {
	struct ipaddr src_addr, dst_addr;
	uint16_t src_port, dst_port;
	uint64_t first_seen, last_seen,
		cnt_tcp, cnt_udp, cnt_other, cnt_all,
		sum_tcp, sum_udp, sum_other, sum_all;
};

/* Print help */
void help(int r){
	printf("\nIPPRUNNER v0.1-20200930\n\n");
	printf("Written by Markus Thilo\n");
	printf("GPL-3\n");
	printf("Runs through PCAP files and statistically analyzes IP packets. Other packets are ignored.\n");
	printf("Adresses, ports (on -g), oldest timestamp, youngest timestamp (first seen / last seen), the quantity\n");
	printf("of packets and the sum of the packet volumes (as given in PCAP files as orig_len) are listed.\n\n");
	printf("IPRUNNER uses only the C standard library, no LIBPCAP is needed.\n\n");
	printf("Usage:\n\n");
	printf("iprunner [--help] [-h] [-r] [-s] [-l] [-b] [-p] [-v]\n");
	printf("\t\t[-a DELIMITER ] [-d DELIMITER] [-w PCNF-FILE] [-j JSON-FILE] INFILE1 [INFILE2 ...]\n");
	printf("\nInput file format ist PCAP or PCNF. It is incompatible to PCAPNG.\n");
	printf("\nOptions:\n\n");
	printf("--help, -h\tPrint this help.\n");
	printf("-r\t\tPrint timestamps, number of packets and traffic volumes in human readable format.\n");
	printf("\t\tThe time stamps are taken from the PCAP files without any validation or adjustment.\n");
	printf("-s\t\tPrint statistics about single addresses (default if not -w or -j).\n");
	printf("\t\tThe list starts with the address of largest traffic volume. In most scenarios this should be\n");
	printf("\t\tthe observed address.\n");
	printf("-l\t\tPrint statistics about links (traffica from source to destination address).\n");
	printf("-b\t\tPrint statistics about bidirectional links (traffic inbetween addresses, both directions).\n");
	printf("-p\t\tPrint statistics about ports per address (one address, one port).\n");
	printf("-v\t\tVerbose print netflow data. This will give the traffic inbetween same addresses and ports\n");
	printf("\t\t(logical \"and\" = \"&&\" - this is the most differentiated statistic).\n");
	printf("-c\t\tPrint a head line with the meaning of the columns as first line before the data sets.\n");
	printf("\t\tADDR, SRC_ADDR, DST_ADDR - IP address (source / destination)\n");
	printf("\t\tPORT, SRC_PORT, DST_PORT - port number on TCP or UDP\n");
	printf("\t\tFIRST_TS, LAST_TS - time stamps (first seen, last seen)\n");
	printf("\t\tTCP_PACKETS, TCP_IN_PACKETS, TCP_OUT_PACKETS - number of TCP packets (incomming / outgoing)\n");
	printf("\t\tUDP_PACKETS, UDP_IN_PACKETS, UDP_OUT_PACKETS - number of UDP packets\n");
	printf("\t\tOTHER_PACKETS, OTHER_IN_PACKETS, OTHER_OUT_PACKETS - other IP protocols\n");
	printf("\t\tALL_PACKETS, ALL_IN_PACKETS, ALL_OUT_PACKETS - all IP packets (TCP+UDP+OTHER)\n");
	printf("\t\tTCP_VOLUME, UDP_VOLUME... - same as PACKETS but the summed data volume (orig_len)\n");
	printf("-a DELIMITER\tSets the delimiter character inbetween IP address and port number. Default is ':'.\n");
	printf("-d DELIMITER\tSets the delimiter character inbetween other data. Default is tab stop.\n");
	printf("-w PCNF-FILE\tWrite output to file. The file format is PCNF. You should name it 'FILENAME.pcnf'.\n");
	printf("\t\tPCNF is the native binary file format. It is effective for large PCAP files to do this first.\n");
	printf("-j JSON-FILE\tWrite output to file. The file format is JSON. You should name it 'FILENAME.json'.\n");
	printf("\nOnly one statistic / output at a time.\n");
	printf("Example: pcaprunner -w neflow.pcnf dump1.pcap dump2.pcap\n\n");
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
	if (( ip.addr[0] == 0 ) && ( ip.addr[1] & 0xffffffff00000000 == 0xffff00000000 )) return 4;
	return 6;
}

/* Check if 2 IP adresses are equal */
int eqaddr(struct ipaddr ip1, struct ipaddr ip2) {
	if ( ( ip1.addr[0] == ip2.addr[0] ) && ( ip1.addr[1] == ip2.addr[1] ) ) return 1;
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

/* Print address to string*/
char *sprintaddr(char *dst_str, struct ipaddr ip) {
	if ( ipversion(ip) == 4 )	/* ip v4 */
		sprintf(dst_str, "%lu.%lu.%lu.%lu",
			( ip.addr[1] >> 24 ) & 0xff,
			( ip.addr[1] >> 16 ) & 0xff,
			( ip.addr[1] >> 8 ) & 0xff,
			ip.addr[1] & 0xff
		);
	else {	/* ip v6 */
		sprintf(dst_str, "[%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx]",
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
	return dst_str;
}

/* Print timestamp to string regardless timezone - just as it is stored in the PCAP file */
char *sprintts(char *dst_str, uint64_t ts, char format) {
	if ( format == 'r' ) {	// print in human readable format, might be GMT
		struct tm *ts_info;
		time_t ts_sec;
		ts_sec = (time_t)(ts >> 32);
		strftime(dst_str, 20, "%Y-%m-%d %X", localtime(&ts_sec));
	} else sprintf(dst_str, "%lu", ts >> 32);	// seconds since 1970
	char ms[8];
	sprintf(ms, ".%06lu", ts & 0xffffffff);	// add microseconds
	strcat(dst_str, ms);
	return dst_str;
}

/* Print traffic counter to string */
char *sprintcnt(char *dst_str, uint64_t cnt, char format) {
	if ( format == 'r' ) {	// print in human readable format
		dst_str = "";
		const uint64_t pt[6] = {
			1000000000000000000,
			1000000000000000,
			1000000000000,
			1000000000,
			1000000,
			1000};
		uint64_t tmp_int;
		char tmp_str[16];
		int zeros = 0;
		for (int i=0; i<6; i++) {
			tmp_int = cnt / pt[i];
			if ( tmp_int > 0 ) {
				if (zeros == 1) sprintf(tmp_str, "%03u ", (unsigned int) tmp_int);
				else sprintf(tmp_str, "%u ", (unsigned int) tmp_int);
				strcat(dst_str, tmp_str);
				cnt = cnt % pt[i];
				zeros = 1;
			}
		}
		if (zeros == 1) sprintf(tmp_str, "%03lu", cnt);
				else sprintf(tmp_str, "%lu", cnt);
		strcat(dst_str, tmp_str);
	} else sprintf(dst_str, "%lu", cnt);
	return dst_str;
}

/* Print traffic volume in Bytes or GB/MB/KB to string */
char *sprintsum(char *dst_str, uint64_t sum, char format) {
	if ( format == 'r' ) {	// print in human readable format
		uint64_t tmp = sum / 1000000000000000;
		if ( tmp > 9 ) {
			sprintf(dst_str, "%lu PB", tmp);
			return dst_str;
		}
		tmp = sum / 1000000000000;
		if ( tmp > 9 ) {
			sprintf(dst_str, "%lu TB", tmp);
			return dst_str;
		}
		tmp = sum / 1000000000;
		if ( tmp > 9 ) {
			sprintf(dst_str, "%lu GB", tmp);
			return dst_str;
		}
		tmp = sum / 1000000;
		if ( tmp > 9 ) {
			sprintf(dst_str, "%lu MB", tmp);
			return dst_str;
		}
		tmp = sum / 1000;
		if ( tmp > 9 ) {
			sprintf(dst_str, "%lu kB", tmp);
			return dst_str;
		}
	}
	sprintf(dst_str, "%lu B", sum);
	return dst_str;
}

/* Append \t + address to string */
char *appendaddr(char *dst_str, struct ipaddr addr) {
	char addr_str[24];
	sprintaddr(addr_str, addr); 
	strcat(dst_str, "\t");
	strcat(dst_str, addr_str);
	return dst_str;
}

/* Append port number to string */
char *appendport(char *dst_str, uint16_t port, char set_type) {
	if ( set_type != 'b' ) { 
		char port_str[8];
		sprintf(port_str, ":%d", port);
		strcat(dst_str, port_str);
	}
	return dst_str;
}

/* Append time stamp to string */
char *appendts(char *dst_str, uint64_t ts, char format) {
	char ts_str[24];
	sprintts(ts_str, ts, format); 
	strcat(dst_str, "\t");
	strcat(dst_str, ts_str);
	return dst_str;
}

/* Append \t + counter to string */
char *appendcnt(char *dst_str, uint64_t cnt, char format) {
	char cnt_str[32];
	sprintcnt(cnt_str, cnt, format);
	strcat(dst_str, "\t");
	strcat(dst_str, cnt_str);
	return dst_str;
}

/* Append \t + traffic volume to string */
char *appendsum(char *dst_str, uint64_t sum, char format) {
	char sum_str[32];
	sprintsum(dst_str, sum, format);
	strcat(dst_str, "\t");
	strcat(dst_str, sum_str);
	return dst_str;
}

/* Print head line to string */
char *sprintbasichead(char *dst_str, char set_type) {
	if ( set_type == 'b' ) {	// basic set
		dst_str = "SRC_ADDR\tDST_ADDR\tFIRST_TS\tLAST_TS\tTCP_PACKETS\tUDP_PACKETS\tOTHER_PACKET\tALL_PACKETS\tTCP_VOLUME\tUDP_VOLUME\tOTHER_VOLUME\tALL_VOLUME\n";
	} else {	// target set
		dst_str = "SRC_ADDR\tSRC_PORT\tDST_ADDR\tDST_PORT\tFIRST_TS\tLAST_TS\tTCP_PACKETS\tUDP_PACKETS\tOTHER_PACKET\tALL_PACKETS\tTCP_VOLUME\tUDP_VOLUME\tOTHER_VOLUM\tALL_VOLUME\n";
	}
	return dst_str;
}

/* Print one data set to string as one line*/
char *sprintset(char *dst_str, struct statset set, char set_type, char format) {
	sprintaddr(dst_str, set.src_addr);
	appendport(dst_str, set.src_port, set_type);
	appendaddr(dst_str, set.dst_addr);
	appendport(dst_str, set.dst_port, set_type);
	appendts(dst_str, set.first_seen, format);
	appendts(dst_str, set.last_seen, format);
	appendcnt(dst_str, set.cnt_tcp, format);
	appendcnt(dst_str, set.cnt_udp, format);
	appendcnt(dst_str, set.cnt_other, format);
	appendcnt(dst_str, set.cnt_all, format);
	appendcnt(dst_str, set.sum_tcp, format);
	appendcnt(dst_str, set.sum_udp, format);
	appendcnt(dst_str, set.sum_other, format);
	appendcnt(dst_str, set.sum_all, format);
	strcat(dst_str, "\n");
	return dst_str;
}

/* Read packet header */
struct packetheader readpacketheader(FILE *fd, uint32_t magic_number) {
	struct packetheader header;
	uint8_t b[16];
	header.error = 1;
	if (fread(&b,16,1,fd) != 1) return header;	// read packet header from pcap file
	if ( magic_number == 0xa1b2c3d4 ) {	// normal byte order
		header.ts = readuint64(b, 0);
		header.incl_len = readuint32(b, 8);
		header.orig_len = readuint32(b, 4);
	} else {	// swapped byte order
		header.ts = ( (uint64_t) readuint32swapped(b, 0) << 32 )
			| ( (uint64_t) readuint32swapped(b, 4) & 0xffffffff );
		header.incl_len = readuint32swapped(b, 8);
		header.orig_len = readuint32swapped(b, 12);
	}
	header.error = 0;	// no errors
	return header;
}

/* Read packet */
struct packetdata readpacketdata(FILE *fd, uint32_t incl_len) {
	struct packetdata packet;
	uint8_t header[40];
	uint32_t ihl, left;
	packet.error = 1;	//	1 means something went wrong
	if (fread(&header,14,1,fd) != 1) return packet;	// read ethernet layer
	packet.type = readuint16(header, 12);	// get type
	if ( packet.type == 0x800 ) {	// ipv4
		if (fread(&header,20,1,fd) != 1) return packet;	// read ipv4 header
		ihl = ( (uint32_t) header[0] & 0xf ) << 2;	// calculate ihl (read 4 bits * 4)
		packet.protocol = header[9];	// read protocol
		packet.src_addr = readipv4(header, 12);	// read source address
		packet.dst_addr = readipv4(header, 16);	// read destination address
		if ( (ihl > 20) && (fseek(fd,ihl-20,SEEK_CUR) != 0) ) return packet;	// go to ipv4 payload
		left = incl_len - 14 - ihl;	// calculate left octets in packet
	} else if ( packet.type == 0x86dd ) {	// ipv6
		if (fread(&header,40,1,fd) != 1) return packet;	// read ipv6 header
		packet.protocol == header[6];	// read protocol = next header
		packet.src_addr = readipv6(header, 8);	// read source address
		packet.dst_addr = readipv6(header, 24);	// read destination address
		left = incl_len - 54;	// calculate left octets in packet
	} else {	// not ip protocol -> is not counted, just set file pointer to next packet
		packet.protocol = 0xff;	// here 0xff means no ip packet
		if ( fseek(fd,incl_len-14,SEEK_CUR) != 0 ) return packet;	// go to next packet header
		packet.error = -1;	// -1 means this packet will not be in the statistics beacause not ip
		return packet;	// and return
	}
	if ( ( packet.protocol == 6 ) || ( packet.protocol == 17 ) ) {	// TCP or UDP
		if (fread(&header,4,1,fd) != 1) return packet;	// read port numbers from tcp or udp header
		packet.src_port = (uint64_t) readuint16(header, 0);	// read source port
		packet.dst_port = (uint64_t) readuint16(header, 2);	// read destination port
		left -= 4;	// decrease left octets by 4 = source and destination ports
	} else {	// some other protocol
		packet.src_port = 0x10000;	// no ports = set ports out of 16 bit range
		packet.dst_port = 0x10000;
	}
	if ( fseek(fd,left,SEEK_CUR) != 0 ) {	// go to next packet header
		packet.error = -2;	// -2 means this packet will be in the statistic but skip the actual pcap file
		return packet;
	}
	packet.error = 0;	// no read error
	return packet;	// all done in the packet
}

/* Create data set and append to array */
uint64_t appendset(struct statset *stats, uint64_t stats_cnt, struct packetheader header, struct packetdata packet) {
	stats[stats_cnt].src_addr = packet.src_addr;	// store the data from PCAP file in the dynamic array
	stats[stats_cnt].dst_addr = packet.dst_addr;
	stats[stats_cnt].src_port = packet.src_port;
	stats[stats_cnt].dst_port = packet.dst_port;
	stats[stats_cnt].first_seen = header.ts;
	stats[stats_cnt].last_seen = header.ts;
	if ( packet.protocol == 6 ) {	// TCP
		stats[stats_cnt].sum_tcp = header.orig_len;	// set traffic volume
		stats[stats_cnt].cnt_tcp = 1;	// set packet counter
		stats[stats_cnt].sum_udp = 0;
		stats[stats_cnt].cnt_udp = 0;
		stats[stats_cnt].sum_other = 0;
		stats[stats_cnt].cnt_other = 0;
	} else if ( packet.protocol == 17 ) {	// UDP
		stats[stats_cnt].sum_tcp = 0;
		stats[stats_cnt].cnt_tcp = 0;
		stats[stats_cnt].sum_udp = header.orig_len;	// set traffic volume
		stats[stats_cnt].cnt_udp = 1;	// set packet counter
		stats[stats_cnt].sum_other = 0;
		stats[stats_cnt].cnt_other = 0;
	} else {	// other IP packet
		stats[stats_cnt].sum_tcp = 0;
		stats[stats_cnt].cnt_tcp = 0;
		stats[stats_cnt].sum_udp = 0;
		stats[stats_cnt].cnt_udp = 0;
		stats[stats_cnt].sum_other = header.orig_len;	// set traffic volume
		stats[stats_cnt].cnt_other = 1;	// set packet counter
	}
	struct statset *stats_new = realloc(stats, ((++stats_cnt)+1)*sizeof(struct statset)); /* get more memory */
	if ( stats_new == NULL ) memerror();
	stats = stats_new;	// update pointer to the enlarged array
	return stats_cnt+1;	// return updatet counter
}

/* Update timestamps, packet counters and volume */
struct statset updatetscntsum(struct statset set, struct packetheader header, struct packetdata packet) {
	if ( header.ts > set.last_seen ) set.last_seen = header.ts;	// update timestamps
	else if ( header.ts < set.first_seen ) set.first_seen = header.ts;
	if ( packet.protocol == 6 ) {	// TCP
		set.sum_tcp += header.orig_len;	// update sum of traffic volume
		set.cnt_tcp++;	// increase packet counter
	} else if ( packet.protocol == 17 ) {	// UDP
		set.sum_udp += header.orig_len;	// update sum of traffic volume
		set.cnt_udp++;	// increase packet counter
	} else if ( packet.protocol == 0xff ) {	// other ip protocol
		set.sum_other += header.orig_len;	// update sum of traffic volume
		set.cnt_other++;	// increase packet counter
	}
	return set;
}

/* Update array with basic address to address statistics, port is ignored */
uint64_t updatebasic(struct statset *stats, uint64_t stats_cnt, struct packetheader header, struct packetdata packet) {
	for (uint64_t i=0; i<stats_cnt; i++) {	// loop through the stored data
		if ( ( eqaddr(packet.src_addr, stats[i].src_addr) == 1 )	// if identical addresses
			&& ( eqaddr(packet.dst_addr, stats[i].dst_addr) == 1 ) ) {
			stats[i] = updatetscntsum(stats[i], header, packet);
			return stats_cnt;
		}
	}
	return appendset(stats, stats_cnt, header, packet);
}

/* Update array, check address and port */
uint64_t updateaddrport(struct statset *stats, uint64_t stats_cnt, struct packetheader header, struct packetdata packet) {
	for (uint64_t i=0; i<stats_cnt; i++) {	// loop through the stored data
		if ( ( eqaddr(packet.src_addr, stats[i].src_addr) == 1 )	// if identical addresses
			&& ( eqaddr(packet.dst_addr, stats[i].dst_addr) == 1 )
			&& ( packet.src_port == stats[i].src_port )	// and identical ports
			&& ( packet.dst_port == stats[i].dst_port ) ) {
			stats[i] = updatetscntsum(stats[i], header, packet);
			return stats_cnt;
		}
	}
	return appendset(stats, stats_cnt, header, packet);
}

/* Update array for target address option */
uint64_t updatetarget(struct statset *stats, uint64_t stats_cnt, struct packetheader header, struct packetdata packet,
	struct ipaddr target) {
	if ( eqaddr(packet.src_addr, target) == 1 || eqaddr(packet.dst_addr, target) == 1 )	// if src or dst is target
			return updateaddrport(stats, stats_cnt, header, packet);
	return stats_cnt;
}

/* Update array for link address option */
uint64_t updatelink(struct statset *stats, uint64_t stats_cnt, struct packetheader header, struct packetdata packet,
	struct ipaddr target1, struct ipaddr target2) {
	if ( ( eqaddr(packet.src_addr, target1) == 1 && eqaddr(packet.dst_addr, target2) == 1 )	// if src is target1 and dst is target2
		|| ( eqaddr(packet.src_addr, target2) == 1 && eqaddr(packet.dst_addr, target1) == 1 ) )	// or src ist target2 and dst is target1
			return updateaddrport(stats, stats_cnt, header, packet);
	return stats_cnt;
}

/* Work on one PCAP file to get basic statistics */
uint64_t workbasicpcap(FILE *fd, uint32_t magic_number, struct statset *stats, uint64_t stats_cnt) {
	struct packetheader header;
	struct packetdata packet;
	if (fseek(fd,24,SEEK_SET) != 0) return stats_cnt;	// go to first packet header
	while (1) {	// loop through packets (endless until skipping by return)
		header = readpacketheader(fd, magic_number);	/* read packet header*/
		if ( header.error == 1 ) break;	// if not successful, end of file might be reached
		packet = readpacketdata(fd, header.incl_len);	// read packet content: ip and tcp/udp header
		if ( packet.error == 1 ) break;	// just skip in case there was a problem while reading the packet
		if ( packet.error == -1 ) continue;	// do not count and go to next packet - no ip packet
		stats_cnt = updatebasic(stats, stats_cnt, header, packet);
		if ( packet.error == -2 ) break;	// count this packet but this is all for the pcap file
	}
	return stats_cnt;
}

/* Work on one PCAP file to get statistics for target address */
uint64_t worktargetpcap(FILE *fd, uint32_t magic_number, struct statset *stats, uint64_t stats_cnt,
	struct ipaddr target) {
	struct packetheader header;
	struct packetdata packet;
	if (fseek(fd,24,SEEK_SET) != 0) return stats_cnt;	// go to first packet header
	while (1) {	// loop through packets (endless until skipping by return)
		header = readpacketheader(fd, magic_number);	/* read packet header*/
		if ( header.error == 1 ) break;	// if not successful, end of file might be reached
		packet = readpacketdata(fd, header.incl_len);	// read packet content: ip and tcp/udp header
		if ( packet.error == 1 ) break;	// just skip in case there was a problem while reading the packet
		if ( packet.error == -1 ) continue;	// do not count and go to next packet - no ip packet
		stats_cnt = updatetarget(stats, stats_cnt, header, packet, target);
		if ( packet.error == -2 ) break;	// count this packet but this is all for the pcap file
	}
	return stats_cnt;
}

/* Work on one PCAP file to get statistics for traffic inbetween 2 addresses */
uint64_t worklinkpcap(FILE *fd, uint32_t magic_number, struct statset *stats, uint64_t stats_cnt,
	struct ipaddr target1, struct ipaddr target2) {
	struct packetheader header;
	struct packetdata packet;
	if (fseek(fd,24,SEEK_SET) != 0) return stats_cnt;	// go to first packet header
	while (1) {	// loop through packets (endless until skipping by return)
		header = readpacketheader(fd, magic_number);	/* read packet header*/
		if ( header.error == 1 ) break;	// if not successful, end of file might be reached
		packet = readpacketdata(fd, header.incl_len);	// read packet content: ip and tcp/udp header
		if ( packet.error == 1 ) break;	// just skip in case there was a problem while reading the packet
		if ( packet.error == -1 ) continue;	// do not count and go to next packet - no ip packet
		stats_cnt = updatelink(stats, stats_cnt, header, packet, target1, target2);
		if ( packet.error == -2 ) break;	// count this packet but this is all for the pcap file
	}
	return stats_cnt;
}

/* Create cnt_all and sum_all, then sort sets by sum_all */
void sortstats(struct statset *stats, uint64_t stats_cnt) {
	struct statset tmp;
	uint64_t swapped;
	for (uint64_t i=0; i<stats_cnt; i++) {	// loop through sets to sum traffic
		stats[i].cnt_all = stats[i].cnt_tcp + stats[i].cnt_udp + stats[i].cnt_other;
		stats[i].sum_all = stats[i].sum_tcp + stats[i].sum_udp + stats[i].sum_other;
	}
	do {	// bubblesort
		swapped = 0;
		for (uint64_t i=1; i<stats_cnt; i++) {
			if ( stats[i-1].sum_all < stats[i].sum_all ) {
				tmp = stats[i-1];
				stats[i-1] = stats[i];
				stats[i] = tmp;
				swapped++;
			}
		}
	} while ( swapped > 0 );
}

/* Main function - program starts here*/
int main(int argc, char **argv) {
	if ( ( argc > 1 )	// show help
	&& ( ( ( argv[1][0] == '-' ) && ( argv[1][1] == '-' ) && ( argv[1][2] == 'h' ) )
	|| ( ( argv[1][0] == '-' ) && ( argv[1][1] == 'h' ) ) ) ) help(0);
	else if ( argc < 2 ) help(1);	// also show help if no argument is given but return with exit(1)
	char opt;	// command line options
	char readable_format = 'n', col_head_line = 'n';	// output options human readable and headlines for columns
	char *gvalue = NULL, *wvalue = NULL;	// pointer to command line arguments
	while ((opt = getopt(argc, argv, "rcg:w:")) != -1)	// command line arguments
		switch (opt) {
			case 'r': readable_format = 'r'; break;// human readable output format
			case 'c': col_head_line = 'c'; break;	// show meanings of columns in a head line
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
	struct gpattern grep;
	grep.type = 'n';
	if ( gvalue != NULL ) grep = getgrep(gvalue);	// option -g = grep
	printf("grep: ip1 = %016lx %016lx, ip2 =  %016lx %016lx, type = >%c<\n", grep.ip1.addr[0], grep.ip1.addr[1], grep.ip2.addr[0], grep.ip2.addr[1], grep.type);
	exit(0);
	FILE *wfd = NULL;
	if ( wvalue != NULL ) {	// option -w
		if ( access(wvalue, F_OK) != -1 ) {	// check for existing file
			fprintf(stderr, "Error: output file %s exists.\n", wvalue);
			exit(1);
		}
		wfd = fopen(argv[2], "wb");	// open output file
		if ( wfd == NULL ) {
			fprintf(stderr, "Error: could not open output file %s.\n", argv[2]);
			exit(1);
		}
	}
	struct statset *stats;
	stats = malloc(sizeof(struct statset));	// allocate ram for the arrays to store data
	if ( stats == NULL ) memerror();	// just in case...
	uint64_t stats_cnt = 0;
	uint32_t magic_number;
	FILE *fd = NULL;	// pcap file pointer
	uint8_t filetype[8];	// to get file type / magic number
	for (int i = optind; i < argc; i++) {	// go throught the input pcap files
		fd = fopen(argv[i], "rb");	// open input pcap file
		if ( fd == NULL ) {
			fprintf(stderr, "Error: could not open file %s.\n", argv[i]);
			exit(1);
		}
		if ( fread(&filetype,4,1,fd) != 1 ) {	// read magic number
			fprintf(stderr, "Error: could not read magic number / type of file from %s.\n", argv[i]);
			exit(1);
		}
		magic_number = readuint32(filetype, 0);	// work with pcap files
		if ( ( magic_number != 0xa1b2c3d4 ) && ( magic_number != 0xd4c3b2a1 ) ) {	// check for pcap file type
			fprintf(stderr, "Error: wrong file type: %s\n", argv[i]);
			exit(1);
		}
		switch (grep.type) {	// calculation depends on grep method (or none)
			case 't': stats_cnt = worktargetpcap(fd, magic_number, stats, stats_cnt, grep.ip1); break;
			case 'l': stats_cnt = worklinkpcap(fd, magic_number, stats, stats_cnt, grep.ip1, grep.ip2); break;
			default: stats_cnt = workbasicpcap(fd, magic_number, stats, stats_cnt);
		}
		fclose(fd);	// close pcap file
	}
	if ( stats_cnt > 0 ) {	// without ip traffic nothing is to generate
//		sortstats(stats, stats_cnt);
		if ( col_head_line == 'c' ) {
			printf("headline\n");
		}
		for (uint64_t i=0; i<stats_cnt; i++) {
			printf("%lu\n", i);
		}
	}
	if ( wfd != NULL ) fclose(wfd);	// close output file on -w
	exit(0);
}
