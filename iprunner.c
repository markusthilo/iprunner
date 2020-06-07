/* IPRUNNER v0.1 */

#include <stdlib.h>
#include <stdio.h>
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

/* Structure to store sets when no target is given */
struct set_no_t {
	struct ipaddr src_addr, dst_addr;
		cnt_in_tcp, cnt_in_udp, cnt_in_other, cnt_out_tcp, cnt_out_udp, cnt_out_other, cnt_all,
		sum_in_tcp, sum_in_udp, sum_in_other, sum_out_tcp, sum_out_udp, sum_out_other, sum_all;
};

/* Structure to store links */
struct linkset {
	struct ipaddr src_addr, dst_addr;
	uint64_t first_ts, last_ts, cnt_tcp, cnt_udp, cnt_other, cnt_all, sum_tcp, sum_udp, sum_other, sum_all;
};

/* Structure to store ports per address */
struct portset {
	struct ipaddr addr;
	uint16_t port;
	uint64_t first_ts, last_ts,
		cnt_in_tcp, cnt_in_udp, cnt_in_other, cnt_out_tcp, cnt_out_udp, cnt_out_other, cnt_all,
		sum_in_tcp, sum_in_udp, sum_in_other, sum_out_tcp, sum_out_udp, sum_out_other, sum_all;
};

/* Structure to store bidirectional links */
struct bilinkset {
	struct ipaddr upper_addr, lower_addr;
	uint64_t first_ts, last_ts, cnt_tcp, cnt_udp, cnt_other, cnt_all, sum_tcp, sum_udp, sum_other, sum_all;
};

/* Global variables and constants ...yes, I know, they are bad, but this is f...ing creepy code anyway */
struct rawset *raws_ptr;	// pointers to the dynamic arrays
struct singleset *singles_ptr;
struct linkset *links_ptr;
struct portset *ports_ptr;
struct bilinkset *bilinks_ptr;
uint64_t raws_cnt = 0, singles_cnt = 0, links_cnt = 0, ports_cnt = 0, bilinks_cnt = 0;	// counter
char addr_port_del = ':';	// default delimiter inbetween address and port number
char info_del = '\t';	// default delimiter inbetween infos
char ts_format = 's';	// default to human readable time stamps
char col_head_line = ' ';	// default is not to print information about the columns in a head line

/* Print help */
void help(int r){
	printf("\IPRUNNER v0.1\n\n");
	printf("Written by Markus Thilo\n");
	printf("January 2017 to June 2020, GPL-3\n");
	printf("Uses only the C standard libraries.\n");
	printf("Runs through PCAP files and statistically analyzes IP packets. Other packets are ignored.\n");
	printf("Adresses, ports, oldest timestamp, youngest timestamp (first seen / last seen), the quantity\n");
	printf("of packets and the sum of the packet volumes (as given in PCAP files as orig_len) are listed.\n\n");
	printf("PCAPRUNNER uses only the C standard library, no LIBPCAP is needed.\n\n");
	printf("Usage:\n\n");
	printf("pcaprunner [--help] [-h] [-r] [-s] [-l] [-b] [-p] [-v]\n");
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
	printf("Project page: https://github.com/markusthilo/netflower\n\n");
	exit(r);
}

/* Write error */
void writeerror() {
	fprintf(stderr, "Error while writing to file.\n");
	exit(1);
}

/* Error while reading PCNF file */
void readpcnferror() {
	fprintf(stderr, "Error while reading PCNF file.\n");
	exit(1);
}

/* Error while allocating memory */
void memerror() {
	fprintf(stderr, "Error while allocating memory.\n");
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
	struct ipaddr ip;
	ip.addr[0] = 0;
	ip.addr[1] = (uint64_t) ( readuint32(a, pos) & 0xffffffff ); // read 32 bits = 4 octets
	return ip;
}

/* Read IPv6 address from array */
struct ipaddr readipv6(uint8_t *a, int pos) {
	struct ipaddr ip;
	ip.addr[0] = readuint64(a, pos);	// read first 8 octets
	ip.addr[1] = readuint64(a, pos+8);	// read 2nd 8 octets
	return ip;
}

/* Check if 2 IP adresses are equal */
int eqaddr(struct ipaddr ip1, struct ipaddr ip2) {
	if ( ( ip1.addr[0] == ip2.addr[0] ) && ( ip1.addr[1] == ip2.addr[1] ) ) return 1;
	return 0;
}

/* Check if the first IP address is mathematically greater than thesecond IP addresse */
int gtaddr(struct ipaddr ip1, struct ipaddr ip2) {
	if ( ip1.addr[0] > ip2.addr[0] ) return 1;
	if ( ( ip1.addr[0] == ip2.addr[0] ) && ( ip1.addr[1] > ip2.addr[1] ) ) return 1;
	return 0;
}

/* Write 64 bits to file */
void fwriteuint64(uint64_t w, FILE *fd) {
	uint8_t b[8];
	b[0] = (uint8_t) ( w >> 56 );
	b[1] = (uint8_t) ( w >> 48 );
	b[2] = (uint8_t) ( w >> 40 );
	b[3] = (uint8_t) ( w >> 32 );
	b[4] = (uint8_t) ( w >> 24 );
	b[5] = (uint8_t) ( w >> 16 );
	b[6] = (uint8_t) ( w >> 8 );
	b[7] = (uint8_t) w;
	if (fwrite(b, 1, 8, fd) != 8) writeerror();
}

/* Write IP address to file */
void fwriteip(struct ipaddr ip, FILE *fd) {
	fwriteuint64(ip.addr[0], fd);
	fwriteuint64(ip.addr[1], fd);
}

/* Print address */
void printaddr(struct ipaddr ip, char d) {
	if ( ( ip.addr[0] == 0 ) && ( ( ip.addr[1] & 0xffffffff00000000 ) == 0 ) )	/* ip v4 */
		printf("%lu.%lu.%lu.%lu%c",
			( ip.addr[1] >> 24 ) & 0xff,
			( ip.addr[1] >> 16 ) & 0xff,
			( ip.addr[1] >> 8 ) & 0xff,
			ip.addr[1] & 0xff,
			d
		);
	else {	/* ip v6 */
		printf("[%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx]%c",
			( ip.addr[0] >> 48 ) & 0xffff,
			( ip.addr[0] >> 32 ) & 0xffff,
			( ip.addr[0] >> 16 ) & 0xffff,
			ip.addr[0] & 0xffff,
			( ip.addr[1] >> 48 ) & 0xffff,
			( ip.addr[1] >> 32 ) & 0xffff,
			( ip.addr[1] >> 16 ) & 0xffff,
			ip.addr[1] & 0xffff,
			d
		);
	}
}

/* Print port number*/
void printportnum (uint64_t p) {
	if ( p < 0x10000 ) printf("%lu%c", p, info_del);
	else printf("-%c", info_del);
}

/* Print timestamp regardless timezone - just as it is stored in the PCAP file */
void printts(uint64_t ts) {
	if ( ts_format == 'r' ) {	// print in human readable format, might be GMT
		struct tm *ts_info;
		time_t ts_sec;
		char ts_string[20];
		ts_sec = (time_t)(ts >> 32);
		ts_info = localtime(&ts_sec);
		strftime(ts_string, 20, "%Y-%m-%d_%X", ts_info);
		printf("%s", ts_string);
	} else printf("%lu", ts >> 32);	// print in unix format/seconds
	printf(".%06lu%c", ts & 0xffffffff, info_del);	// print microseconds
}

/* Print traffic counter */
void printcnt(uint64_t cnt, char d) {
	const uint64_t pt[6] = {
		1000000000000000000,
		1000000000000000,
		1000000000000,
		1000000000,
		1000000,
		1000};
	if ( ts_format == 'r' ) {	// print in human readable format
		uint64_t tmp;
		int zeros = 0;
		for (int i=0; i<6; i++) {
			tmp = cnt / pt[i];
			if ( tmp > 0 ) {
				if (zeros == 1) printf("%03lu,", tmp);
				else printf("%lu,", tmp);
				cnt = cnt % pt[i];
				zeros = 1;
			}
		}
		if (zeros == 1) printf("%03lu%c", cnt, d);
				else printf("%lu%c", cnt, d);
	} else printf("%lu%c", cnt, d);
}

/* Print traffic volume in Bytes or GB/MB/KB */
void printsum(uint64_t sum, char d) {
	if ( ts_format == 'r' ) {	// print in human readable format
		uint64_t tmp = sum / 1000000000000;
		if ( tmp > 9 ) {
			printf("%luT%c", tmp, d);
			return;
		}
		tmp = sum / 1000000000;
		if ( tmp > 9 ) {
			printf("%luG%c", tmp, d);
			return;
		}
		tmp = sum / 1000000;
		if ( tmp > 9 ) {
			printf("%luM%c", tmp, d);
			return;
		}
		tmp = sum / 1000;
		if ( tmp > 9 ) {
			printf("%luK%c", tmp, d);
			return;
		}
	}
	printf("%lu%c", sum, d);
}

/* Write address to JSON file */
void jprintaddr(FILE *fd, struct ipaddr ip) {
	if ( ( ip.addr[0] == 0 ) && ( ( ip.addr[1] & 0xffffffff00000000 ) == 0 ) )	/* ip v4 */
		fprintf(fd, "\"%lu.%lu.%lu.%lu\"",
			( ip.addr[1] >> 24 ) & 0xff,
			( ip.addr[1] >> 16 ) & 0xff,
			( ip.addr[1] >> 8 ) & 0xff,
			ip.addr[1] & 0xff);
	else {	/* ip v6 */
		fprintf(fd, "\"%lx:%lx:%lx:%lx:%lx:%lx:%lx:%lx\"",
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

/* Write timestamp to JSON file */
void jprintts(FILE *fd, uint64_t ts) {
	fprintf(fd, "%lu.%06lu", ts >> 32, ts & 0xffffffff);	// print unix format plus microseconds to json
}

/* Print head line for raw data */
void printheadraws() {
	if ( col_head_line != 'c' ) return;
	printf("SRC_ADDR%cSRC_PORT%cDST_ADDR%cDST_PORT", addr_port_del, info_del, addr_port_del);
	printf("%cFIRST_TS%cLAST_TS", info_del, info_del);
	printf("%cTCP_PACKETS%cUDP_PACKETS%cOTHER_PACKETS%cALL_PACKETS", info_del, info_del, info_del, info_del);
	printf("%cTCP_VOLUME%cUDP_VOLUME%cOTHER_VOLUME%cALL_VOLUME\n", info_del, info_del, info_del, info_del);
}

/* Print one raw data set in one line to stdout */
void printraw(struct rawset set) {
	printaddr(set.src_addr, addr_port_del);
	printportnum(set.src_port);
	printaddr(set.dst_addr, addr_port_del);
	printportnum(set.dst_port);
	printts(set.first_ts);
	printts(set.last_ts);
	printcnt(set.cnt_tcp, info_del);
	printcnt(set.cnt_udp, info_del);
	printcnt(set.cnt_other, info_del);
	printcnt(set.cnt_all, info_del);
	printsum(set.sum_tcp, info_del);
	printsum(set.sum_udp, info_del);
	printsum(set.sum_other, info_del);
	printsum(set.sum_all, '\n');
}

/* Write raw set to JSON file */
void jfprintraw(FILE *fd, struct rawset set) {
	fprintf(fd, "{\"SRC_ADDR\":"); jprintaddr(fd, set.src_addr);
	fprintf(fd, ",\"DST_ADDR\":"); jprintaddr(fd, set.dst_addr);
	fprintf(fd, ",\"SRC_PORT\":%lu,\"DST_PORT\":%lu", set.src_port, set.dst_port);
	fprintf(fd, ",\"FIRST_TS\":"); jprintts(fd, set.first_ts);
	fprintf(fd, ",\"LAST_TS\":"); jprintts(fd, set.last_ts);
	fprintf(fd, ",\"TCP_PACKETS\":%lu,\"UDP_PACKETS\":%lu,\"OTHER_PACKETS\":%lu,\"ALL_PACKETS\":%lu",
		set.cnt_tcp, set.cnt_udp, set.cnt_other, set.cnt_all);
	fprintf(fd, ",\"TCP_VOLUME\":%lu,\"UDP_VOLUME\":%lu,\"OTHER_VOLUME\":%lu,\"ALL_VOLUME\":%lu}",
		set.sum_tcp, set.sum_udp, set.sum_other, set.sum_all);
}

/* Print raw data */
void printraws() {
	printheadraws();
	for (uint64_t i=0; i < raws_cnt; i++) printraw(raws_ptr[i]);	// loop through the array in the allocated memory
}

/* Write raw data sets from dynamic array to file */
void fwriteraws(FILE *fd) {
	for (uint64_t i=0; i<raws_cnt; i++) {
		fwriteip(raws_ptr[i].src_addr, fd);
		fwriteip(raws_ptr[i].dst_addr, fd);
		fwriteuint64(raws_ptr[i].src_port, fd);
		fwriteuint64(raws_ptr[i].dst_port, fd);
		fwriteuint64(raws_ptr[i].first_ts, fd);
		fwriteuint64(raws_ptr[i].last_ts, fd);
		fwriteuint64(raws_ptr[i].cnt_tcp, fd);
		fwriteuint64(raws_ptr[i].cnt_udp, fd);
		fwriteuint64(raws_ptr[i].cnt_other, fd);
		fwriteuint64(raws_ptr[i].cnt_all, fd);
		fwriteuint64(raws_ptr[i].sum_tcp, fd);
		fwriteuint64(raws_ptr[i].sum_udp, fd);
		fwriteuint64(raws_ptr[i].sum_other, fd);
		fwriteuint64(raws_ptr[i].sum_all, fd);
	}
}

/* Print raw data sets from PCNF file */
void fprintraws(FILE *fd, FILE *jfd) {
	struct rawset set;
	uint8_t b[size_rawset];
	if ( fseek(fd,size_header,SEEK_SET) != 0 ) readpcnferror();	// skip to data sets
	printheadraws();
	for (uint64_t i=0; i< raws_cnt; i++) {
		if (fread(&b,1,size_rawset,fd) != size_rawset) readpcnferror();	// read data set from file
		set.src_addr = readipv6(b, 0);	// decode read raw data into data set
		set.dst_addr = readipv6(b, 16);
		set.src_port = readuint64(b, 32);
		set.dst_port = readuint64(b, 40);
		set.first_ts = readuint64(b, 48);
		set.last_ts = readuint64(b, 56);
		set.cnt_tcp = readuint64(b, 64);
		set.cnt_udp = readuint64(b, 72);
		set.cnt_other = readuint64(b, 80);
		set.cnt_all = readuint64(b, 88);
		set.sum_tcp = readuint64(b, 96);
		set.sum_udp = readuint64(b, 104);
		set.sum_other = readuint64(b, 112);
		set.sum_all = readuint64(b, 120);
		if ( jfd == NULL ) printraw(set);	// print data set
		else {
			if ( i > 0 ) fprintf(jfd, ",");
			jfprintraw(jfd, set);
		}
	}
}

/* Print head line for singles */
void printheadsingles() {
	if ( col_head_line != 'c' ) return;
	printf("ADDR%cFIRST_TS%cLAST_TS", info_del, info_del);
	printf("%cTCP_IN_PACKETS%cUDP_IN_PACKETS%cOTHER_IN_PACKETS", info_del, info_del, info_del);
	printf("%cTCP_OUT_PACKETS%cUDP_OUT_PACKETS%cOTHER_OUT_PACKETS%cALL_PACKETS", info_del, info_del, info_del, info_del);
	printf("%cTCP_IN_VOLUME%cUDP_IN_VOLUME%cOTHER_IN_VOLUME", info_del, info_del, info_del);
	printf("%cTCP_OUT_VOLUME%cUDP_OUT_VOLUME%cOTHER_OUT_VOLUME%cALL_VOLUME\n", info_del, info_del, info_del, info_del);
}

/* Print one single set to stdout */
void printsingle(struct singleset set) {
	printaddr(set.addr, info_del);
	printts(set.first_ts);
	printts(set.last_ts);
	printcnt(set.cnt_in_tcp, info_del);
	printcnt(set.cnt_in_udp, info_del);
	printcnt(set.cnt_in_other, info_del);
	printcnt(set.cnt_out_tcp, info_del);
	printcnt(set.cnt_out_udp, info_del);
	printcnt(set.cnt_out_other, info_del);
	printcnt(set.cnt_all, info_del);
	printsum(set.sum_in_tcp, info_del);
	printsum(set.sum_in_udp, info_del);
	printsum(set.sum_in_other, info_del);
	printsum(set.sum_out_tcp, info_del);
	printsum(set.sum_out_udp, info_del);
	printsum(set.sum_out_other, info_del);
	printsum(set.sum_all, '\n');
}

/* Write single set to JSON file */
void jfprintsingle(FILE *fd, struct singleset set) {
	fprintf(fd, "{\"ADDR\":"); jprintaddr(fd, set.addr);
	fprintf(fd, ",\"FIRST_TS\":"); jprintts(fd, set.first_ts);
	fprintf(fd, ",\"LAST_TS\":"); jprintts(fd, set.last_ts);
	fprintf(fd, ",\"TCP_IN_PACKETS\":%lu,\"UDP_IN_PACKETS\":%lu,\"OTHER_IN_PACKETS\":%lu",
		set.cnt_in_tcp, set.cnt_in_udp, set.cnt_in_other);
	fprintf(fd, ",\"TCP_OUT_PACKETS\":%lu,\"UDP_OUT_PACKETS\":%lu,\"OTHER_OUT_PACKETS\":%lu,\"ALL_PACKETS\":%lu",
		set.cnt_out_tcp, set.cnt_out_udp, set.cnt_out_other, set.cnt_all);
	fprintf(fd, ",\"TCP_IN_VOLUME\":%lu,\"UDP_IN_VOLUME\":%lu,\"OTHER_IN_VOLUME\":%lu",
		set.sum_in_tcp, set.sum_in_udp, set.sum_in_other);
	fprintf(fd, ",\"TCP_OUT_VOLUME\":%lu,\"UDP_OUT_VOLUME\":%lu,\"OTHER_OUT_VOLUME\":%lu,\"ALL_VOLUME\":%lu}",
		set.sum_out_tcp, set.sum_out_udp, set.sum_out_other, set.sum_all);
}

/* Print singles */
void printsingles() {
	printheadsingles();
	for (unsigned long i=0; i < singles_cnt; i++) printsingle(singles_ptr[i]);
}

/* Write single sets from dynamic array to file */
void fwritesingles(FILE *fd) {
	for (uint64_t i=0; i<singles_cnt; i++) {
		fwriteip(singles_ptr[i].addr, fd);
		fwriteuint64(singles_ptr[i].first_ts, fd);
		fwriteuint64(singles_ptr[i].last_ts, fd);
		fwriteuint64(singles_ptr[i].cnt_in_tcp, fd);
		fwriteuint64(singles_ptr[i].cnt_in_udp, fd);
		fwriteuint64(singles_ptr[i].cnt_in_other, fd);
		fwriteuint64(singles_ptr[i].cnt_out_tcp, fd);
		fwriteuint64(singles_ptr[i].cnt_out_udp, fd);
		fwriteuint64(singles_ptr[i].cnt_out_other, fd);
		fwriteuint64(singles_ptr[i].cnt_all, fd);
		fwriteuint64(singles_ptr[i].sum_in_tcp, fd);
		fwriteuint64(singles_ptr[i].sum_in_udp, fd);
		fwriteuint64(singles_ptr[i].sum_in_other, fd);
		fwriteuint64(singles_ptr[i].sum_out_tcp, fd);
		fwriteuint64(singles_ptr[i].sum_out_udp, fd);
		fwriteuint64(singles_ptr[i].sum_out_other, fd);
		fwriteuint64(singles_ptr[i].sum_all, fd);
	}
}

/* Print singles from PCNF file */
void fprintsingles(FILE *fd, FILE *jfd) {
	struct singleset set;
	uint8_t b[size_singleset];
	if ( fseek(fd, size_header + (raws_cnt*size_rawset), SEEK_SET) != 0 ) readpcnferror();	// skip to data sets
	printheadsingles();
	for (uint64_t i=0; i<singles_cnt; i++) {
		if (fread(&b,1,size_singleset,fd) != size_singleset) readpcnferror();	// read data set from file
		set.addr = readipv6(b, 0);	// decode read data into data set
		set.first_ts = readuint64(b, 16);
		set.last_ts = readuint64(b, 24);
		set.cnt_in_tcp = readuint64(b, 32);
		set.cnt_in_udp = readuint64(b, 40);
		set.cnt_in_other = readuint64(b, 48);
		set.cnt_out_tcp = readuint64(b, 56);
		set.cnt_out_udp = readuint64(b, 64);
		set.cnt_out_other = readuint64(b, 72);
		set.cnt_all = readuint64(b, 80);
		set.sum_in_tcp = readuint64(b, 88);
		set.sum_in_udp = readuint64(b, 96);
		set.sum_in_other = readuint64(b, 104);
		set.sum_out_tcp = readuint64(b, 112);
		set.sum_out_udp = readuint64(b, 120);
		set.sum_out_other = readuint64(b, 128);
		set.sum_all = readuint64(b, 136);
		if ( jfd == NULL ) printsingle(set);	// print data set
		else {
			if ( i > 0 ) fprintf(jfd, ",");
			jfprintsingle(jfd, set);
		}
	}
}

/* Print head line for links */
void printheadlinks() {
	if ( col_head_line != 'c' ) return;
	printf("SRC_ADDR%cDST_ADDR", info_del);
	printf("%cFIRST_TS%cLAST_TS", info_del, info_del);
	printf("%cTCP_PACKETS%cUDP_PACKETS%cOTHER_PACKETS%cALL_PACKETS", info_del, info_del, info_del, info_del);
	printf("%cTCP_VOLUME%cUDP_VOLUME%cOTHER_VOLUME%cALL_VOLUME\n", info_del, info_del, info_del, info_del);
}

/* Print one link set */
void printlink(struct linkset set) {
	printaddr(set.src_addr, info_del);
	printaddr(set.dst_addr, info_del);
	printts(set.first_ts);
	printts(set.last_ts);
	printcnt(set.cnt_tcp, info_del);
	printcnt(set.cnt_udp, info_del);
	printcnt(set.cnt_other, info_del);
	printcnt(set.cnt_all, info_del);
	printsum(set.sum_tcp, info_del);
	printsum(set.sum_udp, info_del);
	printsum(set.sum_other, info_del);
	printsum(set.sum_all, '\n');
}

/* Write link set to JSON file */
void jfprintlink(FILE *fd, struct linkset set) {
	fprintf(fd, "{\"SRC_ADDR\":"); jprintaddr(fd, set.src_addr);
	fprintf(fd, ",\"DST_ADDR\":"); jprintaddr(fd, set.dst_addr);
	fprintf(fd, ",\"FIRST_TS\":"); jprintts(fd, set.first_ts);
	fprintf(fd, ",\"LAST_TS\":"); jprintts(fd, set.last_ts);
	fprintf(fd, ",\"TCP_PACKETS\":%lu,\"UDP_PACKETS\":%lu,\"OTHER_PACKETS\":%lu,\"ALL_PACKETS\":%lu",
		set.cnt_tcp, set.cnt_udp, set.cnt_other, set.cnt_all);
	fprintf(fd, ",\"TCP_VOLUME\":%lu,\"UDP_VOLUME\":%lu,\"OTHER_VOLUME\":%lu,\"ALL_VOLUME\":%lu}",
		set.sum_tcp, set.sum_udp, set.sum_other, set.sum_all);
}

/* Print links */
void printlinks() {
	printheadlinks();
	for (uint64_t i=0; i < links_cnt; i++) printlink(links_ptr[i]);	// loop through the array in the allocated memory
}

/* Write links from dynamic array to file */
void fwritelinks(FILE *fd) {
	for (uint64_t i=0; i<links_cnt; i++) {
		fwriteip(links_ptr[i].src_addr, fd);
		fwriteip(links_ptr[i].dst_addr, fd);
		fwriteuint64(links_ptr[i].first_ts, fd);
		fwriteuint64(links_ptr[i].last_ts, fd);
		fwriteuint64(links_ptr[i].cnt_tcp, fd);
		fwriteuint64(links_ptr[i].cnt_udp, fd);
		fwriteuint64(links_ptr[i].cnt_other, fd);
		fwriteuint64(links_ptr[i].cnt_all, fd);
		fwriteuint64(links_ptr[i].sum_tcp, fd);
		fwriteuint64(links_ptr[i].sum_udp, fd);
		fwriteuint64(links_ptr[i].sum_other, fd);
		fwriteuint64(links_ptr[i].sum_all, fd);
	}
}

/* Print links from PCNF file */
void fprintlinks(FILE *fd, FILE *jfd) {
	struct linkset set;
	uint8_t b[size_linkset];
	if ( fseek(fd, size_header	// skip to the sets
		+ (raws_cnt*size_rawset)
		+ (singles_cnt*size_singleset), SEEK_SET) != 0 ) readpcnferror();
	printheadlinks();
	for (uint64_t i=0; i<links_cnt; i++) {
		if (fread(&b, 1, size_linkset,fd) != size_linkset) readpcnferror();	// read data set from file
		set.src_addr = readipv6(b, 0);	// decode read data into data set
		set.dst_addr = readipv6(b, 16);
		set.first_ts = readuint64(b, 32);
		set.last_ts = readuint64(b, 40);
		set.cnt_tcp = readuint64(b, 48);
		set.cnt_udp = readuint64(b, 56);
		set.cnt_other = readuint64(b, 64);
		set.cnt_all = readuint64(b, 72);
		set.sum_tcp = readuint64(b, 80);
		set.sum_udp = readuint64(b, 88);
		set.sum_other = readuint64(b, 96);
		set.sum_all = readuint64(b, 104);
		if ( jfd == NULL ) printlink(set);	// print data set
		else {
			if ( i > 0 ) fprintf(jfd, ",");
			jfprintlink(jfd, set);
		}
	}
}

/* Print head line for ports */
void printheadports() {
	if ( col_head_line != 'c' ) return;
	printf("ADDR%cPORT%cFIRST_TS%cLAST_TS", addr_port_del, info_del, info_del);
	printf("%cTCP_IN_PACKETS%cUDP_IN_PACKETS%cOTHER_IN_PACKETS", info_del, info_del, info_del);
	printf("%cTCP_OUT_PACKETS%cUDP_OUT_PACKETS%cOTHER_OUT_PACKETS%cALL_OUT_PACKETS", info_del, info_del, info_del, info_del);
	printf("%cTCP_IN_VOLUME%cUDP_IN_VOLUME%cOTHER_IN_VOLUME", info_del, info_del, info_del);
	printf("%cTCP_OUT_VOLUME%cUDP_OUT_VOLUME%cOTHER_OUT_VOLUME%cALL_VOLUME\n", info_del, info_del, info_del, info_del);
}

/* Print ports */
void printport(struct portset set) {
	printaddr(set.addr, addr_port_del);
	printportnum(set.port);
	printts(set.first_ts);
	printts(set.last_ts);
	printcnt(set.cnt_in_tcp, info_del);
	printcnt(set.cnt_in_udp, info_del);
	printcnt(set.cnt_in_other, info_del);
	printcnt(set.cnt_out_tcp, info_del);
	printcnt(set.cnt_out_udp, info_del);
	printcnt(set.cnt_out_other, info_del);
	printcnt(set.cnt_all, info_del);
	printsum(set.sum_in_tcp, info_del);
	printsum(set.sum_in_udp, info_del);
	printsum(set.sum_in_other, info_del);
	printsum(set.sum_out_tcp, info_del);
	printsum(set.sum_out_udp, info_del);
	printsum(set.sum_out_other, info_del);
	printsum(set.sum_all, '\n');
}

/* Write port set to JSON file */
void jfprintport(FILE *fd, struct portset set) {
	fprintf(fd, "{\"ADDR\":"); jprintaddr(fd, set.addr);
	fprintf(fd, ",\"PORT\":%u", set.port);
	fprintf(fd, ",\"FIRST_TS\":"); jprintts(fd, set.first_ts);
	fprintf(fd, ",\"LAST_TS\":"); jprintts(fd, set.last_ts);
	fprintf(fd, ",\"TCP_IN_PACKETS\":%lu,\"UDP_IN_PACKETS\":%lu,\"OTHER_IN_PACKETS\":%lu",
		set.cnt_in_tcp, set.cnt_in_udp, set.cnt_in_other);
	fprintf(fd, ",\"TCP_OUT_PACKETS\":%lu,\"UDP_OUT_PACKETS\":%lu,\"OTHER_OUT_PACKETS\":%lu,\"ALL_PACKETS\":%lu",
		set.cnt_out_tcp, set.cnt_out_udp, set.cnt_out_other, set.cnt_all);
	fprintf(fd, ",\"TCP_IN_VOLUME\":%lu,\"UDP_IN_VOLUME\":%lu,\"OTHER_IN_VOLUME\":%lu",
		set.sum_in_tcp, set.sum_in_udp, set.sum_in_other);
	fprintf(fd, ",\"TCP_OUT_VOLUME\":%lu,\"UDP_OUT_VOLUME\":%lu,\"OTHER_OUT_VOLUME\":%lu,\"ALL_VOLUME\":%lu}",
		set.sum_out_tcp, set.sum_out_udp, set.sum_out_other, set.sum_all);
}

/* Print ports */
void printports() {
	printheadports();
	for (uint64_t i=0; i < ports_cnt; i++) printport(ports_ptr[i]);	// loop through the array in the allocated memory
}

/* Write port sets from dynamic array to file */
void fwriteports(FILE *fd) {
	for (uint64_t i=0; i<ports_cnt; i++) {
		fwriteip(ports_ptr[i].addr, fd);
		fwriteuint64(ports_ptr[i].port, fd);
		fwriteuint64(ports_ptr[i].first_ts, fd);
		fwriteuint64(ports_ptr[i].last_ts, fd);
		fwriteuint64(ports_ptr[i].cnt_in_tcp, fd);
		fwriteuint64(ports_ptr[i].cnt_in_udp, fd);
		fwriteuint64(ports_ptr[i].cnt_in_other, fd);
		fwriteuint64(ports_ptr[i].cnt_out_tcp, fd);
		fwriteuint64(ports_ptr[i].cnt_out_udp, fd);
		fwriteuint64(ports_ptr[i].cnt_out_other, fd);
		fwriteuint64(ports_ptr[i].cnt_all, fd);
		fwriteuint64(ports_ptr[i].sum_in_tcp, fd);
		fwriteuint64(ports_ptr[i].sum_in_udp, fd);
		fwriteuint64(ports_ptr[i].sum_in_other, fd);
		fwriteuint64(ports_ptr[i].sum_out_tcp, fd);
		fwriteuint64(ports_ptr[i].sum_out_udp, fd);
		fwriteuint64(ports_ptr[i].sum_out_other, fd);
		fwriteuint64(ports_ptr[i].sum_all, fd);
	}
}

/* Print ports from PCNF file */
void fprintports(FILE *fd, FILE *jfd) {
	struct portset set;
	uint8_t b[size_portset];
	if ( fseek(fd, size_header	// skip to the sets
		+ (raws_cnt*size_rawset)
		+ (singles_cnt*size_singleset)
		+ (links_cnt*size_linkset), SEEK_SET) != 0 ) readpcnferror();
	printheadports();
	for (uint64_t i=0; i<ports_cnt; i++) {
		if (fread(&b, 1, size_portset,fd) != size_portset) readpcnferror();	// read data set from file
		set.addr = readipv6(b, 0);	// decode read data into data set
		set.port = readuint64(b, 16);
		set.first_ts = readuint64(b, 24);
		set.last_ts = readuint64(b, 32);
		set.cnt_in_tcp = readuint64(b, 40);
		set.cnt_in_udp = readuint64(b, 48);
		set.cnt_in_other = readuint64(b, 56);
		set.cnt_out_tcp = readuint64(b, 64);
		set.cnt_out_udp = readuint64(b, 72);
		set.cnt_out_other = readuint64(b, 80);
		set.cnt_all = readuint64(b, 88);
		set.sum_in_tcp = readuint64(b, 96);
		set.sum_in_udp = readuint64(b, 104);
		set.sum_in_other = readuint64(b, 112);
		set.sum_out_tcp = readuint64(b, 120);
		set.sum_out_udp = readuint64(b, 128);
		set.sum_out_other = readuint64(b, 136);
		set.sum_all = readuint64(b, 144);
		if ( jfd == NULL ) printport(set);
		else {
			if ( i > 0 ) fprintf(jfd, ",");
			jfprintport(jfd, set);
		}
	}
}

/* Print head line for bidirectional links */
void printheadbilinks() {
	if ( col_head_line != 'c' ) return;
	printf("UPPER_ADDR%cLOWER_ADDR", info_del);
	printf("%cFIRST_TS%cLAST_TS", info_del, info_del);
	printf("%cTCP_PACKETS%cUDP_PACKETS%cOTHER_PACKETS%cALL_PACKETS", info_del, info_del, info_del, info_del);
	printf("%cTCP_VOLUME%cUDP_VOLUME%cOTHER_VOLUME%cALL_VOLUME\n", info_del, info_del, info_del, info_del);
}

/* Print one bidirectional link */
void printbilink(struct bilinkset set) {
	printaddr(set.upper_addr, info_del);
	printaddr(set.lower_addr, info_del);
	printts(set.first_ts);
	printts(set.last_ts);
	printcnt(set.cnt_tcp, info_del);
	printcnt(set.cnt_udp, info_del);
	printcnt(set.cnt_other, info_del);
	printcnt(set.cnt_all, info_del);
	printsum(set.sum_tcp, info_del);
	printsum(set.sum_udp, info_del);
	printsum(set.sum_other, info_del);
	printsum(set.sum_all, '\n');
}

/* Write bilink set to JSON file */
void jfprintbilink(FILE *fd, struct bilinkset set) {
	fprintf(fd, "{\"UPPER_ADDR\":"); jprintaddr(fd, set.upper_addr);
	fprintf(fd, ",\"LOWER_ADDR\":"); jprintaddr(fd, set.lower_addr);
	fprintf(fd, ",\"FIRST_TS\":"); jprintts(fd, set.first_ts);
	fprintf(fd, ",\"LAST_TS\":"); jprintts(fd, set.last_ts);
	fprintf(fd, ",\"TCP_PACKETS\":%lu,\"UDP_PACKETS\":%lu,\"OTHER_PACKETS\":%lu,\"ALL_PACKETS\":%lu",
		set.cnt_tcp, set.cnt_udp, set.cnt_other, set.cnt_all);
	fprintf(fd, ",\"TCP_VOLUME\":%lu,\"UDP_VOLUME\":%lu,\"OTHER_VOLUME\":%lu,\"ALL_VOLUME\":%lu}",
		set.sum_tcp, set.sum_udp, set.sum_other, set.sum_all);
}

/* Print bidirectional links */
void printbilinks() {
	printheadbilinks();
	for (uint64_t i=0; i < bilinks_cnt; i++) printbilink(bilinks_ptr[i]);	// loop through the array in the allocated memory
}

/* Write bidirectional links from dynamic array to file */
void fwritebilinks(FILE *fd) {
	for (uint64_t i=0; i<bilinks_cnt; i++) {
		fwriteip(bilinks_ptr[i].upper_addr,fd);	// decode read data into data set
		fwriteip(bilinks_ptr[i].lower_addr, fd);
		fwriteuint64(bilinks_ptr[i].first_ts, fd);
		fwriteuint64(bilinks_ptr[i].last_ts, fd);
		fwriteuint64(bilinks_ptr[i].cnt_tcp, fd);
		fwriteuint64(bilinks_ptr[i].cnt_udp, fd);
		fwriteuint64(bilinks_ptr[i].cnt_other, fd);
		fwriteuint64(bilinks_ptr[i].cnt_all, fd);
		fwriteuint64(bilinks_ptr[i].sum_tcp, fd);
		fwriteuint64(bilinks_ptr[i].sum_udp, fd);
		fwriteuint64(bilinks_ptr[i].sum_other, fd);
		fwriteuint64(bilinks_ptr[i].sum_all, fd);
	}
}

/* Print  birirectional links from PCNF file */
void fprintbilinks(FILE *fd, FILE *jfd) {
	struct bilinkset set;
	uint8_t b[size_bilinkset];
	if ( fseek(fd, size_header	// skip to the sets
		+ (raws_cnt*size_rawset)
		+ (singles_cnt*size_singleset)
		+ (links_cnt*size_linkset)
		+ (ports_cnt*size_portset), SEEK_SET) != 0 ) readpcnferror();
	printheadbilinks();
	for (uint64_t i=0; i<bilinks_cnt; i++) {
		if (fread(&b, 1, size_bilinkset, fd) != size_bilinkset) readpcnferror();	// read data set from file
		set.upper_addr = readipv6(b, 0);	// decode read data into data set
		set.lower_addr = readipv6(b, 16);
		set.first_ts = readuint64(b, 32);
		set.last_ts = readuint64(b, 40);
		set.cnt_tcp = readuint64(b, 48);
		set.cnt_udp = readuint64(b, 56);
		set.cnt_other = readuint64(b, 64);
		set.cnt_all = readuint64(b, 72);
		set.sum_tcp = readuint64(b, 80);
		set.sum_udp = readuint64(b, 88);
		set.sum_other = readuint64(b, 96);
		set.sum_all = readuint64(b, 104);
		if ( jfd == NULL) printbilink(set);
		else {
			if ( i > 0 ) fprintf(jfd, ",");
			jfprintbilink(jfd, set);
		}
	}
}

/* Write PCNF file */
void fwritepcnf(FILE *fd) {
	fwriteuint64(file_identifier, fd);	// write file identifier = magic number
	fwriteuint64(raws_cnt, fd);	// write number of sets to PCNF file header
	fwriteuint64(singles_cnt, fd);
	fwriteuint64(links_cnt, fd);
	fwriteuint64(ports_cnt, fd);
	fwriteuint64(bilinks_cnt, fd);
	fwriteraws(fd);	// write data sets
	fwritesingles(fd);
	fwritelinks(fd);
	fwriteports(fd);
	fwritebilinks(fd);
}

/* Write sets to JSON file */
void fwritejson(FILE *fd) {
	fprintf(fd, "{\"raws\":[");
	jfprintraw(fd, raws_ptr[0]);
	for (uint64_t i=1; i < raws_cnt; i++) {	// loop through raws
		fprintf(fd, ",");
		jfprintraw(fd, raws_ptr[i]);
	}
	fprintf(fd, "],\"singles\":[");
	jfprintsingle(fd, singles_ptr[0]);
	for (uint64_t i=1; i < singles_cnt; i++) {	// loop through singles
		fprintf(fd, ",");
		jfprintsingle(fd, singles_ptr[i]);
	}
	fprintf(fd, "],\"links\":[");
	jfprintlink(fd, links_ptr[0]);
	for (uint64_t i=1; i < links_cnt; i++) {	// loop through links
		fprintf(fd, ",");
		jfprintlink(fd, links_ptr[i]);
	}
	fprintf(fd, "],\"ports\":[");
	jfprintport(fd, ports_ptr[0]);
	for (uint64_t i=1; i < ports_cnt; i++) {	// loop through ports
		fprintf(fd, ",");
		jfprintport(fd, ports_ptr[i]);
	}
	fprintf(fd, "],\"bilinks\":[");
	jfprintbilink(fd, bilinks_ptr[0]);
	for (uint64_t i=1; i < bilinks_cnt; i++) {	// loop through bilinks
		fprintf(fd, ",");
		jfprintbilink(fd, bilinks_ptr[i]);
	}
	fprintf(fd, "]}\n");
}

/* Read header of PCNF file */
void freadpcnfcnt(FILE *fd) {
	uint8_t b[40];
	if (fread(&b,1,40,fd) != 40) readpcnferror();	// read from pcnf file
	raws_cnt = readuint64(b, 0);	// decode
	singles_cnt = readuint64(b, 8);
	links_cnt = readuint64(b, 16);
	ports_cnt = readuint64(b, 24);
	bilinks_cnt = readuint64(b, 32);
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

/* Put packet info in array raws */
void putinfo(struct packetheader header, struct packetdata packet) {
	struct rawset *new_raws_ptr;
	for (uint64_t i=0; i<raws_cnt; i++) {	// loop through the stored data
		if ( ( eqaddr(packet.src_addr, raws_ptr[i].src_addr) == 1 )	// if identical addresses
			&& ( eqaddr(packet.dst_addr, raws_ptr[i].dst_addr) == 1 )
			&& ( packet.src_port == raws_ptr[i].src_port )	// and identical ports
			&& ( packet.dst_port == raws_ptr[i].dst_port ) ) {
			if ( header.ts > raws_ptr[i].last_ts ) raws_ptr[i].last_ts = header.ts;	// update timestamps
			else if ( header.ts < raws_ptr[i].first_ts ) raws_ptr[i].first_ts = header.ts;
			if ( packet.protocol == 6 ) {	// TCP
				raws_ptr[i].sum_tcp += header.orig_len;	// update sum of traffic volume
				raws_ptr[i].cnt_tcp++;	// increase packet counter
			} else if ( packet.protocol == 17 ) {	// UDP
				raws_ptr[i].sum_udp += header.orig_len;	// update sum of traffic volume
				raws_ptr[i].cnt_udp++;	// increase packet counter
			} else if ( packet.protocol == 0xff ) {	// other ip protocol
				raws_ptr[i].sum_other += header.orig_len;	// update sum of traffic volume
				raws_ptr[i].cnt_other++;	// increase packet counter
			}
			return;
		}
	}
/* If no matching adresse-port-combination was found, create new data set */
	raws_ptr[raws_cnt].src_addr = packet.src_addr;	// store the data from PCAP file in the dynamic array
	raws_ptr[raws_cnt].dst_addr = packet.dst_addr;
	raws_ptr[raws_cnt].src_port = packet.src_port;
	raws_ptr[raws_cnt].dst_port = packet.dst_port;
	raws_ptr[raws_cnt].first_ts = header.ts;
	raws_ptr[raws_cnt].last_ts = header.ts;
	if ( packet.protocol == 6 ) {	// TCP
		raws_ptr[raws_cnt].sum_tcp = header.orig_len;	// set traffic volume
		raws_ptr[raws_cnt].cnt_tcp = 1;	// set packet counter
		raws_ptr[raws_cnt].sum_udp = 0;
		raws_ptr[raws_cnt].cnt_udp = 0;
		raws_ptr[raws_cnt].sum_other = 0;
		raws_ptr[raws_cnt].cnt_other = 0;
	} else if ( packet.protocol == 17 ) {	// UDP
		raws_ptr[raws_cnt].sum_tcp = 0;
		raws_ptr[raws_cnt].cnt_tcp = 0;
		raws_ptr[raws_cnt].sum_udp = header.orig_len;	// set traffic volume
		raws_ptr[raws_cnt].cnt_udp = 1;	// set packet counter
		raws_ptr[raws_cnt].sum_other = 0;
		raws_ptr[raws_cnt].cnt_other = 0;
	} else {	// other IP packet
		raws_ptr[raws_cnt].sum_tcp = 0;
		raws_ptr[raws_cnt].cnt_tcp = 0;
		raws_ptr[raws_cnt].sum_udp = 0;
		raws_ptr[raws_cnt].cnt_udp = 0;
		raws_ptr[raws_cnt].sum_other = header.orig_len;	// set traffic volume
		raws_ptr[raws_cnt].cnt_other = 1;	// set packet counter
	}
	new_raws_ptr = realloc(raws_ptr,((++raws_cnt)+1)*size_rawset); /* get more memory */
	if ( new_raws_ptr == NULL ) memerror();
	raws_ptr = new_raws_ptr;	// update pointer to the enlarged array
}

/* Sort raw data sets */
void sortraws() {
	struct rawset tmp;
	uint64_t swapped;
	for (uint64_t i=0; i<raws_cnt; i++) {	// loop through sets to sum traffic
		raws_ptr[i].cnt_all = raws_ptr[i].cnt_tcp + raws_ptr[i].cnt_udp + raws_ptr[i].cnt_other;
		raws_ptr[i].sum_all = raws_ptr[i].sum_tcp + raws_ptr[i].sum_udp + raws_ptr[i].sum_other;
	}
	do {
		swapped = 0;
		for (uint64_t i=1; i<raws_cnt; i++) {
			if ( raws_ptr[i-1].sum_all < raws_ptr[i].sum_all ) {
				tmp = raws_ptr[i-1];
				raws_ptr[i-1] = raws_ptr[i];
				raws_ptr[i] = tmp;
				swapped++;
			}
		}
	} while ( swapped > 0 );
}

/* Work on one PCAP file */
void workpcap(FILE *fd, uint32_t magic_number) {
	struct packetheader header;
	struct packetdata packet;
	if (fseek(fd,24,SEEK_SET) != 0) return;	// go to first packet header
	for (;;) {	// loop through packets (endless until skipping by return)
		header = readpacketheader(fd, magic_number);	/* read packet header*/
		if ( header.error == 1 ) return;	// if not successful, end of file might be reached
		packet = readpacketdata(fd, header.incl_len);	// read packet content: ip and tcp/udp header
		if ( packet.error == 1 ) return;	// just skip in case there was a problem while reading the packet
		if ( packet.error == -1 ) continue;	// do not count and go to next packet - no ip packet
		putinfo(header, packet);	// put packet infos in array
		if ( packet.error == -2 ) return;	// count this packet but this is all for the pcap file
	}
}

/* Generate statistics about single IP addresses */
void gensingles() {
	struct singleset *new_singles_ptr, tmp;
	int match;
	uint64_t swapped;
	for (uint64_t i=0; i<raws_cnt; i++) {	// loop through raw data sets
		match = 0;
		for (uint64_t j=0; j<singles_cnt; j++) {	// loop through existing singles
			if ( eqaddr(raws_ptr[i].src_addr, singles_ptr[j].addr) == 1 ) {	// source address already in array?
				if ( raws_ptr[i].first_ts < singles_ptr[j].first_ts ) singles_ptr[j].first_ts = raws_ptr[i].first_ts;	// update timestamps
				if ( raws_ptr[i].last_ts > singles_ptr[j].last_ts ) singles_ptr[j].last_ts = raws_ptr[i].last_ts;
				singles_ptr[j].cnt_out_tcp += raws_ptr[i].cnt_tcp;	// update packet counters
				singles_ptr[j].cnt_out_udp += raws_ptr[i].cnt_udp;
				singles_ptr[j].cnt_out_other += raws_ptr[i].cnt_other;
				singles_ptr[j].sum_out_tcp += raws_ptr[i].sum_tcp;	// update traffic volume
				singles_ptr[j].sum_out_udp += raws_ptr[i].sum_udp;
				singles_ptr[j].sum_out_other += raws_ptr[i].sum_other;
				match = 1;
				break;
			}
		}
		if ( match == 0 ) {	// if no match -> create new data set
			singles_ptr[singles_cnt].addr = raws_ptr[i].src_addr;
			singles_ptr[singles_cnt].first_ts = raws_ptr[i].first_ts;
			singles_ptr[singles_cnt].last_ts = raws_ptr[i].last_ts;
			singles_ptr[singles_cnt].cnt_in_tcp = 0;
			singles_ptr[singles_cnt].cnt_in_udp = 0;
			singles_ptr[singles_cnt].cnt_in_other = 0;
			singles_ptr[singles_cnt].cnt_out_tcp = raws_ptr[i].cnt_tcp;
			singles_ptr[singles_cnt].cnt_out_udp = raws_ptr[i].cnt_udp;
			singles_ptr[singles_cnt].cnt_out_other = raws_ptr[i].cnt_other;
			singles_ptr[singles_cnt].sum_in_tcp = 0;
			singles_ptr[singles_cnt].sum_in_udp = 0;
			singles_ptr[singles_cnt].sum_in_other = 0;
			singles_ptr[singles_cnt].sum_out_tcp = raws_ptr[i].sum_tcp;
			singles_ptr[singles_cnt].sum_out_udp = raws_ptr[i].sum_udp;
			singles_ptr[singles_cnt].sum_out_other = raws_ptr[i].sum_other;
			new_singles_ptr = realloc(singles_ptr,((++singles_cnt)+1)*size_singleset); /* get more memory */
			if ( new_singles_ptr == NULL ) memerror();
			singles_ptr = new_singles_ptr;	// update pointer to the enlarged array
		}
		match = 0;
		for (uint64_t j=0; j<singles_cnt; j++) {	// loop through existing singles
			if ( eqaddr(raws_ptr[i].dst_addr, singles_ptr[j].addr) == 1 ) {	// destination address already in array?
				if ( raws_ptr[i].first_ts < singles_ptr[j].first_ts ) singles_ptr[j].first_ts = raws_ptr[i].first_ts;	// update timestamps
				if ( raws_ptr[i].last_ts > singles_ptr[j].last_ts ) singles_ptr[j].last_ts = raws_ptr[i].last_ts;
				singles_ptr[j].cnt_in_tcp += raws_ptr[i].cnt_tcp;	// update packet counters
				singles_ptr[j].cnt_in_udp += raws_ptr[i].cnt_udp;
				singles_ptr[j].cnt_in_other += raws_ptr[i].cnt_other;
				singles_ptr[j].sum_in_tcp += raws_ptr[i].sum_tcp;	// update traffic volume
				singles_ptr[j].sum_in_udp += raws_ptr[i].sum_udp;
				singles_ptr[j].sum_in_other += raws_ptr[i].sum_other;
				match = 1;
			}
		}
		if ( match == 0 )	{	// if no match -> create new data set
			singles_ptr[singles_cnt].addr = raws_ptr[i].dst_addr;
			singles_ptr[singles_cnt].first_ts = raws_ptr[i].first_ts;
			singles_ptr[singles_cnt].last_ts = raws_ptr[i].last_ts;
			singles_ptr[singles_cnt].cnt_in_tcp = raws_ptr[i].cnt_tcp;
			singles_ptr[singles_cnt].cnt_in_udp = raws_ptr[i].cnt_udp;
			singles_ptr[singles_cnt].cnt_in_other = raws_ptr[i].cnt_other;
			singles_ptr[singles_cnt].cnt_out_tcp = 0;
			singles_ptr[singles_cnt].cnt_out_udp = 0;
			singles_ptr[singles_cnt].cnt_out_other = 0;
			singles_ptr[singles_cnt].sum_in_tcp = raws_ptr[i].sum_tcp;
			singles_ptr[singles_cnt].sum_in_udp = raws_ptr[i].sum_udp;
			singles_ptr[singles_cnt].sum_in_other = raws_ptr[i].sum_other;
			singles_ptr[singles_cnt].sum_out_tcp = 0;
			singles_ptr[singles_cnt].sum_out_udp = 0;
			singles_ptr[singles_cnt].sum_out_other = 0;
			new_singles_ptr = realloc(singles_ptr,((++singles_cnt)+1)*sizeof(struct singleset)); /* get more memory */
			if ( new_singles_ptr == NULL ) memerror();
			singles_ptr = new_singles_ptr;	// update pointer to the enlarged array
		}
	}
	for (unsigned long i=0; i<singles_cnt; i++) {	// loop through singles once more to sum traffic
		singles_ptr[i].cnt_all = singles_ptr[i].cnt_in_tcp + singles_ptr[i].cnt_in_udp + singles_ptr[i].cnt_in_other
								+ singles_ptr[i].cnt_out_tcp + singles_ptr[i].cnt_out_udp + singles_ptr[i].cnt_out_other;
		singles_ptr[i].sum_all = singles_ptr[i].sum_in_tcp + singles_ptr[i].sum_in_udp + singles_ptr[i].sum_in_other
								+ singles_ptr[i].sum_out_tcp + singles_ptr[i].sum_out_udp + singles_ptr[i].sum_out_other;
	}
	do {	// sort
		swapped = 0;
		for (uint64_t i=1; i<singles_cnt; i++) {
			if ( singles_ptr[i-1].sum_all < singles_ptr[i].sum_all ) {
				tmp = singles_ptr[i-1];
				singles_ptr[i-1] = singles_ptr[i];
				singles_ptr[i] = tmp;
				swapped++;
			}
		}
	} while ( swapped > 0 );
}

/* Generate statistics about links */
void genlinks() {
	struct linkset *new_links_ptr, tmp;
	int match;
	uint64_t swapped;
	for (uint64_t i=0; i<raws_cnt; i++) {	// loop through raw data sets
		match = 0;
		for (uint64_t j=0; j<links_cnt; j++) {	// loop through existing links
			if ( ( eqaddr(raws_ptr[i].src_addr, links_ptr[j].src_addr) == 1 )	// source and destination address already in array?
			&& ( eqaddr(raws_ptr[i].dst_addr, links_ptr[j].dst_addr) == 1 ) ) {
				if ( raws_ptr[i].first_ts < links_ptr[j].first_ts ) links_ptr[j].first_ts = raws_ptr[i].first_ts;	// update timestamps
				if ( raws_ptr[i].last_ts > links_ptr[j].last_ts ) links_ptr[j].last_ts = raws_ptr[i].last_ts;
				links_ptr[j].cnt_tcp += raws_ptr[i].cnt_tcp;	// update packet counters
				links_ptr[j].cnt_udp += raws_ptr[i].cnt_udp;
				links_ptr[j].cnt_other += raws_ptr[i].cnt_other;
				links_ptr[j].sum_tcp += raws_ptr[i].sum_tcp;	// update traffic volume
				links_ptr[j].sum_udp += raws_ptr[i].sum_udp;
				links_ptr[j].sum_other += raws_ptr[i].sum_other;
				match = 1;
				break;
			}
		}
		if ( match == 0 ) {	// if no match -> create new data set
			links_ptr[links_cnt].src_addr = raws_ptr[i].src_addr;
			links_ptr[links_cnt].dst_addr = raws_ptr[i].dst_addr;
			links_ptr[links_cnt].first_ts = raws_ptr[i].first_ts;
			links_ptr[links_cnt].last_ts = raws_ptr[i].last_ts;
			links_ptr[links_cnt].cnt_tcp = raws_ptr[i].cnt_tcp;
			links_ptr[links_cnt].cnt_udp = raws_ptr[i].cnt_udp;
			links_ptr[links_cnt].cnt_other = raws_ptr[i].cnt_other;
			links_ptr[links_cnt].sum_tcp = raws_ptr[i].sum_tcp;
			links_ptr[links_cnt].sum_udp = raws_ptr[i].sum_udp;
			links_ptr[links_cnt].sum_other = raws_ptr[i].sum_other;
			new_links_ptr = realloc(links_ptr,((++links_cnt)+1)*sizeof(struct linkset)); /* get more memory */
			if ( new_links_ptr == NULL ) memerror();
			links_ptr = new_links_ptr;	// update pointer to the enlarged array
		}
	}
	for (uint64_t i=0; i<links_cnt; i++) {	// loop through links once more to sum traffic
		links_ptr[i].cnt_all = links_ptr[i].cnt_tcp + links_ptr[i].cnt_udp + links_ptr[i].cnt_other;
		links_ptr[i].sum_all = links_ptr[i].sum_tcp + links_ptr[i].sum_udp + links_ptr[i].sum_other;
	}
	do {	// sort
		swapped = 0;
		for (int i=1; i<links_cnt; i++) {
			if ( links_ptr[i-1].sum_all < links_ptr[i].sum_all ) {
				tmp = links_ptr[i-1];
				links_ptr[i-1] = links_ptr[i];
				links_ptr[i] = tmp;
				swapped++;
			}
		}
	} while ( swapped > 0 );
}

/* Generate statistics about traffic per port of single IP addresses */
void genports() {
	struct portset *new_ports_ptr, tmp;
	int match;
	uint64_t swapped;
	for (uint64_t i=0; i<raws_cnt; i++) {	// loop through raw data sets
		match = 0;
		for (uint64_t j=0; j<ports_cnt; j++) {	// loop through existing data sets
			if ( ( eqaddr(raws_ptr[i].src_addr, ports_ptr[j].addr) == 1 )	// source address + port already in array?
			&& ( raws_ptr[i].src_port == ports_ptr[j].port) ) {
				if ( raws_ptr[i].first_ts < ports_ptr[j].first_ts ) ports_ptr[j].first_ts = raws_ptr[i].first_ts;	// update timestamps
				if ( raws_ptr[i].last_ts > ports_ptr[j].last_ts ) ports_ptr[j].last_ts = raws_ptr[i].last_ts;
				ports_ptr[j].cnt_out_tcp += raws_ptr[i].cnt_tcp;	// update packet counters
				ports_ptr[j].cnt_out_udp += raws_ptr[i].cnt_udp;
				ports_ptr[j].cnt_out_other += raws_ptr[i].cnt_other;
				ports_ptr[j].sum_out_tcp += raws_ptr[i].sum_tcp;	// update traffic volume
				ports_ptr[j].sum_out_udp += raws_ptr[i].sum_udp;
				ports_ptr[j].sum_out_other += raws_ptr[i].sum_other;
				match = 1;
				break;
			}
		}
		if ( match == 0 ) {	// if no match -> create new data set
			ports_ptr[ports_cnt].addr = raws_ptr[i].src_addr;
			ports_ptr[ports_cnt].port = raws_ptr[i].src_port;
			ports_ptr[ports_cnt].first_ts = raws_ptr[i].first_ts;
			ports_ptr[ports_cnt].last_ts = raws_ptr[i].last_ts;
			ports_ptr[ports_cnt].cnt_in_tcp = 0;
			ports_ptr[ports_cnt].cnt_in_udp = 0;
			ports_ptr[ports_cnt].cnt_in_other = 0;
			ports_ptr[ports_cnt].cnt_out_tcp = raws_ptr[i].cnt_tcp;
			ports_ptr[ports_cnt].cnt_out_udp = raws_ptr[i].cnt_udp;
			ports_ptr[ports_cnt].cnt_out_other = raws_ptr[i].cnt_other;
			ports_ptr[ports_cnt].sum_in_tcp = 0;
			ports_ptr[ports_cnt].sum_in_udp = 0;
			ports_ptr[ports_cnt].sum_in_other = 0;
			ports_ptr[ports_cnt].sum_out_tcp = raws_ptr[i].sum_tcp;
			ports_ptr[ports_cnt].sum_out_udp = raws_ptr[i].sum_udp;
			ports_ptr[ports_cnt].sum_out_other = raws_ptr[i].sum_other;
			new_ports_ptr = realloc(ports_ptr,((++ports_cnt)+1)*sizeof(struct portset)); /* get more memory */
			if ( new_ports_ptr == NULL ) memerror();
			ports_ptr = new_ports_ptr;	// update pointer to the enlarged array
		}
		match = 0;
		for (unsigned long j=0; j<ports_cnt; j++) {	// loop through existing data sets
			if ( ( eqaddr(raws_ptr[i].dst_addr, ports_ptr[j].addr) == 1 )	// destination address + port already in array?
			&& ( raws_ptr[i].dst_port == ports_ptr[j].port) ) {
				if ( raws_ptr[i].first_ts < ports_ptr[j].first_ts ) ports_ptr[j].first_ts = raws_ptr[i].first_ts;	// update timestamps
				if ( raws_ptr[i].last_ts > ports_ptr[j].last_ts ) ports_ptr[j].last_ts = raws_ptr[i].last_ts;
				ports_ptr[j].cnt_in_tcp += raws_ptr[i].cnt_tcp;	// update packet counters
				ports_ptr[j].cnt_in_udp += raws_ptr[i].cnt_udp;
				ports_ptr[j].cnt_in_other += raws_ptr[i].cnt_other;
				ports_ptr[j].sum_in_tcp += raws_ptr[i].sum_tcp;	// update traffic volume
				ports_ptr[j].sum_in_udp += raws_ptr[i].sum_udp;
				ports_ptr[j].sum_in_other += raws_ptr[i].sum_other;
				match = 1;
			}
		}
		if ( match == 0 )	{	// if no match -> create new data set
			ports_ptr[ports_cnt].addr = raws_ptr[i].dst_addr;
			ports_ptr[ports_cnt].port = raws_ptr[i].dst_port;
			ports_ptr[ports_cnt].first_ts = raws_ptr[i].first_ts;
			ports_ptr[ports_cnt].last_ts = raws_ptr[i].last_ts;
			ports_ptr[ports_cnt].cnt_in_tcp = raws_ptr[i].cnt_tcp;
			ports_ptr[ports_cnt].cnt_in_udp = raws_ptr[i].cnt_udp;
			ports_ptr[ports_cnt].cnt_in_other = raws_ptr[i].cnt_other;
			ports_ptr[ports_cnt].cnt_out_tcp = 0;
			ports_ptr[ports_cnt].cnt_out_udp = 0;
			ports_ptr[ports_cnt].cnt_out_other = 0;
			ports_ptr[ports_cnt].sum_in_tcp = raws_ptr[i].sum_tcp;
			ports_ptr[ports_cnt].sum_in_udp = raws_ptr[i].sum_udp;
			ports_ptr[ports_cnt].sum_in_other = raws_ptr[i].sum_other;
			ports_ptr[ports_cnt].sum_out_tcp = 0;
			ports_ptr[ports_cnt].sum_out_udp = 0;
			ports_ptr[ports_cnt].sum_out_other = 0;
			new_ports_ptr = realloc(ports_ptr,((++ports_cnt)+1)*sizeof(struct portset)); /* get more memory */
			if ( new_ports_ptr == NULL ) memerror();
			ports_ptr = new_ports_ptr;	// update pointer to the enlarged array
		}
	}
	for (uint64_t i=0; i<ports_cnt; i++) {	// loop through singles once more to sum traffic;
		ports_ptr[i].cnt_all = ports_ptr[i].cnt_in_tcp + ports_ptr[i].cnt_in_udp + ports_ptr[i].cnt_in_other
								+ ports_ptr[i].cnt_out_tcp + ports_ptr[i].cnt_out_udp + ports_ptr[i].cnt_out_other;
		ports_ptr[i].sum_all = ports_ptr[i].sum_in_tcp + ports_ptr[i].sum_in_udp + ports_ptr[i].sum_in_other
								+ ports_ptr[i].sum_out_tcp + ports_ptr[i].sum_out_udp + ports_ptr[i].sum_out_other;
	}
	do {	// sort
		swapped = 0;
		for (uint64_t i=1; i<ports_cnt; i++) {
			if ( ports_ptr[i-1].sum_all < ports_ptr[i].sum_all ) {
				tmp = ports_ptr[i-1];
				ports_ptr[i-1] = ports_ptr[i];
				ports_ptr[i] = tmp;
				swapped++;
			}
		}
	} while ( swapped > 0 );
}

/* Generate statistics about bidirectional links */
void genbilinks() {
	struct bilinkset *new_bilinks_ptr, tmp;
	struct ipaddr upper_addr, lower_addr;
	uint64_t swapped;
	int match;
	for (uint64_t i=0; i<links_cnt; i++) {	// loop through links
		match = 0;
		if ( gtaddr(links_ptr[i].src_addr, links_ptr[i].dst_addr) == 1 ) {	// order source and detination address
			upper_addr = links_ptr[i].src_addr;
			lower_addr = links_ptr[i].dst_addr;
		} else {
			upper_addr = links_ptr[i].dst_addr;
			lower_addr = links_ptr[i].src_addr;
		}
		for (uint64_t j=0; j<bilinks_cnt; j++) {	// loop through existing bilinks
			if ( ( eqaddr(upper_addr, bilinks_ptr[j].upper_addr) == 1 )	// address pair already in?
			&& ( eqaddr(lower_addr, bilinks_ptr[j].lower_addr) == 1 ) ) {
				if ( links_ptr[i].first_ts < bilinks_ptr[j].first_ts ) bilinks_ptr[j].first_ts = links_ptr[i].first_ts;	// update timestamps
				if ( links_ptr[i].last_ts > bilinks_ptr[j].last_ts ) bilinks_ptr[j].last_ts = links_ptr[i].last_ts;
				bilinks_ptr[j].cnt_tcp += links_ptr[i].cnt_tcp;	// update packet counters
				bilinks_ptr[j].cnt_udp += links_ptr[i].cnt_udp;
				bilinks_ptr[j].cnt_other += links_ptr[i].cnt_other;
				bilinks_ptr[j].sum_tcp += links_ptr[i].sum_tcp;	// update traffic volume
				bilinks_ptr[j].sum_udp += links_ptr[i].sum_udp;
				bilinks_ptr[j].sum_other += links_ptr[i].sum_other;
				match = 1;
				break;
			}
		}
		if ( match == 0 ) {	// if no match -> create new data set
			bilinks_ptr[bilinks_cnt].upper_addr = upper_addr;
			bilinks_ptr[bilinks_cnt].lower_addr = lower_addr;
			bilinks_ptr[bilinks_cnt].first_ts = links_ptr[i].first_ts;
			bilinks_ptr[bilinks_cnt].last_ts = links_ptr[i].last_ts;
			bilinks_ptr[bilinks_cnt].cnt_tcp = links_ptr[i].cnt_tcp;
			bilinks_ptr[bilinks_cnt].cnt_udp = links_ptr[i].cnt_udp;
			bilinks_ptr[bilinks_cnt].cnt_other = links_ptr[i].cnt_other;
			bilinks_ptr[bilinks_cnt].sum_tcp = links_ptr[i].sum_tcp;
			bilinks_ptr[bilinks_cnt].sum_udp = links_ptr[i].sum_udp;
			bilinks_ptr[bilinks_cnt].sum_other = links_ptr[i].sum_other;
			new_bilinks_ptr = realloc(bilinks_ptr,((++bilinks_cnt)+1)*sizeof(struct bilinkset)); /* get more memory */
			if ( new_bilinks_ptr == NULL ) memerror();
			bilinks_ptr = new_bilinks_ptr;	// update pointer to the enlarged array
		}
	}
	for (unsigned long i=0; i<bilinks_cnt; i++) {	// loop through bilinks once more to sum traffic
		bilinks_ptr[i].cnt_all = bilinks_ptr[i].cnt_tcp + bilinks_ptr[i].cnt_udp + bilinks_ptr[i].cnt_other;
		bilinks_ptr[i].sum_all = bilinks_ptr[i].sum_tcp + bilinks_ptr[i].sum_udp + bilinks_ptr[i].sum_other;
	}
	do {	// sort
		swapped = 0;
		for (uint64_t i=1; i<bilinks_cnt; i++) {
			if ( bilinks_ptr[i-1].sum_all < bilinks_ptr[i].sum_all ) {
				tmp = bilinks_ptr[i-1];
				bilinks_ptr[i-1] = bilinks_ptr[i];
				bilinks_ptr[i] = tmp;
				swapped++;
			}
		}
	} while ( swapped > 0 );
}

/* Read delimiter on command line */
char readdelimiter(char *string) {
	if ( string[1] == 0 ) return string[0];	// ordinary printable character
	if ( ( string[0] == '\\' ) && ( string[1] == 't' ) && ( string[2] == 0 ) ) return '\t';
	fprintf(stderr, "Delimiter requires one basic character or \"\\t\" as argument.\n");
	exit(1);
}

/* Print sets to stdout */
void printsets(char out) {
	switch (out) {
		case 'v':	printraws(); break;
		case 's':	printsingles(); break;
		case 'l':	printlinks(); break;
		case 'p':	printports(); break;
		case 'b':	printbilinks();
	}
}

/* Main function - program starts here*/
int main(int argc, char **argv) {
	if ( ( argc > 1 )	// show help
	&& ( ( ( argv[1][0] == '-' ) && ( argv[1][1] == '-' ) && ( argv[1][2] == 'h' ) )
	|| ( ( argv[1][0] == '-' ) && ( argv[1][1] == 'h' ) ) ) ) help(0);
	else if ( argc < 2 ) help(1);	// also show help if no argument is given but return with exit(1)
	char opt, output = 'q';	// for arguments -s, -l, -p, -v or -u (output options)
	uint8_t filetype[8];	// to get file type / magic number and pcnf version
	uint32_t magic_number;	// file type
	char *pvalue = NULL, *dvalue = NULL, *wvalue = NULL, *jvalue = NULL;	// pointer to command line arguments
	FILE *fd, *pfd, *jfd = NULL;	// file pointer
	int outoptcnt = 0;	// count the output options - only one is possible
	while ((opt = getopt(argc, argv, "slbpvrca:d:w:j:")) != -1)	// command line arguments
		switch (opt) {
			case 's': outoptcnt++; output = opt; break;	// pass on output options
			case 'l': outoptcnt++; output = opt; break;
			case 'b': outoptcnt++; output = opt; break;
			case 'p': outoptcnt++; output = opt; break;
			case 'v': outoptcnt++; output = opt; break;
			case 'r': ts_format = 'r'; break;// timestamps in human readable time
			case 'c': col_head_line = 'c'; break;	// show meanings of columns in a head line
			case 'a': pvalue = optarg; break;	// set delimiter inbetween ip address and port number
			case 'd': dvalue = optarg; break;	// set delimiter inbetween infos
			case 'w': wvalue = optarg; break;	// set pcnf output file
			case 'j': jvalue = optarg; break;	// set json output file
			case '?':
				if ( (optopt == 'w') || (optopt == 'a') || (optopt == 'd') )
					fprintf(stderr, "Error: option -%c requires an argument.\n", optopt);
				else if (isprint(optopt))
					fprintf(stderr, "Use -h to get instructions.\n");
				exit(1);
			default: help(1);
		}
	if ( outoptcnt > 1 ) {	// check if more than one output option is given
		fprintf(stderr, "Error: only one output option at a time.\n");
		exit(1);
	}
	if ( argv[optind] == NULL ) {	// check if there are input files, at least one
		fprintf(stderr, "Error: at least one input file is required.\n");
		exit(1);
	}
	if ( pvalue != NULL ) addr_port_del = readdelimiter(pvalue);	// option -a
	if ( dvalue != NULL ) info_del = readdelimiter(dvalue);	// option -d
	if ( wvalue != NULL ) {	// option -w
		if ( access(wvalue, F_OK) != -1 ) {	// check for existing file
			fprintf(stderr, "Error: output PCAP file %s exists.\n", wvalue);
			exit(1);
		}
		pfd = fopen(wvalue, "wb");	// open pcnf file to write
		if ( pfd == NULL ) {
			fprintf(stderr, "Error: could not create writable PCNF file %s.\n", wvalue);
			exit(1);
		}
	}
	if ( jvalue != NULL ) {	// option -j
		if ( access(jvalue, F_OK) != -1 ) {	// check for existing file
			fprintf(stderr, "Error: output JSON file %s exists.\n", jvalue);
			exit(1);
		}
		jfd = fopen(jvalue, "w");	// open pcnf file to write
		if ( jfd == NULL ) {
			fprintf(stderr, "Error: could not create writable JSON file %s.\n", jvalue);
			exit(1);
		}
	}
	if ( (output=='q') && (wvalue==NULL) && (jvalue==NULL) ) output = 's';	// print singles if no file to write is given
	fd = fopen(argv[optind], "rb");	// open input file
	if ( fd == NULL ) {
		fprintf(stderr, "Error: could not open first input file %s.\n", argv[optind]);
		exit(1);
		}
	if ( fread(&filetype,1,8,fd) != 8 ) {
		fprintf(stderr, "Error: could not read first input file %s.\n", argv[optind]);
		exit(1);
	}
	if ( readuint64(filetype, 0) == file_identifier ) {	// handle PCNF file
		if ( wvalue != NULL ) {
			fprintf(stderr, "Error: cannot write PCNF to PCNF file.");
			exit(1);
		}
		if ( argv[optind+1] != NULL ) {
			fprintf(stderr, "\nError: one PCNF file can be handled - only %s got analized.\n", argv[optind]);
			exit(1);
		}
		freadpcnfcnt(fd);
		if ( jfd != NULL ) {
			fprintf(jfd, "{\"raws\":[");
			fprintraws(fd, jfd);
			fprintf(jfd, "],\"singles\":[");
			fprintsingles(fd, jfd);
			fprintf(jfd, "],\"links\":[");
			fprintlinks(fd, jfd);
			fprintf(jfd, "],\"ports\":[");
			fprintports(fd, jfd);
			fprintf(jfd, "],\"bilinks\":[");
			fprintbilinks(fd, jfd);
			fprintf(jfd, "]}\n");
		}
		switch (output) {
			case 'v':	fprintraws(fd, NULL); break;
			case 's':	fprintsingles(fd, NULL); break;
			case 'l':	fprintlinks(fd, NULL); break;
			case 'p':	fprintports(fd, NULL);	break;
			case 'b': 	fprintbilinks(fd, NULL);
		}
		exit(0);
	}
	fclose(fd);
	raws_ptr = malloc(size_rawset);	// allocate ram for the arrays to store data
	singles_ptr = malloc(size_singleset);
	links_ptr = malloc(size_linkset);
	ports_ptr = malloc(size_portset);
	bilinks_ptr = malloc(size_bilinkset);
	if ( ( raws_ptr == NULL )	// just in case...
	|| ( singles_ptr == NULL )
	|| ( links_ptr == NULL )
	|| ( ports_ptr == NULL )
	|| ( bilinks_ptr == NULL ) ) memerror();
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
		workpcap(fd, magic_number);
		fclose(fd);	// close pcap file
	}
	if ( raws_cnt > 0 ) {	// without ip traffic nothing is to generate
		sortraws();
		if ( ( wvalue != NULL ) || ( jvalue != NULL ) ) {	// generate statistics
			gensingles();
			genlinks();
			genports();
			genbilinks();
			if ( wvalue != NULL ) {	// -w
				fwritepcnf(pfd);	// write pcnf output file
				fclose(pfd);	// close output pcnf file
			}
			if ( jvalue != NULL ) {	// -j
				fwritejson(jfd);	// write json file
				fclose(jfd);	// close json file
			}
			printsets(output);
			exit(0);
		}
		switch (output) {	// calculate data to print desired sets to stdout
			case 'v':	break;
			case 'l':	genlinks(); break;
			case 'p':	genports(); break;
			case 'b':	genlinks(); genbilinks(); break;
			default: 	gensingles(); break;
		}
	}
	printsets(output);
	exit(0);
}
