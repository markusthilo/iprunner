#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <inttypes.h>

/* Structure for IP address */
struct ipaddr {
	uint64_t addr[2];
};

char * mkstr(char * str1, const char * str2) {
	printf("str1: >%s< ", str1);
	printf("str2: >%s<\n", str2);
	strcat(str1, str2);
//	sprintf(str1, "String >%s< has length %ld", str2, strlen(str2));
	return str1;
}

void printel(int * pointer){
	printf("%d\n", * pointer);
}


int main() {
	long long unsigned llu = 0xfffffffffffffffff;
	printf("0x%llx = %llu\n", llu, llu);
//	printel(&a[2]);
//	char string[40] = "1faf:2cde::5678:11af:2def:1234:78-";
//	long b;
//	int p = 0;
//	b = hexbytes2long(string, &p);
//	printf(">%s< = %lx, position = %d\n", string, b, p);
//	struct ipaddr v6 = str2ip(string);
//	printf("v6: %" PRIx64 " %" PRIx64 "\n", v6.addr[0], v6.addr[1]);
	exit(0);
}
