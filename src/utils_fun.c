
#include <pcap/pcap.h>
#include "utils_fun.h"
#include <ctype.h>
#include <math.h>
#include <stdio.h>


/**
 * @brief print an ip adrress under a recognisable form 
 *
 * This function uses a cast to fill 4 slots in a struct representing an IPv4 address
 * 
 * @param ip the ip address to be printed
 * 
 */
void print_ip_addr(bpf_u_int32 ip) {
        struct ip_addr *ptr=(struct ip_addr*)&ip;
        printf ("%d.%d.%d.%d\n", ptr->one,ptr->two,ptr->three,ptr->four);
}






/**
 * @brief print n hex caracter 
 * 
 * 
 */
void print_hex(const unsigned char *payload, int payload_size)
{
	const unsigned char *temp_pay = payload;
	unsigned char trad_ascii[16];

	printf("0    ");
	for (int i = 1; i < payload_size; i++)
	{
		printf("%02x ", *temp_pay);
		trad_ascii[(i-1)%16] = *temp_pay;
		temp_pay++;

		if ((i % 16) == 0)
		{
			printf("    ");
			for (int j = 0; j < 16; j++)
			{
				if (isprint(trad_ascii[j]))
				{
					printf("%c", trad_ascii[j]);
				}
				else
				{
					printf(".");
				}
				
			}
			printf("\n%i    ", i);
		}
		
	}
	printf("\n");
	printf("\n");
}


/**
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", ntohs(*ch));
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}



/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}