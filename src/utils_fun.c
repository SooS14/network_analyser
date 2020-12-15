
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
 */
void print_ip_addr(bpf_u_int32 ip) {
        struct ip_addr *ptr=(struct ip_addr*)&ip;
        printf ("%d.%d.%d.%d\n", ptr->one,ptr->two,ptr->three,ptr->four);
}



/**
 * @brief prints size hexadecimal caracters from payload
 * 
 * @param payload array containing the caracters
 * @param size the number of caracters to be printed
 */
void print_hex(const unsigned char *payload, int size)
{
	const unsigned char *ptr = payload;
	unsigned char trad_ascii[16];

	printf("0    ");
	for (int i = 1; i < size; i++)
	{
		printf("%02x ", *ptr);
		trad_ascii[(i-1)%16] = *ptr;
		ptr++;

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