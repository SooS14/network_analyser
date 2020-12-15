#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include <string.h>
#include "utils_fun.h"


void smtp_cmd(const u_char * packet)
{
    const char *payload = (const char *) packet;

	if (strstr(payload, "HELO") != NULL)
	{
		printf("HELO, ");
	}
	if (strstr(payload, "MAIL") != NULL)
	{
		printf("MAIL, ");
	}
	if (strstr(payload, "RCPT") != NULL)
	{
		printf("RCPT, ");
	}
	if (strstr(payload, "DATA") != NULL)
	{
		printf("DATA, ");
	}
	if (strstr(payload, "QUIT") != NULL)
	{
		printf("QUIT, ");
	}
	if (strstr(payload, "EHLO") != NULL)
	{
		printf("EHLO -> ESMTP, ");
	}
}


void esmtp_ext(const u_char * packet)
{
    const char *payload = (const char *) packet;

	if (strstr(payload, "8BITMIME") != NULL)
	{
		printf("8BITMIME, ");
	}
	if (strstr(payload, "SIZE") != NULL)
	{
		printf("SIZE, ");
	}
	if (strstr(payload, "DSN") != NULL)
	{
		printf("DSN, ");
	}
	if (strstr(payload, "ONEX") != NULL)
	{
		printf("ONEX, ");
	}
	if (strstr(payload, "ETRN") != NULL)
	{
		printf("ETRN, ");
	}
	if (strstr(payload, "XUSR") != NULL)
	{
		printf("XUSR, ");
	}
	if (strstr(payload, "HELP") != NULL)
	{
		printf("HELP, ");
	}
}


void smtp_v2(const u_char *packet)
{
    printf("\n-> smtp header \n");
    smtp_cmd(packet);
    printf("\n");
    esmtp_ext(packet);
    printf("\n");
}



void smtp_v3(const u_char *packet, int app_len)
{
    printf("\n");
    printf("\n########## smtp header ##########\n");
    smtp_cmd(packet);
    printf("\n");
    esmtp_ext(packet);
    printf("\n"); 
    
    print_hex(packet, app_len);
}



void smtp_pkt(u_char * verbose, const u_char *packet, int app_len)
{

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf("POP");
        break;

    case 2:
        smtp_v2(packet);
        break;

    case 3:
        smtp_v3(packet, app_len);
        break;
    
    default:
        fprintf(stderr, "error switch smtp_pkt function");
        break;
    }
}