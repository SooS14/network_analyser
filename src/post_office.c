#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include <string.h>
#include "utils_fun.h"



/**
 * @brief prints the POP command
 * 
 * @param data is a struct the applicative data
 */
void pop_cmd(const u_char * data)
{
    const char *payload = (const char *) data;
    int test = 0;

	if (strstr(payload, "USER") != NULL)
	{
		printf("USER, ");
        test = 1;
	}
	if (strstr(payload, "STLS") != NULL)
	{
		printf("STLS, ");
        test = 1;
	}
	if (strstr(payload, "PASS") != NULL)
	{
		printf("PASS, ");
        test = 1;
	}
	if (strstr(payload, "STAT") != NULL)
	{
		printf("STAT, ");
        test = 1;
	}
	if (strstr(payload, "LIST") != NULL)
	{
		printf("LIST, ");
        test = 1;
	}
	if (strstr(payload, "UIDL") != NULL)
	{
		printf("UIDL, ");
        test = 1;
	}
	if (strstr(payload, "RETR") != NULL)
	{
		printf("RETR, ");
        test = 1;
	}
	if (strstr(payload, "DELE") != NULL)
	{
		printf("DELE, ");
        test = 1;
	}
	if (strstr(payload, "TOP") != NULL)
	{
		printf("TOP, ");
        test = 1;
	}
	if (strstr(payload, "LAST") != NULL)
	{
		printf("LAST, ");
        test = 1;
	}
	if (strstr(payload, "RSET") != NULL)
	{
		printf("RSET, ");
        test = 1;
	}
	if (strstr(payload, "NOOP") != NULL)
	{
		printf("NOOP, ");
        test = 1;
	}
	if (strstr(payload, "QUIT") != NULL)
	{
		printf("QUIT, ");
        test = 1;
	}
	if (strstr(payload, "+OK") != NULL)
	{
		printf("+OK, ");
        test = 1;
	}
	if (strstr(payload, "-ERR") != NULL)
	{
		printf("-ERR, ");
        test = 1;
	}
    if (!test)
    {
        printf("none");
    }
    
}




/**
 * @brief process the POP data
 * 
 * @param data is a struct the applicative data
 * @param app_len size of the applicative data
 * @param verbose
 */
void pop_pkt(u_char * verbose, const u_char *data, int app_len)
{

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf(" POP");
        break;

    case 2:
        printf("\n-> pop header \n");
        printf("cmd : ");
        pop_cmd(data);
        printf("\n");
        break;

    case 3:
        printf("\n");
        printf("\n########## pop header ##########\n");
        printf("command : ");
        pop_cmd(data);
        printf("\n");
        printf("\n");
        print_hex(data, app_len);
        break;
    
    default:
        fprintf(stderr, "error switch pop_pkt function");
        break;
    }
}