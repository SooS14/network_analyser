#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include <string.h>
#include "utils_fun.h"



/**
 * @brief prints the IMAP command
 * 
 * @param data is a struct the applicative data
 */
void imap_cmd(const u_char * data)
{
    const char *payload = (const char *) data;

	if (strstr(payload, "LOGIN") != NULL)
	{
		printf("LOGIN, ");
	}
	if (strstr(payload, "SELECT") != NULL)
	{
		printf("SELECT, ");
	}
	if (strstr(payload, "LOGOUT") != NULL)
	{
		printf("LOGOUT, ");
	}
	if (strstr(payload, "NOOP") != NULL)
	{
		printf("NOOP, ");
	}
	if (strstr(payload, "LIST") != NULL)
	{
		printf("LIST, ");
	}
	if (strstr(payload, "CREATE") != NULL)
	{
		printf("CREATE, ");
	}
	if (strstr(payload, "DELETE") != NULL)
	{
		printf("DELETE, ");
	}
	if (strstr(payload, "RENAME") != NULL)
	{
		printf("RENAME, ");
	}
	if (strstr(payload, "APPEND") != NULL)
	{
		printf("APPEND, ");
	}
	if (strstr(payload, "FETCH") != NULL)
	{
		printf("FETCH, ");
	}
	if (strstr(payload, "UID") != NULL)
	{
		printf("UID, ");
	}
	if (strstr(payload, "COPY") != NULL)
	{
		printf("COPY, ");
	}
	if (strstr(payload, "STORE") != NULL)
	{
		printf("STORE, ");
	}
	if (strstr(payload, " OK ") != NULL)
	{
		printf("OK, ");
	}
}



/**
 * @brief process the IMAP data
 * 
 * @param data is a struct the applicative data
 * @param app_len size of the applicative data
 * @param verbose
 */
void imap_pkt(u_char * verbose, const u_char *data, int app_len)
{

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf("IMAP");
        break;

    case 2:
        printf("\n-> imap header \n");
        printf("cmd : ");
        imap_cmd(data);
        printf("\n");
        break;

    case 3:
        printf("\n");
        printf("\n########## imap header ##########\n");
        printf("command : ");
        imap_cmd(data);
        printf("\n");
        printf("\n"); 
        print_hex(data, app_len);
        break;
    
    default:
        fprintf(stderr, "error switch imap_pkt function");
        break;
    }
}
