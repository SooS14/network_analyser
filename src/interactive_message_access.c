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
    int test = 0;
    const char *payload = (const char *) data;
    
	if (strstr(payload, "LOGIN") != NULL)
	{
		printf("response : LOGIN, ");
        test = 1;
	}
    if (strstr(payload, "IDLE") != NULL)
	{
		printf("response : IDLE, ");
        test = 1;
	}
	if (strstr(payload, "SELECT") != NULL)
	{
		printf("response : SELECT, ");
        test = 1;
	}
	if (strstr(payload, "LOGOUT") != NULL)
	{
		printf("response : LOGOUT, ");
        test = 1;
	}
	if (strstr(payload, "NOOP") != NULL)
	{
		printf("response : NOOP, ");
        test = 1;
	}
	if (strstr(payload, "LIST") != NULL)
	{
		printf("response : LIST, ");
        test = 1;
	}
	if (strstr(payload, "CREATE") != NULL)
	{
		printf("response : CREATE, ");
        test = 1;
	}
	if (strstr(payload, "DELETE") != NULL)
	{
		printf("response : DELETE, ");
        test = 1;
	}
	if (strstr(payload, "RENAME") != NULL)
	{
		printf("response : RENAME, ");
        test = 1;
	}
	if (strstr(payload, "APPEND") != NULL)
	{
		printf("response : APPEND, ");
        test = 1;
	}
	if (strstr(payload, "FETCH") != NULL)
	{
		printf("response : FETCH, ");
        test = 1;
	}
	if (strstr(payload, "UID") != NULL)
	{
		printf("response : UID, ");
        test = 1;
	}
	if (strstr(payload, "COPY") != NULL)
	{
		printf("response : COPY, ");
        test = 1;
	}
	if (strstr(payload, "STORE") != NULL)
	{
		printf("STORE, ");
        test = 1;
	}


	if (strstr(payload, "login") != NULL)
	{
		printf("request : login, ");
        test = 1;
	}
    if (strstr(payload, "idle") != NULL)
	{
		printf("request : idle, ");
        test = 1;
	}
	if (strstr(payload, "select") != NULL)
	{
		printf("request : select, ");
        test = 1;
	}
	if (strstr(payload, "logout") != NULL)
	{
		printf("request : logout, ");
        test = 1;
	}
	if (strstr(payload, "noop") != NULL)
	{
		printf("request : noop, ");
        test = 1;
	}
	if (strstr(payload, "list") != NULL)
	{
		printf("request : list, ");
        test = 1;
	}
	if (strstr(payload, "create") != NULL)
	{
		printf("request : create, ");
        test = 1;
	}
	if (strstr(payload, "delete") != NULL)
	{
		printf("request : delete, ");
        test = 1;
	}
	if (strstr(payload, "rename") != NULL)
	{
		printf("request : rename, ");
        test = 1;
	}
	if (strstr(payload, "append") != NULL)
	{
		printf("request : append, ");
        test = 1;
	}
	if (strstr(payload, "fetch") != NULL)
	{
		printf("request : fetch, ");
        test = 1;
	}
	if (strstr(payload, "uid") != NULL)
	{
		printf("request : uid, ");
        test = 1;
	}
	if (strstr(payload, "copy") != NULL)
	{
		printf("request : copy, ");
        test = 1;
	}
	if (strstr(payload, "store") != NULL)
	{
		printf("request : store, ");
        test = 1;
	}

    if (!test)
    {
        printf("none");
    }
    printf("\n");

    if ((payload[0] >= 49) && (payload[0] <= 53))
    {
        int count = 1;
        while ((payload[count] >= 49) && (payload[count] <= 53))
        {
            count++;
        }
        printf("Tag : ");
        for (int i = 0; i <= count; i++)
        {
            printf("%c", payload[i]);
        }
        printf("\n");
        
        test = 1;
    }
    
	if (strstr(payload, "OK") != NULL)
	{
		printf("status : OK\n");
        test = 1;
	}
	if (strstr(payload, "NO") != NULL)
	{
		printf("status : NO\n");
        test = 1;
	}
	if (strstr(payload, "BAD") != NULL)
	{
		printf("status = BAD\n");
        test = 1;
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
        imap_cmd(data);
        printf("\n");
        break;

    case 3:
        printf("\n");
        printf("\n########## imap header ##########\n");
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
