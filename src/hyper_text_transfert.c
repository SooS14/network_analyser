#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include <string.h>
#include "utils_fun.h"




/**
 * @brief prints http command
 * 
 * @param data is a struct the applicative data
 */
void http_req(const u_char * data)
{

    const char *payload = (const char *) data;

    if (strstr(payload, "GET") != NULL)
	{
		printf("GET, ");
	}
    if (strstr(payload, "HEAD") != NULL)
	{
		printf("HEAD, ");
	}
    if (strstr(payload, "POST") != NULL)
	{
		printf("POST, ");
	}
    if (strstr(payload, "OPTIONS") != NULL)
	{
		printf("OPTIONS, ");
	}
    if (strstr(payload, "PUT") != NULL)
	{
		printf("PUT, ");
	}
    if (strstr(payload, "DELETE") != NULL)
	{
		printf("DELETE, ");
	}
    if (strstr(payload, "TRACE") != NULL)
	{
		printf("TRACE, ");
	}
    if (strstr(payload, "OK") != NULL)
	{
		printf("OK, ");
	}
}


/**
 * @brief prints HTTP version
 * 
 * @param data is a struct the applicative data
 */
void http_ver(const u_char * data)
{
    const char *payload = (const char *) data;

    if (strstr(payload, "HTTP/1.0") != NULL)
	{
		printf("HTTP/1.0, ");
	}
    if (strstr(payload, "HTTP/1.1") != NULL)
	{
		printf("HTTP/1.1, ");
	}
    if (strstr(payload, "HTTP/2") != NULL)
	{
		printf("HTTP/2, ");
	}
}


/**
 * @brief process the HTTP header
 * 
 * @param data is a struct the applicative data
 * @param app_len size of the applicative data
 * @param verbose
 */
void http_pkt(u_char * verbose, const u_char *data, int app_len)
{
    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf("HTTP");
        break;

    case 2:
        printf("\n-> http header \n");
        printf("cmd : ");
        http_req(data);
        printf("ver : ");
        http_ver(data);
        printf("\n");
        break;

    case 3:
        printf("\n");
        printf("\n########## http header ##########\n");
        printf("Commande : ");
        http_req(data);
        printf("\n"); 
        printf("Version : ");
        http_ver(data);
        printf("\n"); 
        print_hex(data, app_len);    
        break;
    
    default:
        fprintf(stderr, "error switch http_pkt function");
        break;
    }
}