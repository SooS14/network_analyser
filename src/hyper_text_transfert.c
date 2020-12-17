#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include <string.h>
#include "utils_fun.h"




void http_status(const u_char * data)
{
    const char * payload = (const char *) data;
    int count = 0;
    int len = strlen(payload);

    if (strstr(payload,"HTTP/") != NULL)
    {
        while ((payload[count] != '\r') && (payload[count+1] != '\n'))
        {
            printf("%c",payload[count]);
            count++;
            if (count >= len)
            {
                break;
            }
        }
    }
}


void print_field(const char *payload, const char * needle)
{
    char * ptr;
    int len = strlen(payload);
    int count = 0;
    
    if ((ptr = strstr(payload, needle)) != NULL)
	{
        while ((*ptr != '\r') && (*(ptr+1) != '\n'))
        {
            putc(*ptr,stdout);
            ptr++;
            count++;
            if (count >= len)
            {
                break;
            }
        }
        printf("\n");

	}
}


/**
 * @brief prints HTTP headers
 * 
 * @param data is a struct the applicative data
 */
void http_head(const u_char * data)
{
    const char *payload = (const char *) data;

    print_field(payload,"Connection");
    print_field(payload,"Date");
    print_field(payload,"Accept");
    print_field(payload,"Accept-Encoding");
    print_field(payload,"Accept-Charset");
    print_field(payload,"Accept-Language");
    print_field(payload,"Cookie");
    print_field(payload,"Host");
    print_field(payload,"If-Modified-Since");
    print_field(payload,"Range");
    print_field(payload,"Referer");
    print_field(payload,"User-Agent");
    print_field(payload,"Accept-Range");
    print_field(payload,"Age");
    print_field(payload,"Set-Cookie");
    print_field(payload,"Last-Modified");
    print_field(payload,"Content-Length");
    print_field(payload,"Content-Range");
    print_field(payload,"Content-Transfert-Encoding");
    print_field(payload,"Content-Type");
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
        http_status(data);
        printf("\n");
        break;

    case 3:
        printf("\n");
        printf("\n########## http header ##########\n");
        http_status(data);
        printf("\n"); 
        http_head(data);
        printf("\n");
        print_hex(data, app_len);
        break;
    
    default:
        fprintf(stderr, "error switch http_pkt function");
        break;
    }
}