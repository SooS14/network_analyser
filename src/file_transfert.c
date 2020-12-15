#include <pcap/pcap.h>
#include "header_def.h"
#include <stdlib.h>
#include <string.h>
#include "utils_fun.h"




/**
 * @brief prints ftp command
 * 
 * @param data is a struct the applicative data
 */
void ftp_cmd(const u_char * data)
{
    const char *payload = (const char *) data;

    if (strstr(payload, "USER") != NULL)
	{
		printf("USER, ");
	}
    if (strstr(payload, "PASS") != NULL)
	{
		printf("PASS, ");
	}
    if (strstr(payload, "ACCT") != NULL)
	{
		printf("ACCT, ");
	}
    if (strstr(payload, "CWD") != NULL)
	{
		printf("CWD, ");
	}
    if (strstr(payload, "CDUP") != NULL)
	{
		printf("CDUP, ");
	}
    if (strstr(payload, "QUIT") != NULL)
	{
		printf("QUIT, ");
	}
    if (strstr(payload, "PORT") != NULL)
	{
		printf("PORT, ");
	}
    if (strstr(payload, "PASV") != NULL)
	{
		printf("PASV, ");
	} 
    if (strstr(payload, "TYPE") != NULL)
	{
		printf("TYPE, ");
	} 
    if (strstr(payload, "RETR") != NULL)
	{
		printf("RETR, ");
	} 
    if (strstr(payload, "STOR") != NULL)
	{
		printf("STOR, ");
	} 
    if (strstr(payload, "APPE") != NULL)
	{
		printf("APPE, ");
	} 
    if (strstr(payload, "REST") != NULL)
	{
		printf("REST, ");
	} 
    if (strstr(payload, "RNFR") != NULL)
	{
		printf("RNFR, ");
	} 
    if (strstr(payload, "RNTO") != NULL)
	{
		printf("RNTO, ");
	}
    if (strstr(payload, "ABOR") != NULL)
	{
		printf("ABOR, ");
	}
    if (strstr(payload, "DELE") != NULL)
	{
		printf("DELE, ");
	}
    if (strstr(payload, "RMD") != NULL)
	{
		printf("RMD, ");
	}
    if (strstr(payload, "MKD") != NULL)
	{
		printf("MKD, ");
	}
    if (strstr(payload, "PWD") != NULL)
	{
		printf("PWD, ");
	}
    if (strstr(payload, "LIST") != NULL)
	{
		printf("LIST, ");
	}
    if (strstr(payload, "SITE") != NULL)
	{
		printf("SITE, ");
	}
    if (strstr(payload, "SYST") != NULL)
	{
		printf("SYST, ");
	}
    if (strstr(payload, "STAT") != NULL)
	{
		printf("STAT, ");
	}
    if (strstr(payload, "HELP") != NULL)
	{
		printf("HELP, ");
	}
    if (strstr(payload, "NOOP") != NULL)
	{
		printf("NOOP, ");
	}
}



/**
 * @brief prints ftp code
 * 
 * @param data is a struct the applicative data
 */
void ftp_code(const u_char * data)
{
    if (((data[0] >= 49) && (data[0] <= 53)) &&
        ((data[1] >= 49) && (data[1] <= 53)))
    {
        printf(" %c%c%c", data[0], data[1], data[2]);
    }
    
}


/**
 * @brief process the ftp header
 * 
 * @param data is a struct the applicative data
 * @param app_len size of the applicative data
 * @param verbose
 */
void ftp_pkt(u_char * verbose, const u_char *data, int app_len)
{
    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf(" FTP");
        break;

    case 2:
        printf("\n-> ftp header \n");
        printf("cmd : ");
        ftp_cmd(data);
        printf(" code : ");
        ftp_code(data);
        printf("\n");
        break;

    case 3:
        printf("\n");
        printf("\n########## ftp header ##########\n");
        printf("cmd : ");
        ftp_cmd(data);
        printf("\ncode : ");
        ftp_code(data);
        printf("\n");  
        printf("\n");
        print_hex(data, app_len);
        break;
    
    default:
        fprintf(stderr, "error switch ftp_pkt function");
        break;
    }
}