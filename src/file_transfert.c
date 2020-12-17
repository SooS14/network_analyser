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
    int test = 0;

    if (strstr(payload, "USER") != NULL)
	{
		printf("USER, ");
        test = 1;
	}
    if (strstr(payload, "PASS") != NULL)
	{
		printf("PASS, ");
        test = 1;
	}
    if (strstr(payload, "ACCT") != NULL)
	{
		printf("ACCT, ");
        test = 1;
    }
    if (strstr(payload, "CWD") != NULL)
	{
		printf("CWD, ");
        test = 1;
	}
    if (strstr(payload, "CDUP") != NULL)
	{
		printf("CDUP, ");
        test = 1;
	}
    if (strstr(payload, "QUIT") != NULL)
	{
		printf("QUIT, ");
        test = 1;
	}
    if (strstr(payload, "PORT") != NULL)
	{
		printf("PORT, ");
        test = 1;
	}
    if (strstr(payload, "PASV") != NULL)
	{
		printf("PASV, ");
        test = 1;
	} 
    if (strstr(payload, "TYPE") != NULL)
	{
		printf("TYPE, ");
        test = 1;
	} 
    if (strstr(payload, "RETR") != NULL)
	{
		printf("RETR, ");
        test = 1;
	} 
    if (strstr(payload, "STOR") != NULL)
	{
		printf("STOR, ");
        test = 1;
	} 
    if (strstr(payload, "APPE") != NULL)
	{
		printf("APPE, ");
        test = 1;
	} 
    if (strstr(payload, "REST") != NULL)
	{
		printf("REST, ");
        test = 1;
	} 
    if (strstr(payload, "RNFR") != NULL)
	{
		printf("RNFR, ");
        test = 1;
	} 
    if (strstr(payload, "RNTO") != NULL)
	{
		printf("RNTO, ");
        test = 1;
	}
    if (strstr(payload, "ABOR") != NULL)
	{
		printf("ABOR, ");
        test = 1;
	}
    if (strstr(payload, "DELE") != NULL)
	{
		printf("DELE, ");
        test = 1;
	}
    if (strstr(payload, "RMD") != NULL)
	{
		printf("RMD, ");
        test = 1;
	}
    if (strstr(payload, "MKD") != NULL)
	{
		printf("MKD, ");
        test = 1;
	}
    if (strstr(payload, "PWD") != NULL)
	{
		printf("PWD, ");
        test = 1;
	}
    if (strstr(payload, "LIST") != NULL)
	{
		printf("LIST, ");
        test = 1;
	}
    if (strstr(payload, "SITE") != NULL)
	{
		printf("SITE, ");
        test = 1;
	}
    if (strstr(payload, "SYST") != NULL)
	{
		printf("SYST, ");
        test = 1;
	}
    if (strstr(payload, "STAT") != NULL)
	{
		printf("STAT, ");
        test = 1;
	}
    if (strstr(payload, "HELP") != NULL)
	{
		printf("HELP, ");
        test = 1;
	}
    if (strstr(payload, "NOOP") != NULL)
	{
		printf("NOOP, ");
        test = 1;
	}

    if (!test)
    {
        printf("none");
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
    else
    {
        printf("none");
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
        printf(" ; code : ");
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