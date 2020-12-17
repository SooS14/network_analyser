#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include "header_def.h"
#include "utils_fun.h"
#include "bootp.h"
#include <ctype.h>



/**
 * @brief prints vendor specific option
 * 
 * Vendor's specific options are stored in a char array.
 * The function goes through this array and analyse the information
 * in TLV form. Not all options are supported, see bootp.h for more details.
 * 
 * @param vend vendor specific parts of bootp header
 */
void vendor_spe(const unsigned char * vend)
{

    printf("vendor specific : ");

	if (vend[0] != 0x63 ||
        vend[1] != 0x82 ||
	    vend[2] != 0x53 ||
        vend[3] != 0x63)
	{
        printf("no  magic cookie\n");
		return;
	}

    printf("DHCP\n");
    int count = 4;
    int time = 0;

    while (count < 64)
    {
        switch (vend[count])
        {

        case DHCP_END:
            printf("----end of dhcp options\n");
            printf("----Padding : ");
            for (int i = count+1; i < 64; i++)
            {
                printf("%.2x", vend[i]);
            }
            printf("\n");
            return;


        case DHCP_SUBNET_MASK:
            printf("----subnet mask : ");
            if (vend[count+1] == 4)
            {
                printf("%i.%i.%i.%i",
                    vend[count+2],vend[count+3],
                    vend[count+4],vend[count+5]);
            }
            else
            {
                printf("0x");
                for (int i = 0; i < vend[count+1]; i++)
                {
                    printf("%.2x", vend[count+i+2]);
                }
            }
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        case DHCP_TIME_OFFSET:
            printf("----time offset : 0x");
            time = 0;
            for (int i = 0; i < vend[count+1]; i++)
            {
                time += vend[count+i+2];
            }
            printf("%i", time);
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        case DHCP_ROUTER:
            printf("----router : ");
            if (vend[count+1] == 4)
            {
                printf("%i.%i.%i.%i",
                    vend[count+2],vend[count+3],
                    vend[count+4],vend[count+5]);
            }
            else
            {
                printf("0x");
                for (int i = 0; i < vend[count+1]; i++)
                {
                    printf("%.2x", vend[count+i+2]);
                }
            }
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        case DHCP_DNS:
            printf("----dns : ");
            if (vend[count+1] == 4)
            {
                printf("%i.%i.%i.%i",
                    vend[count+2],vend[count+3],
                    vend[count+4],vend[count+5]);
            }
            else
            {
                printf("0x");
                for (int i = 0; i < vend[count+1]; i++)
                {
                    printf("%.2x", vend[count+i+2]);
                }
            }
            count = vend[count+1] + 2 + count;
            printf("\n");            
            break;

        case DHCP_HOST_NAME:
            printf("----host name : 0x");
            for (int i = 0; i < vend[count+1]; i++)
            {
                if (isprint(vend[count+i+2]))
                {
                    printf("%c", vend[count+i+2]);
                }
                else
                {
                    printf(".");
                }
            }
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        case DHCP_DOMAIN_NAME:
            printf("----domain name : 0x");
            for (int i = 0; i < vend[count+1]; i++)
            {
                if (isprint(vend[count+i+2]))
                {
                    printf("%c", vend[count+i+2]);
                }
                else
                {
                    printf(".");
                }
            }
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        case DHCP_BROADCAST_ADDR:
            printf("----broadcast addr : ");
            if (vend[count+1] == 4)
            {
                printf("%i.%i.%i.%i",
                    vend[count+2],vend[count+3],
                    vend[count+4],vend[count+5]);
            }
            else
            {
                printf("0x");
                for (int i = 0; i < vend[count+1]; i++)
                {
                    printf("%.2x", vend[count+i+2]);
                }
            }
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        case DHCP_NONS:
            printf("----netbios over TCP/IP name server : 0x");
            for (int i = 0; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[count+i+2]);
            }
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        case DHCP_NOS:
            printf("----netbios over TCP/IP scope : 0x");
            for (int i = 0; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[count+i+2]);
            }
            count = vend[count+1] + 2 + count;
            printf("\n");        
            break;

        case DHCP_REQ_IP_ADDR:
            printf("----Requested IP address : ");
            if (vend[count+1] == 4)
            {
                printf("%i.%i.%i.%i",
                    vend[count+2],vend[count+3],
                    vend[count+4],vend[count+5]);
            }
            else
            {
                printf("0x");
                for (int i = 0; i < vend[count+1]; i++)
                {
                    printf("%.2x", vend[count+i+2]);
                }
            }
            count = vend[count+1] + 2 + count;
            printf("\n");  
            break;

        case DHCP_LEASE_TIME:
            printf("----lease time : ");
            time = 0;
            for (int i = 0; i < vend[count+1]; i++)
            {
                time += vend[count+i+2];
            }
            printf("%i",time);
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        case DHCP_DHCP_MESS_TYPE:
            printf("----DHCP message type : ");

            switch (vend[count+2])
            {
            case DHCP_DISCOVER:
                printf("DISCOVER");
                break;
            
            case DHCP_OFFER:
                printf("OFFER");
                break;

            case DHCP_REQUEST:
                printf("REQUEST");
                break;

            case DHCP_DECLINE:
                printf("DECLINE");
                break;

            case DHCP_ACK:
                printf("ACK");
                break;

            case DHCP_NAK:
                printf("NAK");
                break;

            case DHCP_RELEASE:
                printf("RELEASE");
                break;

            default:
                break;
            }

            count = count + 3;
            printf("\n");
            break;

        case DHCP_SERV_ID:
            printf("----Server identifier : ");
            if (vend[count+1] == 4)
            {
                printf("%i.%i.%i.%i",
                    vend[count+2],vend[count+3],
                    vend[count+4],vend[count+5]);
            }
            else
            {
                printf("0x");
                for (int i = 0; i < vend[count+1]; i++)
                {
                    printf("%.2x", vend[count+i+2]);
                }
            }
            count = vend[count+1] + 2 + count;
            printf("\n");          
            break;

        case DHCP_PARAM_REQ_LST:
            printf("----Parameters request list :\n");
            for (int i = 0; i < vend[count+1]; i++)
            {
                switch (vend[count+2+i])
                {
                case DHCP_REQ_SUBNET_MSK:
                    printf("    ~~~~DHCP_REQ_SUBNET_MSK\n");
                    break;

                case DHCP_REQ_DOMAIN_NAME:
                    printf("    ~~~~DHCP_REQ_DOMAIN_NAME\n");
                    break;

                case DHCP_REQ_ROUTER:
                    printf("    ~~~~DHCP_REQ_ROUTER\n");
                    break;

                case DHCP_REQ_NONS:
                    printf("    ~~~~DHCP_REQ_NONS\n");
                    break;

                case DHCP_REQ_NNT:
                    printf("    ~~~~DHCP_REQ_NNT\n");
                    break;

                case DHCP_REQ_NOS:
                    printf("    ~~~~DHCP_REQ_NOS\n");
                    break;

                case DHCP_REQ_DNS:
                    printf("    ~~~~DHCP_REQ_DNS\n");
                    break;

                default:
                    printf("    ~~~~requested parameter not supported\n");
                    break;
                }
            }
            count = vend[count+1] + 2 + count;

            break;

        case DHCP_CLIENT_ID:
            printf("----Client identifier : 0x");
            for (int i = 0; i < vend[count+1]; i++)
            {
                printf("%.2x", vend[count+i+2]);
            }
            count = vend[count+1] + 2 + count;
            printf("\n");
            break;

        default:
            printf("----Option not supported : 0x%.2x\n", vend[count]);
            count=count+vend[count+1]+2;
            break;
        }

    }

}


/**
 * @brief prints some informations in the BOOTP header
 * 
 * @param bootp is a struct representing the BOOTP header
 */
void bootp_v2(const struct bootp_head *bootp)
{
    printf("\n-> bootp header \n");
	printf("ciaddr : %s ", inet_ntoa(bootp->ciaddr));
	printf("yiaddr : %s ", inet_ntoa(bootp->yiaddr));
	printf("siaddr : %s ", inet_ntoa(bootp->siaddr));
}


/**
 * @brief prints all informations in the BOOTP header
 * 
 * @param bootp is a struct representing the BOOTP header
 */
void bootp_v3(const struct bootp_head *bootp)
{
    printf("\n");
    printf("\n############# bootp header ############\n");

    printf("Opcode : ");
    if (bootp->op == BOOTP_REPLY)
    {
        printf("reply");
    }
    else if (bootp->op == BOOTP_REQUEST)
    {
        printf("request");
    }
	printf("\nHardware address type : %i\n", bootp->htype);
	printf("Hardware address lenght : %i\n", bootp->hlen);
	printf("Gateway hops : %u\n", bootp->hops);
	printf("Transaction ID : 0x%x\n", ntohl(bootp->xid));
	printf("Seconds since beginning : %i \n", ntohs(bootp->secs));
	printf("Flags : 0x%.2x\n", ntohs(bootp->flags));
	printf("Client address : %s\n", inet_ntoa(bootp->ciaddr));
	printf("Your address : %s\n", inet_ntoa(bootp->yiaddr));
	printf("Server address : %s\n", inet_ntoa(bootp->siaddr));
	printf("Gateway address : %s\n", inet_ntoa(bootp->giaddr));
	printf("Client hardware address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            bootp->chaddr[0],bootp->chaddr[1],bootp->chaddr[2],
            bootp->chaddr[3],bootp->chaddr[4],bootp->chaddr[5]);
    printf("Server Name : %s\n", bootp->sname);
    printf("File name : %s\n", bootp->file);
    vendor_spe(bootp->vend); //NE MARCHE PAS WHILE INF À VOIR
}


/**
 * @brief process the bootp header
 * 
 * @param data is a struct the applicative data
 * @param app_len size of the applicative data
 * @param verbose
 */
void bootp_pkt(u_char * verbose, const u_char *data, int len_ip)
{
    const struct bootp_head *bootp;
    bootp = (const struct bootp_head*) data;

    int verb = atoi((const char *) verbose);
    switch (verb)
    {
    case 1:
        printf(" BOOTP");
        break;

    case 2:
        bootp_v2(bootp);
        break;

    case 3:
        bootp_v3(bootp);
        break;
    
    default:
        fprintf(stderr, "error switch bootp_pkt function");
        break;
    }

}
