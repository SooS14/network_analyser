/* compile with : gcc -o analyseur analyseur.c -lpcap */
/* use valgrind with : 

valgrind --tool=memcheck --leak-check=full ./bin/analyseur 

--track-origins=yes to see where uninitialised values come from
For lists of detected and suppressed errors, rerun with: -s
*/

// TODO : strstr bizarre - print_hex ne print pas tout - vendor spe ne marche pas


#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "args_parser.h"
#include "header_def.h"
#include "pcap_fun.h"
#include "utils_fun.h"



#define SIZE 1024





/**
 * @brief main function of the project
 *
 * This function opens the interfaces/pcap files, apply filters, and call for pcap_loop.
 * 
 * @param argc 
 * @param argv
 */
int main(int argc, char *argv[])
{

    args_t args;
    parse_args(argc, argv, &args);    


    //list of var needed to open a device
    pcap_if_t *alldevsp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    pcap_t *p;	


    //struct that is needed to use filters :
    struct bpf_program fp;


    //var used to get the ip address and mask of a device
	bpf_u_int32 mask;		
	bpf_u_int32 ip_addr;	


    //var used by pcap_loop 
    int pcap_loop_ret;


    if (args.flags && LOOP)
    {
        if (args.loop < 0)
        {
        fprintf(stderr, "err count_loop is < 0\n");
        exit(EXIT_FAILURE);
        }
    }
    

    if (!(args.flags & OFFLINE_ANALYSE))
    {

        findalldevs(&alldevsp,errbuf);

        if (!(args.flags & LIVE_ANALYSE))
        {
            printf("no file/device given. Using first device found by findalldevs :\n");
            printf("device : %s, desc : %s\n", alldevsp->name, alldevsp->description);
            device = alldevsp->name;
    
        }

        else 
        
        {
            int check_device = 0;
            pcap_if_t * ptr = alldevsp;

            while (ptr != NULL)
            {
                if (strncmp(alldevsp->name, args.interface, SIZE) == 0)
                {
                
                    printf("your device has been found within findalldevs's list, launching live analyse\n");
                    check_device = 1;
                    device = args.interface;
                    break;
                }

                ptr = ptr->next;
            
            }

            if (check_device == 0)
            {
                printf("your device hasn't been found, exiting\n");
                exit(0);
            }

        }

        open_live(device, errbuf, &p);

        datalink(&p, device);

        if (args.flags & FILTER)
        {

            lookupnet(device,&mask,&ip_addr,errbuf);

            set_filters(&p, &fp, args.filter, mask);

        }	
    }


    else
    
    
    {
        printf("using offline analyse if both -i and -o flags are present\n");
        printf("opening file for an offline analyse\n");
        if ((p = pcap_open_offline(args.file_path ,errbuf)) == NULL)
        {
            fprintf(stderr, "open_offline err, errbuf :%s\n", errbuf);
            exit(0);
        }
    }


    u_char * verbose = (u_char *) args.verbose_lev;

    if (args.flags && LOOP)
    {
        pcap_loop_ret = pcap_loop(p, args.loop, ethernet_pkt, verbose);
    }
    else
    {
        pcap_loop_ret = pcap_loop(p, -1, ethernet_pkt, verbose);
    }
    
    
    if (pcap_loop_ret == 0)
    {
        printf("count is exhausted or no more packets are available\n");
    }
    else if (pcap_loop_ret == PCAP_ERROR)
    {
        printf("err pcap_loop, loop terminated with PCAP_ERR\n");
    }
        


    pcap_close(p);


    return 0;
}
