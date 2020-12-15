#include "args_parser.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>



/**
 * @brief Parse the arguments in the command ligne
 *
 * Retreive options using getopt function. Options are stored in args_t struct.
 * args->flags is a quick way to know what are the available informations
 * 
 * @param argc (standard main argument)
 * @param argv (standard main argument)
 * @param args will receive the argument values
 * 
 */
void parse_args(int argc,  char ** argv, args_t *args)
{
    args->interface = NULL;
    args->file_path = NULL;
    args->flags = NO_FLAGS;
    args->filter = NULL;
    args->loop = 0;
    args->verbose_lev = "1";
    

    opterr = 0;
    int c;

    while ((c = getopt (argc, argv, "hi:o:f:v:l:")) != -1)
    {
        switch (c)
        {
            case 'h':
              print_usage();
              exit(0);
            case 'i':
                args->interface = optarg;
                args->flags |= LIVE_ANALYSE;
                break;
            case 'o':
                args->file_path = optarg;
                args->flags |= OFFLINE_ANALYSE;
                break;
            case 'f':
                args->filter = optarg;
                args->flags |= FILTER;
                break;
            case 'l':
                args->loop = atoi(optarg);
                args->flags |= LOOP;
                break;
            case 'v':
                if ((strncmp(optarg, "1", 2) != 0) &&
                    (strncmp(optarg, "2", 2) != 0) &&
                    (strncmp(optarg, "3", 2) != 0) &&
                    (strncmp(optarg, "4", 2) != 0))
                {
                    fprintf(stderr, "Unknown verbose level %s \n", optarg);
                    exit(1);
                }

                args->verbose_lev = optarg;
                
                break;
                
            case '?':

                if (optopt == 'i' || optopt == 'o' || optopt == 'f' || optopt == 'v')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                {
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                }
                else
                {
                    fprintf (stderr,
                    "Unknown option character `\\x%x'.\n",
                    optopt);
                } 

                print_usage();
                exit(1);

            default:
                fprintf (stderr,
                    "Unknown option character `%c'.\n",
                    c);
                print_usage();
                exit(1);
        }
    }

}






/**
 * @brief print available options
 * 
 */
void print_usage(void)
{
  puts(
  "Usage:\n"

  "-i <interface> :   interface for live analyse\n"
  "-o <fichier> :     file for offline analyse\n"
  "-f <filtre> :      GMP filter (optional)\n"
  "-v <1..4> :        verbosity level\n"
  "                   (1=very concise ; 2=concise ; 3=complete ; 4=full_frame)\n"
  "                   verbosity is set to very concise by default\n"
  "-l <number> :      number of packet to analyse, by default the\n"
  "                   analyse stops when there's no more packet\n"
  "-h                 print help\n");
}
