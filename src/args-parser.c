#include "args-parser.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int
parse_args(int argc,  char ** argv, args_t *args)
{
    args->interface = NULL;
    args->file_path = NULL;
    args->flags = NO_FLAGS;
    args->filter = NULL;
    args->verbose_lev = 0;

    opterr = 0;
    int c;

    while ((c = getopt (argc, argv, "hi:o:f:v:")) != -1)
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
            case 'v':
                args->verbose_lev = atoi(optarg);
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


void
print_usage(void)
{
  puts(
  "Usage:\n"

  "-i <interface> :   interface pour l’analyse live\n"
  "-o <fichier> :     fichier d’entrée pour l’analyse offline\n"
  "-f <filtre> :      filtre BPF (optionnel)\n"
  "-v <1..3> :        niveau de verbosité\n"
  "                   (1=très concis ; 2=synthétique ; 3=complet)\n"
  "-h                 afficher l'aide\n");
}
