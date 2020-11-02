#ifndef ARGS_H
#define ARGS_H

typedef enum flags_t {
    NO_FLAGS = 0,
    LIVE_ANALYSE = 1,
    OFFLINE_ANALYSE = 1 << 1,
    FILTER = 1 << 2,
} flags_t;

typedef struct args_t {
    char * interface;
    char * file_path;
    char * filter;
    int verbose_lev;
    flags_t flags;
} args_t;


/**
 * @brief Parse les arguments de ligne de commande
 * et definie les attributs de game en fonction.
 * @param argc (standard main argument)
 * @param argv (standard main argument)
 * @param args will receive the argument values
 * @return OK if everything went well or ERROR_* if there was an error
 */
int
parse_args(int argc,  char ** argv, args_t *args);


/**
 * @brief print the usage
 */
void
print_usage(void);


#endif
