#ifndef ARGS_H
#define ARGS_H


#define V_CONCISE 0
#define CONCISE 1
#define COMPLETE 2


typedef enum flags_t {
    NO_FLAGS = 0,
    LIVE_ANALYSE = 1,
    OFFLINE_ANALYSE = 1 << 1,
    FILTER = 1 << 2,
    LOOP = 1 << 3,
} flags_t;

typedef struct args_t {
    char * interface;
    char * file_path;
    char * filter;
    char * verbose_lev;
    unsigned int loop;
    flags_t flags;
} args_t;




void parse_args(int argc,  char ** argv, args_t *args);



void print_usage(void);


#endif
