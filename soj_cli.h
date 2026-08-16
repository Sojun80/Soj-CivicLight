#ifndef SOJ_CLI_H
#define SOJ_CLI_H

#include <getopt.h>

extern struct option const options[];
extern const char          short_options[];

void show_usage_and_exit(int status);
void parse_arg(int key, char *arg);
void parse_config(json_t *config, char *ref);
void parse_cmdline(int argc, char *argv[]);

#endif
