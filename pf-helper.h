#ifndef REDSOCKS_PF_HELPER_H
#define REDSOCKS_PF_HELPER_H
#include <netinet/in.h>
int pf_helper_start(int pf);
int pf_helper_lookup(int channel, int connection, struct sockaddr_in *destination);
void pf_helper_stop(int channel);
#endif
