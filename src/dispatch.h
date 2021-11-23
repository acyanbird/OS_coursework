#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(unsigned char *userdata, struct pcap_pkthdr *header,
              const unsigned char *packet);

#endif
