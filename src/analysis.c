#include "analysis.h"

#include <pcap.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <malloc.h>

extern int syn; // for syn attack, count for syn pack and ip
extern int synIP;
unsigned int *data;
int dataSize = 10;
int arp = 0;    // num of arp

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  // TODO your part 2 code here
    struct ethhdr *eth_head = (struct ethhdr *)packet;
    struct iphdr *ip_head = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_head = (struct tcphdr *) (packet + sizeof (struct ethhdr) + sizeof (struct iphdr));

    // check the syn flood
    if(!(tcp_head->fin && tcp_head->rst && tcp_head->psh && tcp_head->ack && tcp_head->urg && tcp_head->ece && tcp_head->cwr) && tcp_head->syn) {
        // check all flag except syn flag is 0
        syn++;
        if(syn == dataSize){    // need to enlarge
            dataSize *= 2;
            data = (unsigned int *) realloc(data, dataSize*sizeof (unsigned int ));
        }
        *(data+syn-1) = ip_head->saddr; // add send addr
    }

    // detect arp package, arp has proto 0x0806, that is 2054
    if(ntohs(eth_head->h_proto) == 2054){
        arp++;
    }
}
