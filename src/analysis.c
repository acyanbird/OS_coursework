#include "analysis.h"
#include "common.h"
#include "sniff.h"

extern int syn; // for syn attack, count for syn pack and ip
unsigned int *data;
int dataSize = 10;
int arp = 0;    // num of arp
char *black1 = "Host: www.google.co.uk";
char *black2 = "Host: www.bbc.com";
int blackURL = 0;

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
    if (verbose) {
        // if need to print, call dum
        dump(packet, header->len);
    }
    struct ethhdr *eth_head = (struct ethhdr *) packet;
    struct iphdr *ip_head = (struct iphdr *) (packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_head = (struct tcphdr *) (packet + sizeof(struct ethhdr) + ip_head->ihl*4);
    // len is not fixed, add length

    // check the syn flood
    if (!(tcp_head->fin && tcp_head->rst && tcp_head->psh && tcp_head->ack && tcp_head->urg && tcp_head->ece &&
          tcp_head->cwr) && tcp_head->syn) {
        // check all flag except syn flag is 0
        syn++;
        if (syn == dataSize) {    // need to enlarge
            dataSize *= 2;
            data = (unsigned int *) realloc(data, dataSize * sizeof(unsigned int));
        }
        *(data + syn - 1) = ip_head->saddr; // add send addr
    }
    // detect arp package, arp has proto 0x0806, that is 2054
    else if (ntohs(eth_head->h_proto) == 2054) {
        arp++;
    }
    else if (ntohs(tcp_head->dest) == 80 ) {
        char *hdata = (char *)tcp_head + 20;
        // len of min tcp header
        int hdatalen = header->len - ETH_HLEN - ip_head->ihl*4 - 20; // min tcp head is 20
        if(hdatalen){   // if 0 not exe
            char *tol = (char *) calloc(hdatalen + 1, sizeof (char ));  // \n at last
            for (int i = 0; i < hdatalen; ++i) {    // copy into a string
                char byte = hdata[i];
                tol[i] = byte;
            }
            tol[hdatalen] = '\n';

            char *exist1 = strstr(tol, black1);
            char *exist2 = strstr(tol, black2);
            // det if black url 1 and 2 in the string

            if(exist1 || exist2){
                printf("==============================\nBlacklisted URL violation detected\nSource IP address: ");
                print_ip(ip_head->saddr);
                printf("\nDestination IP address: ");
                print_ip(ip_head->daddr);
                printf("\n==============================\n");
                fflush(stdout);
                blackURL++;
            }
        }
    }
}
