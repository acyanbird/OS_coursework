#include "analysis.h"
#include "common.h"
#include "sniff.h"

int syn = 0;
// store syn ip
unsigned int *data;
// init size of ip storing
int dataSize = 10;
int arp = 0;
char *black1 = "Host: www.google.co.uk";
char *black2 = "Host: www.bbc.com";
int blackURL = 0;

// init for multi thread
pthread_mutex_t synm, arpm, blackm = PTHREAD_MUTEX_INITIALIZER;

extern pthread_mutex_t queueMutex;
extern pthread_cond_t queueCond;

extern jobQueue *q;

void *analyse(void *arg) {
    // init 3 argument
    int verbose;
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    while(1) {
        pthread_mutex_lock(&queueMutex);
        while (isEmpty(q)){
            pthread_cond_wait(&queueCond, &queueMutex);
        }
        // get the job
        job *j = deQueue(q);
        pthread_mutex_unlock(&queueMutex);

        header = j->header;
        packet = j->packet;
        verbose = j->verbose;

        if (verbose) {
            // if need to print, call dum
            dump(packet, header->len);
        }
        struct ethhdr *eth_head = (struct ethhdr *) packet;
        struct iphdr *ip_head = (struct iphdr *) (packet + sizeof(struct ethhdr));
        struct tcphdr *tcp_head = (struct tcphdr *) (packet + sizeof(struct ethhdr) + ip_head->ihl * 4);
        // len is not fixed, add length

        // check the syn flood
        // check all flag except syn flag is 0
        if (!(tcp_head->fin || tcp_head->rst || tcp_head->psh || tcp_head->ack || tcp_head->urg || tcp_head->ece ||
              tcp_head->cwr) && tcp_head->syn) {
            // now into mutex lock
            pthread_mutex_lock(&synm);
            syn++;
            // if need to enlarge array
            if (syn == dataSize) {
                dataSize *= 2;
                data = (unsigned int *) realloc(data, dataSize * sizeof(unsigned int));
            }
            *(data + syn - 1) = ip_head->saddr;
            pthread_mutex_unlock(&synm);
        }

            // detect arp package, arp has proto 0x0806, that is 2054
        else if (ntohs(eth_head->h_proto) == 2054) {
            pthread_mutex_lock(&arpm);
            arp++;
            pthread_mutex_unlock(&arpm);
        } else if (ntohs(tcp_head->dest) == 80) {
            char *hdata = (char *) tcp_head + 20;
            while (hdata != NULL) {
                char *next = strstr(hdata, "\r\n");
                char *current = hdata;
                char *exist1 = strstr(current, black1);
                char *exist2 = strstr(current, black2);
                if (exist1 || exist2) {
                    pthread_mutex_lock(&blackm);
                    printf("==============================\nBlacklisted URL violation detected\nSource IP address: ");
                    print_ip(ip_head->saddr);
                    printf("\nDestination IP address: ");
                    print_ip(ip_head->daddr);
                    printf("\n==============================\n");
                    fflush(stdout);
                    blackURL++;
                    pthread_mutex_unlock(&blackm);
                    break;
                }
                if(next == NULL){
                    break;
                }
                int moveNext = strlen(next);
                moveNext += 2;  // skip \r\n
                hdata += moveNext;
            }
            }
        }
    }

