#include "dispatch.h"
#include <pcap.h>
#include "analysis.h"
#include "common.h"

pthread_mutex_t queueMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queueCond=PTHREAD_COND_INITIALIZER;
extern jobQueue *q;

void dispatch(unsigned char *userdata, struct pcap_pkthdr *header,
              const unsigned char *packet) {

    job *j;
    j = (job *)malloc(sizeof (struct job));
    int verbose = (int)userdata;
    createJob(j, header, packet, verbose);
    pthread_mutex_lock(&queueMutex);
    enQueue(j, q);
    //  broadcast to all waiting thread
    pthread_cond_broadcast(&queueCond);
    pthread_mutex_unlock(&queueMutex);
//  analyse(header, packet, (int)userdata);
}
