//
// Created by cyanbird on 24/11/2021.
//

#ifndef POOLTEST_JOBQUEUE_H
#define POOLTEST_JOBQUEUE_H
#include <stddef.h>


typedef struct job{
    struct pcap_pkthdr *header;
    int verbose;
    const unsigned char *packet;
    struct job *next;
} job;

typedef struct jobQueue{
    job *head;
    job *tail;
} jobQueue;

void createJob(job *j, struct pcap_pkthdr *header,  const unsigned char *packet, int verbose);
void createQueue(jobQueue *q);
int isEmpty(jobQueue *q);
void enQueue(job *j, jobQueue *q);
job* deQueue(jobQueue *q);

#endif //POOLTEST_JOBQUEUE_H
