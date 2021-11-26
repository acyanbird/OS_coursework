//
// Created by cyanbird on 24/11/2021.
//

#include "jobqueue.h"
void createJob(job *j, struct pcap_pkthdr *header,  const unsigned char *packet, int verbose){
    j->next = NULL;
    j->header = header;
    j->packet = packet;
    j->verbose = verbose;
}

void createQueue(jobQueue *q){
    q->head=NULL;
    q->tail=NULL;
}

int isEmpty(jobQueue *q){
    return (q->head==NULL);
}

void enQueue(job *j, jobQueue *q){
    if(isEmpty(q)){
        q->head = j;
        q->tail = j;
    } else {
        q->tail->next = j;
        q->tail = j;
    }
}

job* deQueue(jobQueue *q){
    if(!isEmpty(q)){
        job *de = q->head;
        q->head = q->head->next;
        if(q->head==NULL){
            q->tail = NULL;
        }
        return de;
    }
    return NULL;
}

