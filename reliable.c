#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"
#include "buffer.h"

struct reliable_state {
    rel_t *next;			/* Linked list for traversing all connections */
    rel_t **prev;

    conn_t *c;			/* This is the connection object */

    buffer_t* send_buffer;
    int send_unack;
    int send_nxt;

    buffer_t* rec_buffer;
    int rec_nxt;

    int timeout;
    int windowSize;

    int eof_self;
    int eof_other;
    int eof_ack;

};
rel_t *rel_list;

/* Creates a new reliable protocol session, returns NULL on failure.
* ss is always NULL */
rel_t *
rel_create (conn_t *c, const struct sockaddr_storage *ss,
const struct config_common *cc)
{
    rel_t *r;

    r = xmalloc (sizeof (*r));
    memset (r, 0, sizeof (*r));

    if (!c) {
        c = conn_create (r, ss);
        if (!c) {
            free (r);
            return NULL;
        }
    }

    r->c = c;
    r->next = rel_list;
    r->prev = &rel_list;
    if (rel_list)
    rel_list->prev = &r->next;
    rel_list = r;

    r->send_buffer = xmalloc(sizeof(buffer_t));
    r->send_buffer->head = NULL;
    r->send_unack = 1;
    r->send_nxt = 1;

    r->rec_buffer = xmalloc(sizeof(buffer_t));
    r->rec_buffer->head = NULL;
    r->rec_nxt = 1;

    r->windowSize = cc->window;
    r->timeout = cc->timeout;

    r->eof_ack = -1;
    r->eof_other = 0;
    r->eof_self = 0;

    return r;
}

void
rel_destroy (rel_t *r)
{

    if (r->next) {
        r->next->prev = r->prev;
    }
    *r->prev = r->next;
    conn_destroy (r->c);

    /* Free any other allocated memory here */
    buffer_clear(r->send_buffer);
    free(r->send_buffer);
    buffer_clear(r->rec_buffer);
    free(r->rec_buffer);
    
    free(r);

}

// n is the expected length of pkt
void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
    uint16_t packet_len = ntohs(pkt->len);
    if (packet_len != n) {
        //drop package since length not matching
        return;
    }

    uint32_t packet_ack = ntohl(pkt->ackno);

    //check if checksum is correct
    uint16_t check = pkt->cksum;
    pkt->cksum = 0;
    if(check != cksum(pkt, ntohs(pkt->len))) {
        //drop package since it got corrupted
        return;
    }

    if (packet_len == 8) {
        //ACK PACK
        buffer_remove(r->send_buffer, packet_ack);

        r->send_unack = packet_ack;
        if(packet_ack >= r->eof_ack && r->eof_ack != -1) {
            //you can terminate
            r->eof_self = 1;
            //if other is also ready to terminate, destroy
            if(r->eof_other == 1) {
                rel_output(r);
                rel_destroy(r);
                return;
            }
        }
        rel_read(r);
    }
    else {
        
        //DATA PACK

        uint32_t packet_seq = ntohl(pkt->seqno);

        if(packet_seq >= r->rec_nxt + r->windowSize) {
            //dropping since our window hasn't advanced this far
            return;
        }

        if (conn_bufspace(r->c) < packet_len) {
            //dropping since there is no space in output buffer
            return;
        }

        int temp_seq;
        if(packet_seq < r->rec_nxt) {
            temp_seq = r->rec_nxt;
        } else {
            if(buffer_contains(r->rec_buffer, packet_seq) == 0) {
                struct timeval now;
                gettimeofday(&now, NULL);
                long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
                buffer_insert(r->rec_buffer, pkt, now_ms);
            }
            temp_seq = r->rec_nxt;
            while(buffer_contains(r->rec_buffer, temp_seq)) {
                temp_seq++;
            }
        }

        int length = htons(8);
        int ack = htonl(temp_seq);

        packet_t *ackpkt = (packet_t *)malloc(sizeof(*ackpkt));
        ackpkt->cksum = 0;
        ackpkt->len = length;
        ackpkt->ackno = ack;

        uint16_t check = cksum(ackpkt, ntohs(ackpkt->len));
        ackpkt->cksum = check;

        conn_sendpkt(r->c, ackpkt, 8);

        //this is the right packet (the one we want to output therefore we output it)
        if(packet_seq == r->rec_nxt) {
            rel_output(r);
        }

        if(r->eof_self == 1 && r->eof_other == 1) {
            rel_destroy(r);
        }

    }
}

void
rel_read (rel_t *s)
{
    while((uint32_t)(int)s->windowSize > buffer_size(s->send_buffer) && s->eof_ack == -1) {
        char buf[500];
        int input_ready = conn_input(s->c, buf, 500);

        if(input_ready == 0) {
            return;
        }
        if(input_ready == -1) {
            //send empty data packet
            int ack = htonl(s->rec_nxt);
            int seq = htonl(s->send_nxt);

            //this is the ack packet we need to get back s.t. we can end conn
            s->eof_ack = s->send_nxt;
            s->send_nxt++;

            packet_t *pkt = xmalloc(sizeof(*pkt));
            
            pkt->cksum = 0;
            pkt->len = htons(12);
            pkt->ackno = ack;
            pkt->seqno = seq;

            uint16_t check = cksum(pkt, ntohs(pkt->len));
            pkt->cksum = check;

            struct timeval now;
            gettimeofday(&now, NULL);
            long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
            buffer_insert(s->send_buffer, pkt, now_ms);

            conn_sendpkt(s->c, pkt, 12);
            return;
        }

        int ack = htonl(s->rec_nxt);
        int seq = htonl(s->send_nxt);
        s->send_nxt++;

        packet_t *pkt = xmalloc(sizeof(*pkt));
        
        pkt->cksum = 0;
        pkt->len = htons(12 + input_ready);
        pkt->ackno = ack;
        pkt->seqno = seq;

        memcpy(pkt->data, buf, input_ready);

        uint16_t check = cksum(pkt, ntohs(pkt->len));
        pkt->cksum = check;

        struct timeval now;
        gettimeofday(&now, NULL);
        long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;

        buffer_insert(s->send_buffer, pkt, now_ms);

        conn_sendpkt(s->c, pkt, 12 + input_ready);
    }
}


void
rel_output (rel_t *r)
{
    while(buffer_size(r->rec_buffer) > 0 && ntohl(buffer_get_first(r->rec_buffer)->packet.seqno) == r->rec_nxt) {
        packet_t p = buffer_get_first(r->rec_buffer)->packet;
        int packet_len = ntohs(p.len);

        r->rec_nxt++;

        conn_output(r->c, &p.data, packet_len-12);
        buffer_remove_first(r->rec_buffer);

        if(packet_len == 12) {
            r->eof_other = 1;
        }
    }
}

void
rel_timer ()
{
    // Go over all reliable senders, and have them send out
    // all packets whose timer has expired
    rel_t *current = rel_list;
    while (current != NULL) {
        
        buffer_node_t* curr_node = buffer_get_first(current->send_buffer);
        while(curr_node != NULL) {
            struct timeval now;
            gettimeofday(&now, NULL);
            long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;

            if(curr_node->last_retransmit + current->timeout < now_ms) {
                curr_node->last_retransmit = now_ms;
                conn_sendpkt(current->c,  &curr_node->packet, ntohs(curr_node->packet.len));
            }
            curr_node = curr_node->next;
        }
        current = current->next;
    }
}