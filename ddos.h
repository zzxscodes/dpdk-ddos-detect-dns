#ifndef __DDOSDETECTOR_H__
#define __DDOSDETECTOR_H__ 

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_log.h>
#include <rte_kni.h>
#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>

#define RTE_MBUF_F_RX_DROP (1ULL << 23)
#define CAPTURE_WINDOWS 256

// DDoS detection threshold
extern double tresh;
// Store the number of set bits in each packet
extern uint32_t p_setbits[CAPTURE_WINDOWS];
// Store the total number of bits in each packet
extern uint32_t p_totbits[CAPTURE_WINDOWS];
// Store the entropy value of each packet
extern double p_entropy[CAPTURE_WINDOWS];
// Index for circular storage of packet information
extern int pkt_idx;

// Function to calculate entropy
double ddos_entropy(double set_bits, double total_bits);

// Function to count the number of set bits in the input data
uint32_t count_bit(uint8_t *msg, const uint32_t length);

// Function to extract the source IP address from the packet
in_addr_t get_source_ip(struct rte_mbuf *pkt);

// Function to detect DDoS attacks
int ddos_detect(struct rte_mbuf *pkt);

#endif