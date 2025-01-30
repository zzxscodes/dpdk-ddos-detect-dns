#include "ddos.h"

// Global variables
double tresh = 1200.0;
uint32_t p_setbits[CAPTURE_WINDOWS] = {0};
uint32_t p_totbits[CAPTURE_WINDOWS] = {0};
double p_entropy[CAPTURE_WINDOWS] = {0};
int pkt_idx = 0;

// Function to calculate entropy
double ddos_entropy(double set_bits, double total_bits) {
    return (-set_bits) * (log2(set_bits) - log2(total_bits)) 
           - (total_bits - set_bits) * (log2(total_bits - set_bits) - log2(total_bits))
           + log2(total_bits);
}

// Function to count the number of set bits in the input data
uint32_t count_bit(uint8_t *msg, const uint32_t length) {
    uint64_t v, set_bits = 0;
    const uint64_t *ptr = (uint64_t *) msg;
    const uint64_t *end = (uint64_t *) (msg + length);
    do {
        v = *(ptr++);
        v = v - ((v >> 1) & 0x5555555555555555);                   
        v = (v & 0x3333333333333333) + ((v >> 2) & 0x3333333333333333);     
        v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0F;
        set_bits += (v * 0x0101010101010101) >> (sizeof(v) - 1) * 8; 
    } while(end > ptr);
    return set_bits;
}

// Function to extract the source IP address from the packet
in_addr_t get_source_ip(struct rte_mbuf *pkt) {
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        return ip_hdr->src_addr;
    }
    return 0;
}

// Function to detect DDoS attacks
int ddos_detect(struct rte_mbuf *pkt) {
    static char flag = 0; 
    uint8_t *msg = rte_pktmbuf_mtod(pkt, uint8_t *);
    uint32_t set_bits = count_bit(msg, pkt->buf_len);
    uint32_t tot_bits = pkt->buf_len * 8;

    p_setbits[pkt_idx % CAPTURE_WINDOWS] = set_bits;
    p_totbits[pkt_idx % CAPTURE_WINDOWS] = tot_bits;
    p_entropy[pkt_idx % CAPTURE_WINDOWS] = ddos_entropy(set_bits, tot_bits);

    if (pkt_idx >= CAPTURE_WINDOWS) {
        int i = 0;
        uint32_t total_set = 0, total_bit = 0;
        double sum_entropy = 0.0;
        for (i = 0; i < CAPTURE_WINDOWS; i++) {
            total_set += p_setbits[i]; 
            total_bit += p_totbits[i]; 
            sum_entropy += p_entropy[i];
        }
        double entropy = ddos_entropy(total_set, total_bit);
        printf("%u/%u Entropy(%f), Total_Entropy(%f)\n", total_set, total_bit, sum_entropy, entropy);
        if (tresh <  sum_entropy - entropy) { 
            if (!flag) { 
                printf("ddos attack!!! Entropy(%f) < Total_Entropy(%f)\n", entropy, sum_entropy);
                pkt->ol_flags |= RTE_MBUF_F_RX_DROP; 
            }
            flag = 1;
        } else {
            if (flag) { 
                printf( "no new!!! Entropy(%f) < Total_Entropy(%f)\n", 
                    entropy, sum_entropy);
            }
            flag = 0;
        }
        pkt_idx = (pkt_idx + 1) % CAPTURE_WINDOWS + CAPTURE_WINDOWS;
    } else {
        pkt_idx++;
    }
    return 0;
}