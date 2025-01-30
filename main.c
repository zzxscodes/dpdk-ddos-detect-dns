#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_kni.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "dns.h"
#include "ddos.h"
#include "config.h"
#include "blacklist.h"

#define MBUF_NUMBER		8192 * 4
#define MBUF_SIZE		32
#define CACHE_SIZE  256
#define ENABLE_SEND	1
#define ENABLE_KNI_APP 	1	
#define ENABLE_DNS_APP	1	
#define ENABLE_PROMISCUOUS	1
#define ENABLE_DDOS_DETECT  0
#define ENABLE_BLACKLIST 0
#define DNS_UDP_PORT	53

int gDpdkPortId = 0;

#if ENABLE_KNI_APP

struct rte_kni *global_kni = NULL;

#endif

#if ENABLE_SEND

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint32_t gSrcIp; 
static uint32_t gDstIp;

static uint16_t gSrcPort;
static uint16_t gDstPort;

#endif

#if ENABLE_KNI_APP

static int g_config_network_if(uint16_t port_id, uint8_t if_up) {
	if (!rte_eth_dev_is_valid_port(port_id)) {
		return -EINVAL;
	}
	int ret = 0;
	if (if_up) {

		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);

	} else {

		rte_eth_dev_stop(port_id);

	}
	if (ret < 0) {
		printf("Failed to start port : %d\n", port_id);
	}
	return 0;
}

#endif

#if ENABLE_SEND

static struct rte_mbuf *alloc_udp_pkt(struct rte_mempool *pool, uint8_t *data, 
	uint16_t length) {

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pool);  //
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc error\n");
	}

	mbuf->pkt_len = length + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr);
	mbuf->data_len = length + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr);

	uint8_t *msg = rte_pktmbuf_mtod(mbuf, uint8_t*);
	// ether 
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// iphdr
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(length + sizeof(struct rte_ipv4_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// udphdr
	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	udp->dgram_len = htons(length);
	rte_memcpy((uint8_t*)(udp+1), data, length-sizeof(struct rte_udp_hdr));
	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
	return mbuf;
}

#endif

//  echo 1 > /sys/devices/virtual/net/vEth0/carrier

// ifconfig vEth0 192.168.1.33 up

int main(int argc, char *argv[]) {
	
	if (argc != 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    if (load_config(argv[1]) != 0) {
        fprintf(stderr, "Failed to load config file\n");
        return 1;
    }

    // 遍历映射并调用 add_A_record 或 add_AAAA_record
    for (int i = 0; i < mapping_count; i++) {
        if (mappings[i].ip_type == IPV4) {
            add_A_record(mappings[i].domain, mappings[i].ip.ipv4);
        } else {
            add_AAAA_record(mappings[i].domain, mappings[i].ip.ipv6);
        }
    }

	// 4G, hugepage, bind pci 
	if (rte_eal_init(argc, argv) < 0) {

		rte_exit(EXIT_FAILURE, "Error\n");

	}
	//per_lcore_socket_id;
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbufpool", MBUF_NUMBER, CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (!mbuf_pool) {
        rte_exit(EXIT_FAILURE, "mbuf Error\n");
	}

#if ENABLE_KNI_APP

	if (-1 == rte_kni_init(gDpdkPortId)) {
		rte_exit(EXIT_FAILURE, "kni init failed\n");
	}

#endif

	uint16_t nb_rx_queues = 1;
#if ENABLE_SEND
	uint16_t nb_tx_queues = 1;
#else
	uint16_t nb_tx_queues = 0;
#endif
	const struct rte_eth_conf port_conf_default = {
		.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
	};
	rte_eth_dev_configure(gDpdkPortId, nb_rx_queues, nb_tx_queues, &port_conf_default);

	rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, 
		rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool);

#if ENABLE_SEND
	
	rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId),
		NULL);
#endif	

	rte_eth_dev_start(gDpdkPortId);

#if ENABLE_PROMISCUOUS
	rte_eth_promiscuous_enable(gDpdkPortId); 
#endif

#if ENABLE_KNI_APP

	struct rte_kni_conf conf;
	memset(&conf, 0, sizeof(conf));

	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%d", gDpdkPortId);
	conf.group_id = gDpdkPortId;
	conf.mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;

	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr*)conf.mac_addr);
	rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);

	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));
	ops.port_id = gDpdkPortId;
	ops.config_network_if = g_config_network_if;

	global_kni = rte_kni_alloc(mbuf_pool, &conf, &ops);

#endif


#if ENABLE_DNS_APP

	struct Message msg;
  	memset(&msg, 0, sizeof(struct Message));

#endif

#if ENABLE_BLACKLIST

	BlacklistCtx *ctx = blacklist_init(100, 10, 60);

#endif

	while (1) {

		unsigned num_recvd = 0;
		unsigned i = 0;

#if ENABLE_KNI_APP

		struct rte_mbuf *kni_burst[MBUF_SIZE];
		num_recvd = rte_kni_rx_burst(global_kni, kni_burst, MBUF_SIZE);
		if (num_recvd > MBUF_SIZE) {
			rte_exit(EXIT_FAILURE, "rte_kni_rx_burst Error\n");
		}

		unsigned nb_tx = rte_eth_tx_burst(gDpdkPortId, 0, kni_burst, num_recvd);
		if (nb_tx < num_recvd) {

			for (i = nb_tx;i < num_recvd;i ++) {
				rte_pktmbuf_free(kni_burst[i]);
				kni_burst[i] = NULL;
			}
			
		}

#endif
	
		struct rte_mbuf *mbufs[MBUF_SIZE];
		num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, MBUF_SIZE);
		if (num_recvd > MBUF_SIZE) {
			rte_exit(EXIT_FAILURE, "rte_eth_rx_burst Error\n");
		}

#if ENABLE_DDOS_DETECT
		
		i = 0;
		unsigned j = 0;
		for (i = 0; i < num_recvd; i++) {
    		ddos_detect(mbufs[i]);
		}

		for (i = 0; i < num_recvd; i++) {
    		if (mbufs[i]->ol_flags & RTE_MBUF_F_RX_DROP) {
        	rte_pktmbuf_free(mbufs[i]);
    		} else {
        		mbufs[j++] = mbufs[i];
    		}
		}
		num_recvd = j;

#endif

#if ENABLE_BLACKLIST
		
		j = 0;

		for (i = 0; i < num_recvd; i++)
		{
			blacklist_detect(mbufs[i], ctx);
		}

		for (i = 0; i < num_recvd; i++) {
            if (blacklist_filter(mbufs[i], ctx)) {
                rte_pktmbuf_free(mbufs[i]);
            } else {
                mbufs[j++] = mbufs[i];
            }
        }

		num_recvd = j;

#endif
		
		for (i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
#if ENABLE_KNI_APP

				unsigned sent = rte_kni_tx_burst(global_kni, &mbufs[i], 1);
				if (sent < 1)
				{
					rte_pktmbuf_free(mbufs[i]);
				}
				rte_kni_handle_request(global_kni);
#endif
				continue;
			}

			struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				struct rte_udp_hdr* udphdr = (struct rte_udp_hdr*)(iphdr + 1);

#if ENABLE_DNS_APP
				if (ntohs(udphdr->dst_port) == DNS_UDP_PORT) {

					printf("dns request\n");
					
                    rte_memcpy(gSrcMac, ehdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
                    rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
                    
                    rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                    rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));
    
                    rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
                    rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));

					uint16_t length = ntohs(udphdr->dgram_len);
					uint16_t nbytes = length - sizeof(struct rte_udp_hdr);
								
                	uint8_t *data = (uint8_t*)(udphdr + 1);

                	free_questions(msg.questions);
				    free_resource_records(msg.answers);
				    free_resource_records(msg.authorities);
				    free_resource_records(msg.additionals);
				    memset(&msg, 0, sizeof(struct Message));

					if (decode_msg(&msg, data, nbytes) != 0) {
						rte_pktmbuf_free(mbufs[i]); // 
				    	continue;
				    }

				    resolver_process(&msg);

				    uint8_t *p = data;
				    if (encode_msg(&msg, &p) != 0) {
				    	rte_pktmbuf_free(mbufs[i]);
				      	continue;
				    }

				    uint16_t len = p - data;
					struct rte_mbuf *mbuf = alloc_udp_pkt(mbuf_pool, data, len+sizeof(struct rte_udp_hdr));
					rte_eth_tx_burst(gDpdkPortId, 0, &mbuf, 1);
					
				}
#endif
				else if (ntohs(udphdr->dst_port) != 8888)
				{
#if ENABLE_KNI_APP
					unsigned sent = rte_kni_tx_burst(global_kni, &mbufs[i], 1);
					if (sent < 1)
					{
						rte_pktmbuf_free(mbufs[i]);
					}
#else
					rte_pktmbuf_free(mbufs[i]);
#endif
					continue;
				}

				uint16_t length = ntohs(udphdr->dgram_len);
                *((char*) udphdr + length) = '\0';
                
                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

                addr.s_addr = iphdr->dst_addr;
                printf("dst: %s:%d, \n", inet_ntoa(addr), ntohs(udphdr->dst_port));

#if ENABLE_SEND

				rte_memcpy(gSrcMac, ehdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				
				rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

				rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));

				struct rte_mbuf *mbuf = alloc_udp_pkt(mbuf_pool, (uint8_t*)(udphdr+1), length);

				rte_eth_tx_burst(gDpdkPortId, 0, &mbuf, 1);
#endif			
			} else {

#if ENABLE_KNI_APP 
				rte_kni_tx_burst(global_kni, &mbufs[i], 1);
#endif
			}
		}

#if ENABLE_KNI_APP
		rte_kni_handle_request(global_kni);
#endif

#if ENABLE_BLACKLIST
    blacklist_purge(ctx);
#endif

	}

#if ENABLE_BLACKLIST
		blacklist_free(ctx);
#endif

		return 0;
}
