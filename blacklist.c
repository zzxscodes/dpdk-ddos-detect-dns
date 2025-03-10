/* blacklist.c */
#include "blacklist.h"
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_timer.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <stdio.h>

typedef struct {
    uint32_t count;
    uint64_t window_start;
} IpStat;

typedef struct {
    uint64_t block_time;
} BlockEntry;

struct BlacklistCtx {
    uint32_t freq_threshold;
    uint32_t purge_interval;
    uint32_t time_window;
    struct rte_hash *ip_stats;
    struct rte_hash *blacklist;
    uint64_t last_purge;
    uint32_t ip_stats_count;
};

static struct rte_hash* create_hash(const char* name, uint32_t key_len) {
    struct rte_hash_parameters params = {
        .name = name,
        .entries = HASH_ENTRIES,
        .key_len = key_len,
        .hash_func = rte_jhash,
        .socket_id = SOCKET_ID_ANY
    };
    return rte_hash_create(&params);
}

BlacklistCtx* blacklist_init(uint32_t freq_thresh, uint32_t purge_intvl, uint32_t time_win) {
    BlacklistCtx* ctx = rte_zmalloc("blacklist_ctx", sizeof(*ctx), 0);
    if (!ctx) {
        fprintf(stderr, "Failed to allocate memory for BlacklistCtx\n");
        return NULL;
    }

    ctx->ip_stats = create_hash("ip_stats", IPV4_KEY_SIZE);
    ctx->blacklist = create_hash("blacklist", IPV4_KEY_SIZE);
    if (!ctx->ip_stats || !ctx->blacklist) {
        rte_hash_free(ctx->ip_stats);
        rte_hash_free(ctx->blacklist);
        rte_free(ctx);
        fprintf(stderr, "Failed to create hash tables\n");
        return NULL;
    }

    ctx->freq_threshold = freq_thresh;
    ctx->purge_interval = purge_intvl;
    ctx->time_window = time_win;
    ctx->last_purge = rte_get_tsc_cycles() / rte_get_tsc_hz();
    ctx->ip_stats_count = 0;
    return ctx;
}

void blacklist_free(BlacklistCtx* ctx) {
    if (!ctx) return;
    rte_hash_free(ctx->ip_stats);
    rte_hash_free(ctx->blacklist);
    rte_free(ctx);
}

static uint32_t get_ipv4_src(struct rte_mbuf* mbuf) {
    struct rte_ipv4_hdr* iphdr = rte_pktmbuf_mtod_offset(mbuf, 
        struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
    return iphdr->src_addr;
}

// 删除统计数量最小的条目
static void remove_min_count_entry(BlacklistCtx* ctx) {
    uint32_t iter = 0;
    const void* key;
    void* data;
    uint32_t min_count = UINT32_MAX;
    const void* min_key = NULL;

    while (rte_hash_iterate(ctx->ip_stats, &key, &data, &iter) >= 0) {
        IpStat* stat = data;
        if (stat->count < min_count) {
            min_count = stat->count;
            min_key = key;
        }
    }

    if (min_key) {
        if (rte_hash_del_key(ctx->ip_stats, min_key) >= 0) {
            ctx->ip_stats_count--;
        }
    }
}

// 删除最旧的条目
static void remove_oldest_entry(BlacklistCtx* ctx) {
    uint32_t iter = 0;
    const void* key;
    void* data;
    uint64_t oldest_time = UINT64_MAX;
    const void* oldest_key = NULL;

    while (rte_hash_iterate(ctx->ip_stats, &key, &data, &iter) >= 0) {
        IpStat* stat = data;
        if (stat->window_start < oldest_time) {
            oldest_time = stat->window_start;
            oldest_key = key;
        }
    }

    if (oldest_key) {
        if (rte_hash_del_key(ctx->ip_stats, oldest_key) >= 0) {
            ctx->ip_stats_count--;
        }
    }
}

void blacklist_detect(struct rte_mbuf* mbuf, BlacklistCtx* ctx) {
    uint32_t ip = get_ipv4_src(mbuf);
    if (ip == 0) return;

    uint64_t now = rte_get_tsc_cycles() / rte_get_tsc_hz();
    IpStat* stat;
    int ret = rte_hash_lookup_data(ctx->ip_stats, &ip, (void**)&stat);

    if (ret < 0) {
        if (ctx->ip_stats_count >= HASH_ENTRIES) {
            // 达到限制，删除统计数量最小的条目
            remove_min_count_entry(ctx);
            // 如果还是满的，删除最旧的条目
            if (ctx->ip_stats_count >= HASH_ENTRIES) {
                remove_oldest_entry(ctx);
            }
        }

        IpStat new_stat = {1, now};
        ret = rte_hash_add_key_data(ctx->ip_stats, &ip, &new_stat);
        if (ret < 0) {
            fprintf(stderr, "Failed to add IP %u to ip_stats hash table\n", ip);
            return;
        }
        ctx->ip_stats_count++;
    } else {
        if (now - stat->window_start > ctx->time_window) {
            stat->count = 1;
            stat->window_start = now;
        } else if (++stat->count >= ctx->freq_threshold) {
            BlockEntry entry = {now};
            ret = rte_hash_add_key_data(ctx->blacklist, &ip, &entry);
            if (ret < 0) {
                fprintf(stderr, "Failed to add IP %u to blacklist hash table\n", ip);
            } else {
                stat->count = 0;
            }
        }
    }
}

int blacklist_filter(struct rte_mbuf* mbuf, BlacklistCtx* ctx) {
    uint32_t ip = get_ipv4_src(mbuf);
    if (ip == 0) return 0;

    BlockEntry* entry;
    return rte_hash_lookup_data(ctx->blacklist, &ip, (void**)&entry) >= 0;
}

void blacklist_purge(BlacklistCtx* ctx) {
    if (ctx->purge_interval == (uint32_t)-1) return;

    uint64_t now = rte_get_tsc_cycles() / rte_get_tsc_hz();
    if (now - ctx->last_purge < ctx->purge_interval) return;

    uint32_t iter = 0;
    const void* key;
    void* data;
    while (rte_hash_iterate(ctx->blacklist, &key, &data, &iter) >= 0) {
        BlockEntry* entry = data;
        if (now - entry->block_time > ctx->purge_interval) {
            rte_hash_del_key(ctx->blacklist, key);
        }
    }
    ctx->last_purge = now;
}
