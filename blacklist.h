/* blacklist.h */
#ifndef BLACKLIST_H
#define BLACKLIST_H

#include <rte_hash.h>
#include <rte_mbuf.h>

#define IPV4_KEY_SIZE  sizeof(uint32_t)
#define HASH_ENTRIES   1024

typedef struct BlacklistCtx BlacklistCtx;

// 初始化黑名单上下文
BlacklistCtx* blacklist_init(uint32_t freq_thresh, uint32_t purge_intvl, uint32_t time_win);

// 释放资源
void blacklist_free(BlacklistCtx* ctx);

// 请求阈值检测入口
void blacklist_detect(struct rte_mbuf* mbuf, BlacklistCtx* ctx);

// 黑名单过滤判断
int blacklist_filter(struct rte_mbuf* mbuf, BlacklistCtx* ctx);

// 定期清理
void blacklist_purge(BlacklistCtx* ctx);

#endif