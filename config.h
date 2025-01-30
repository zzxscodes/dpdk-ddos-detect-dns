#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_DOMAIN_LENGTH 256
#define MAX_MAPPINGS 100

// 定义 IP 类型
typedef enum {
    IPV4,
    IPV6
} IPType;

// 定义联合存储 IPv4 和 IPv6 地址
typedef union {
    uint8_t ipv4[4];
    uint8_t ipv6[16];
} IPAddress;

// 定义映射结构体
typedef struct {
    char domain[MAX_DOMAIN_LENGTH];
    IPType ip_type;
    IPAddress ip;
} Mapping;

// 加载配置文件
int load_config(const char* filename);

extern Mapping mappings[MAX_MAPPINGS];
extern int mapping_count;

#endif // CONFIG_H