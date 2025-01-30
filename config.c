#include "config.h"

Mapping mappings[MAX_MAPPINGS];
int mapping_count = 0;

// 加载配置文件
int load_config(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open config file");
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file) != NULL) {
        // 忽略注释行
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        char domain[MAX_DOMAIN_LENGTH];
        char ip_str[INET6_ADDRSTRLEN];
        if (sscanf(line, "%255s %45s", domain, ip_str) == 2) {
            if (mapping_count >= MAX_MAPPINGS) {
                fprintf(stderr, "Too many mappings in the config file\n");
                fclose(file);
                return -1;
            }

            strncpy(mappings[mapping_count].domain, domain, MAX_DOMAIN_LENGTH - 1);
            mappings[mapping_count].domain[MAX_DOMAIN_LENGTH - 1] = '\0';

            // 尝试解析为 IPv4 地址
            if (inet_pton(AF_INET, ip_str, &mappings[mapping_count].ip.ipv4) == 1) {
                mappings[mapping_count].ip_type = IPV4;
            } 
            // 尝试解析为 IPv6 地址
            else if (inet_pton(AF_INET6, ip_str, &mappings[mapping_count].ip.ipv6) == 1) {
                mappings[mapping_count].ip_type = IPV6;
            } 
            else {
                fprintf(stderr, "Invalid IP address: %s for domain %s\n", ip_str, domain);
                continue;
            }

            mapping_count++;
        }
    }

    fclose(file);
    return 0;
}