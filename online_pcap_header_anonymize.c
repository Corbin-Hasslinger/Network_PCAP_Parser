#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <time.h>

typedef unsigned char u_char;

#define MAX_PACKETS 1000
#define IP_ENDING_SIZE 65536
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
int pcap_parser(const struct pcap_pkthdr *header, const u_char *packet, u_char **out_buffer, int *out_len, uint16_t *mapping);
void init_map(uint16_t *mapping);
void anonymize_ip(struct iphdr *iphdr, uint16_t *mapping);

typedef struct {
    uint16_t *mapping;
    pcap_dumper_t *dumper;
} handler_ctx;

int main(int argc, char *argv[]){
    // if (argc < 2){
    //     fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
    //     return EXIT_FAILURE;
    // }
    // char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    //     if (!handle) {
    //     fprintf(stderr, "Error opening file %s: %s\n", argv[1], errbuf);
    //     return EXIT_FAILURE;
    // }
    // struct bpf_program fp;
    // pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN);
    // pcap_setfilter(handle, &fp);

    // pcap_dumper_t *dumper = pcap_dump_open(handle, "output_headers_anonymized.pcap");
    // if (!dumper) {
    //     fprintf(stderr, "Failed to open dumper file: %s\n", "output_headers_anonymized.pcap");
    //     pcap_close(handle);
    //     return EXIT_FAILURE;
    // }
    uint16_t mapping[IP_ENDING_SIZE];
    init_map(mapping);

    // handler_ctx ctx = { .mapping = mapping, .dumper = dumper };
    
    // pcap_loop(handle, MAX_PACKETS, packet_handler, (u_char *)&ctx);
    // pcap_dump_close(dumper);
    // pcap_close(handle);
    // return EXIT_SUCCESS;
}
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    handler_ctx *ctx = (handler_ctx *)user;

    if (header->caplen > header->len || header->caplen < 42) {
        fprintf(stderr, "Skipping malformed/truncated packet (caplen = %u, len = %u)\n", header->caplen, header->len);
        return;
    }

    u_char *trimmed = NULL;
    int trimmed_len = 0;

    if (pcap_parser(header, packet, &trimmed, &trimmed_len, ctx->mapping) == 1) {
        struct pcap_pkthdr new_hdr = *header;
        new_hdr.caplen = trimmed_len;
        new_hdr.len = trimmed_len;
        pcap_dump((u_char *)ctx->dumper, &new_hdr, trimmed);
        free(trimmed);
    }
}
int pcap_parser(const struct pcap_pkthdr *header, const u_char *packet, u_char **out_buffer, int *out_len, uint16_t *mapping){
    if (!header || !packet || !out_buffer || !out_len) {
        return -1;
    }
    if (header->caplen < sizeof(struct ether_header)) {
        return 0;
    }
    //Cast ether_header into first 14 bytes of raw packet data
    const struct ether_header *eth_header = (const struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);

    int ip_offset = sizeof(struct ether_header);
    //check if ethertype is VLAN
    if (ether_type == ETHERTYPE_VLAN) {
        if (header->caplen < ip_offset + 4 + sizeof(struct iphdr)) return 0;
        ether_type = ntohs(*(uint16_t *)(packet + ip_offset + 2));
        ip_offset += 4;  // VLAN tag, extra 4 bytes
    }

    if (ether_type != ETHERTYPE_IP) {
        return 0;
    }
    if (header->caplen < ip_offset + sizeof(struct iphdr)) return 0;
    const struct iphdr *ip_hdr = (const struct iphdr *)(packet + ip_offset);
    int ip_header_len = ip_hdr->ihl * 4;

    if (header->caplen < ip_offset + ip_header_len) return 0;

    const u_char *l4_ptr = packet + ip_offset + ip_header_len;
    int l4_len = 0;

    if (ip_hdr->protocol == IPPROTO_TCP) {
        if (header->caplen < l4_ptr - packet + sizeof(struct tcphdr)) return 0;
        const struct tcphdr *tcp_hdr = (const struct tcphdr *)l4_ptr;
        l4_len = tcp_hdr->doff * 4;
    }
    else if (ip_hdr->protocol == IPPROTO_UDP) {
        if (header->caplen < l4_ptr - packet + sizeof(struct udphdr)) return 0;
        const struct udphdr *udp_hdr = (const struct udphdr *)l4_ptr;
        l4_len = sizeof(struct udphdr);
    }
    else {
        return 0; 
    }
    
    int total_len = ip_offset + ip_header_len + l4_len;
    if (header->caplen < total_len) return 0;

    *out_buffer = (u_char *)malloc(total_len);
    if (!*out_buffer) return -1;

    memcpy(*out_buffer, packet, total_len);
    *out_len = total_len;

    struct iphdr *out_ip_hdr = (struct iphdr *)(*out_buffer + ip_offset);
    out_ip_hdr->tot_len = htons(ip_header_len + l4_len);
    anonymize_ip(out_ip_hdr, mapping);

    if (ip_hdr->protocol == IPPROTO_UDP) {
        struct udphdr *out_udp_hdr = (struct udphdr *)(*out_buffer + ip_offset + ip_header_len);
        out_udp_hdr->len = htons(sizeof(struct udphdr));
    }
    
    return 1;
}

void init_map(uint16_t *mapping){
    srand(time(NULL));
    for (int i = 0; i < IP_ENDING_SIZE; ++i) {
        mapping[i] = i;
    }

    for (int i = IP_ENDING_SIZE-1; i >0; i-- ){
        int j = rand() % (i+1);
        uint16_t temp = mapping[i];
        mapping[i] = mapping[j];
        mapping[j] = temp;
    }
}

void anonymize_ip(struct iphdr *ip_hdr, uint16_t *mapping){
    uint32_t src_ip = ntohl(ip_hdr->saddr);
    uint32_t src_prefix = src_ip & 0xFFFF0000;
    uint16_t src_suffix = src_ip & 0x0000FFFF;
    uint16_t anonymized_src_suffix = mapping[src_suffix];
    uint32_t anonymized_src_ip = src_prefix | anonymized_src_suffix;
    ip_hdr->saddr = htonl(anonymized_src_ip);

    uint32_t dst_ip = ntohl(ip_hdr->daddr);
    uint32_t dst_prefix = dst_ip & 0xFFFF0000;
    uint16_t dst_suffix = dst_ip & 0X0000FFFF;
    uint16_t anonymized_dst_suffix = mapping[dst_suffix];
    uint32_t anonymized_dst_ip = dst_prefix | anonymized_dst_suffix;
    ip_hdr->daddr = htonl(anonymized_dst_ip);
}