#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

char *target_host = NULL;

/* HTTP Host 헤더 확인 함수 */
static int is_harmful_site(unsigned char *data, int data_len) {
    struct iphdr *ip_header = (struct iphdr *)data;
    if (ip_header->protocol != IPPROTO_TCP) {
        return 0; // TCP가 아니면 통과
    }
    
    // IP 헤더 길이 계산
    int ip_header_len = ip_header->ihl * 4;
    struct tcphdr *tcp_header = (struct tcphdr *)(data + ip_header_len);
    
    // TCP 헤더 길이 계산
    int tcp_header_len = tcp_header->doff * 4;
    unsigned char *http_data = data + ip_header_len + tcp_header_len;
    int http_data_len = data_len - (ip_header_len + tcp_header_len);
    
    // HTTP 트래픽인지 확인 (포트 80)
    if (ntohs(tcp_header->dest) != 80) {
        return 0;
    }
    
    // HTTP 헤더에서 "Host: " 찾기
    char host_header[512] = {0,};
    char *host_pos = NULL;
    char *host_end = NULL;
    
    for (int i = 0; i < http_data_len - 7; i++) {
        if (memcmp(http_data + i, "Host: ", 6) == 0) {
            host_pos = (char *)(http_data + i + 6);
            
            // 호스트 끝 찾기 (CR, LF, 또는 공백)
            host_end = strchr(host_pos, '\r');
            if (!host_end) host_end = strchr(host_pos, '\n');
            if (!host_end) host_end = strchr(host_pos, ' ');
            
            if (host_end) {
                int host_len = host_end - host_pos;
                if (host_len < 512) {
                    strncpy(host_header, host_pos, host_len);
                    host_header[host_len] = '\0';
                    
                    printf("Found HTTP Host: %s\n", host_header);
                    
                    // 타겟 호스트와 비교
                    if (strcmp(host_header, target_host) == 0) {
                        printf("유해 사이트 발견: %s\n", target_host);
                        return 1; // 유해 사이트
                    }
                }
            }
            break;
        }
    }
    
    return 0; // 유해하지 않음
}

/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen - 1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen - 1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d\n", ret);

    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    unsigned char *packet_data;
    int packet_len = nfq_get_payload(nfa, &packet_data);
    
    printf("entering callback\n");
    
    if (packet_len >= 0) {
        // 유해 사이트인지 확인
        if (is_harmful_site(packet_data, packet_len)) {
            printf("유해 사이트 차단!\n");
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    }
    
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void print_usage() {
    printf("사용법: netfilter-test <hostname>\n");
    printf("예시: netfilter-test test.gilgil.net\n");
}

int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    if (argc != 2) {
        print_usage();
        exit(1);
    }
    
    target_host = argv[1];
    printf("대상 호스트: %s\n", target_host);

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);


    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
