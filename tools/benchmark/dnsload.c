#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int sock;
static atomic_long received, rc_counts[16];
static volatile int stop_rx;

#define LAT_BUCKET_US 10
#define LAT_BUCKETS 200000
static double send_ts[65536];
static atomic_long lat_hist[LAT_BUCKETS];
static atomic_long lat_count, lat_overflow;
static double lat_sum_us;
static double lat_max_us;
static volatile double measure_from;
static int timeline;
static double start_time;
static long tl_count[3600], tl_slow[3600];
static double tl_max[3600];

static char **blk_names;
static size_t blk_count;

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void)
{
    uint64_t x = rng_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    rng_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int put_name(uint8_t *p, const char *name)
{
    int off = 0;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        int len = dot ? (int)(dot - s) : (int)strlen(s);
        p[off++] = (uint8_t)len;
        memcpy(p + off, s, len);
        off += len;
        if (!dot) break;
        s = dot + 1;
    }
    p[off++] = 0;
    return off;
}

static int build_query(uint8_t *buf, uint16_t id, const char *name, uint16_t qtype)
{
    uint8_t *p = buf;
    p[0] = id >> 8; p[1] = id & 0xff;
    p[2] = 0x01; p[3] = 0x00;
    p[4] = 0; p[5] = 1; p[6] = 0; p[7] = 0; p[8] = 0; p[9] = 0; p[10] = 0; p[11] = 1;
    int off = 12 + put_name(p + 12, name);
    p[off++] = qtype >> 8; p[off++] = qtype & 0xff;
    p[off++] = 0; p[off++] = 1;
    p[off++] = 0;
    p[off++] = 0; p[off++] = 41;
    p[off++] = 0x04; p[off++] = 0xd0;
    p[off++] = 0; p[off++] = 0; p[off++] = 0; p[off++] = 0;
    p[off++] = 0; p[off++] = 0;
    return off;
}

static double now_s(void);

static void *rx_thread(void *arg)
{
    uint8_t buf[4096];
    (void)arg;
    while (!stop_rx) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n < 12) continue;
        double t = now_s();
        atomic_fetch_add(&received, 1);
        atomic_fetch_add(&rc_counts[buf[3] & 0x0f], 1);
        uint16_t rid = ((uint16_t)buf[0] << 8) | buf[1];
        double sent_at = send_ts[rid];
        if (sent_at > 0 && sent_at >= measure_from) {
            double us = (t - sent_at) * 1e6;
            if (us < 0) continue;
            long b = (long)(us / LAT_BUCKET_US);
            if (b >= LAT_BUCKETS) atomic_fetch_add(&lat_overflow, 1);
            else atomic_fetch_add(&lat_hist[b], 1);
            atomic_fetch_add(&lat_count, 1);
            lat_sum_us += us;
            if (us > lat_max_us) lat_max_us = us;
            if (timeline) {
                long sec = (long)(t - start_time);
                if (sec >= 0 && sec < 3600) {
                    tl_count[sec]++;
                    if (us > 1000) tl_slow[sec]++;
                    if (us > tl_max[sec]) tl_max[sec] = us;
                }
            }
        }
    }
    return NULL;
}

static double percentile(double p)
{
    long total = atomic_load(&lat_count);
    if (total == 0) return 0;
    long want = (long)(total * p);
    long acc = 0;
    for (long i = 0; i < LAT_BUCKETS; i++) {
        acc += atomic_load(&lat_hist[i]);
        if (acc > want) return (i + 0.5) * LAT_BUCKET_US;
    }
    return LAT_BUCKETS * LAT_BUCKET_US;
}

static void load_blk(const char *path, size_t max)
{
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(1); }
    char line[512];
    size_t cap = 1024;
    blk_names = malloc(cap * sizeof(char *));
    while (fgets(line, sizeof(line), f) && blk_count < max) {
        if (line[0] == '#' || line[0] == '\n') continue;
        line[strcspn(line, "\r\n")] = 0;
        if (blk_count == cap) { cap *= 2; blk_names = realloc(blk_names, cap * sizeof(char *)); }
        blk_names[blk_count++] = strdup(line);
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc < 9) {
        fprintf(stderr, "usage: %s server qps seconds clients_base clients_count pct_random pct_nx pct_blocked [blockfile] [popular_count] [seed]\n", argv[0]);
        return 1;
    }
    const char *server = argv[1];
    double qps = atof(argv[2]);
    double seconds = atof(argv[3]);
    uint32_t cbase = ntohl(inet_addr(argv[4]));
    uint32_t ccount = (uint32_t)atol(argv[5]);
    int pct_random = atoi(argv[6]);
    int pct_nx = atoi(argv[7]);
    int pct_blk = atoi(argv[8]);
    const char *blkfile = argc > 9 ? argv[9] : NULL;
    int popular = argc > 10 ? atoi(argv[10]) : 5000;
    if (argc > 11) rng_state += strtoull(argv[11], NULL, 10) * 0xD1B54A32D192ED03ULL;
    if (rng_state == 0) rng_state = 1;
    for (int i = 0; i < 16; i++) rnd();

    if (pct_blk > 0 && blkfile) load_blk(blkfile, 3000000);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    setsockopt(sock, SOL_IP, IP_FREEBIND, &one, sizeof(one));
    int big = 32 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &big, sizeof(big));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &big, sizeof(big));
    struct sockaddr_in local = { .sin_family = AF_INET, .sin_port = htons(40000 + (getpid() % 20000)), .sin_addr.s_addr = INADDR_ANY };
    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) { perror("bind"); return 1; }
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in dst = { .sin_family = AF_INET, .sin_port = htons(53) };
    inet_pton(AF_INET, server, &dst.sin_addr);

    pthread_t th;
    pthread_create(&th, NULL, rx_thread, NULL);

    enum { BATCH = 64 };
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    uint8_t bufs[BATCH][600];
    uint8_t cbufs[BATCH][CMSG_SPACE(sizeof(struct in_pktinfo))];
    char name[300];

    double start = now_s();
    start_time = start;
    timeline = getenv("DNSLOAD_TIMELINE") != NULL;
    measure_from = start + (seconds > 10 ? 3.0 : 0.0);
    long sent = 0;
    double last_report = start;
    long last_sent = 0, last_recv = 0;
    uint16_t id = 1;

    while (1) {
        double t = now_s();
        double elapsed = t - start;
        if (elapsed >= seconds) break;
        long target = (long)(elapsed * qps);
        int n = 0;
        while (sent + n < target && n < BATCH) {
            int r = (int)(rnd() % 100);
            uint16_t qtype = (rnd() % 4 == 0) ? 28 : 1;
            if (r < pct_random) {
                snprintf(name, sizeof(name), "r%012llx.deadtld", (unsigned long long)(rnd() & 0xffffffffffffULL));
            } else if (r < pct_random + pct_nx) {
                snprintf(name, sizeof(name), "nx%012llx.deadtld", (unsigned long long)(rnd() & 0xffffffffffffULL));
            } else if (r < pct_random + pct_nx + pct_blk && blk_count > 0) {
                snprintf(name, sizeof(name), "%s", blk_names[rnd() % blk_count]);
            } else {
                snprintf(name, sizeof(name), "w%d.deadtld", (int)(rnd() % (uint64_t)popular));
            }
            send_ts[id] = t;
            int len = build_query(bufs[n], id++, name, qtype);
            iovs[n].iov_base = bufs[n];
            iovs[n].iov_len = len;
            memset(&msgs[n].msg_hdr, 0, sizeof(struct msghdr));
            msgs[n].msg_hdr.msg_name = &dst;
            msgs[n].msg_hdr.msg_namelen = sizeof(dst);
            msgs[n].msg_hdr.msg_iov = &iovs[n];
            msgs[n].msg_hdr.msg_iovlen = 1;
            msgs[n].msg_hdr.msg_control = cbufs[n];
            msgs[n].msg_hdr.msg_controllen = sizeof(cbufs[n]);
            struct cmsghdr *cm = CMSG_FIRSTHDR(&msgs[n].msg_hdr);
            cm->cmsg_level = IPPROTO_IP;
            cm->cmsg_type = IP_PKTINFO;
            cm->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cm);
            memset(pi, 0, sizeof(*pi));
            uint32_t cip = cbase + (uint32_t)(rnd() % ccount);
            pi->ipi_spec_dst.s_addr = htonl(cip);
            n++;
        }
        if (n > 0) {
            int s = sendmmsg(sock, msgs, n, 0);
            if (s < 0) {
                if (errno != EAGAIN && errno != ENOBUFS) { perror("sendmmsg"); }
                usleep(1000);
            } else {
                sent += s;
            }
        } else {
            usleep(500);
        }
        if (t - last_report >= 10.0) {
            long rcv = atomic_load(&received);
            fprintf(stderr, "[%.0fs] sent %ld (%.0f/s) recv %ld (%.0f/s)\n", elapsed, sent, (sent - last_sent) / (t - last_report), rcv, (rcv - last_recv) / (t - last_report));
            last_report = t; last_sent = sent; last_recv = rcv;
        }
    }
    sleep(2);
    stop_rx = 1;
    pthread_join(th, NULL);
    long rcv = atomic_load(&received);
    printf("sent=%ld recv=%ld noerror=%ld servfail=%ld nxdomain=%ld refused=%ld\n", sent, rcv, atomic_load(&rc_counts[0]), atomic_load(&rc_counts[2]), atomic_load(&rc_counts[3]), atomic_load(&rc_counts[5]));
    if (timeline) {
        time_t wall = time(NULL) - (time_t)(now_s() - start);
        for (long i = 0; i < 3600 && i < (long)seconds + 2; i++) {
            if (tl_count[i] == 0) continue;
            struct tm tmv;
            time_t w = wall + i;
            localtime_r(&w, &tmv);
            fprintf(stderr, "t %02d:%02d:%02d n=%ld slow1ms=%ld max_us=%.0f\n", tmv.tm_hour, tmv.tm_min, tmv.tm_sec, tl_count[i], tl_slow[i], tl_max[i]);
        }
    }
    long lc = atomic_load(&lat_count);
    printf("latency_us mean=%.0f p50=%.0f p90=%.0f p99=%.0f p999=%.0f max=%.0f samples=%ld over2s=%ld\n", lc ? lat_sum_us / lc : 0, percentile(0.50), percentile(0.90), percentile(0.99), percentile(0.999), lat_max_us, lc, atomic_load(&lat_overflow));
    return 0;
}
