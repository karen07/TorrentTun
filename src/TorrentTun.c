#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef GIT_COMMIT_STR
#define GIT_COMMIT_STR "dev"
#endif

#define TORRENTTUN_VERSION "1.0.0 " GIT_COMMIT_STR

#define SERVER_MODE 0
#define CLIENT_MODE 1

#define SESSION_INIT 0
#define SESSION_HANDSHAKE_SENT 1
#define SESSION_HANDSHAKE_DONE 2
#define SESSION_READY 3

#define MAX_ERRNO 4096
#define MAX_PACKET_SIZE 65535
#define DEFAULT_MAX_PAYLOAD_SIZE 4096

#define PROTO_PSTR "BitTorrent protocol"
#define PROTO_PSTRLEN 19
#define RESERVED_SIZE 8
#define INFO_HASH_SIZE 20
#define PEER_ID_SIZE 20
#define BT_HANDSHAKE_SIZE (1 + PROTO_PSTRLEN + RESERVED_SIZE + INFO_HASH_SIZE + PEER_ID_SIZE)

#define BT_MSG_CHOKE 0
#define BT_MSG_UNCHOKE 1
#define BT_MSG_PIECE 7

#define PIECE_INDEX_DATA 0

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16

#define PRINT_TS_TO(fp)                                                                   \
    do {                                                                                  \
        time_t now_ts = time(NULL);                                                       \
        struct tm tm_now;                                                                 \
        localtime_r(&now_ts, &tm_now);                                                    \
        fprintf((fp), "[%02d:%02d:%02d] ", tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec); \
    } while (0)

/* ===================== netaddr ===================== */

typedef struct {
    struct sockaddr_storage ss;
    socklen_t len;
} netaddr_t;

static void netaddr_clear(netaddr_t *a)
{
    memset(a, 0, sizeof(*a));
}

static sa_family_t netaddr_family(const netaddr_t *a)
{
    return ((const struct sockaddr *)&a->ss)->sa_family;
}

static socklen_t sockaddr_len_by_family(sa_family_t family)
{
    if (family == AF_INET) {
        return (socklen_t)sizeof(struct sockaddr_in);
    }

    if (family == AF_INET6) {
        return (socklen_t)sizeof(struct sockaddr_in6);
    }

    return 0;
}

static int32_t netaddr_from_sockaddr(netaddr_t *dst, const struct sockaddr *sa, socklen_t len)
{
    if (!dst || !sa) {
        return -EINVAL;
    }

    if (sa->sa_family != AF_INET && sa->sa_family != AF_INET6) {
        return -EAFNOSUPPORT;
    }

    socklen_t need = sockaddr_len_by_family(sa->sa_family);
    if (len < need) {
        return -EINVAL;
    }

    memset(dst, 0, sizeof(*dst));
    memcpy(&dst->ss, sa, need);
    dst->len = need;
    return 0;
}

static int32_t netaddr_copy(netaddr_t *dst, const netaddr_t *src)
{
    if (!dst || !src) {
        return -EINVAL;
    }

    memcpy(dst, src, sizeof(*dst));
    return 0;
}

static int32_t netaddr_equal(const netaddr_t *a, const netaddr_t *b)
{
    sa_family_t fa = netaddr_family(a);
    sa_family_t fb = netaddr_family(b);

    if (fa != fb) {
        return 0;
    }

    if (fa == AF_INET) {
        const struct sockaddr_in *aa = (const struct sockaddr_in *)&a->ss;
        const struct sockaddr_in *bb = (const struct sockaddr_in *)&b->ss;

        return aa->sin_port == bb->sin_port && aa->sin_addr.s_addr == bb->sin_addr.s_addr;
    }

    if (fa == AF_INET6) {
        const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)&a->ss;
        const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)&b->ss;

        return aa->sin6_port == bb->sin6_port && aa->sin6_scope_id == bb->sin6_scope_id &&
               memcmp(&aa->sin6_addr, &bb->sin6_addr, sizeof(struct in6_addr)) == 0;
    }

    return 0;
}

static int32_t netaddr_is_unspecified(const netaddr_t *a)
{
    if (netaddr_family(a) == AF_INET) {
        return ((const struct sockaddr_in *)&a->ss)->sin_addr.s_addr == htonl(INADDR_ANY);
    }

    if (netaddr_family(a) == AF_INET6) {
        static const struct in6_addr zero = IN6ADDR_ANY_INIT;
        return memcmp(&((const struct sockaddr_in6 *)&a->ss)->sin6_addr, &zero, sizeof(zero)) == 0;
    }

    return 1;
}

static const void *netaddr_addr_ptr(const netaddr_t *a)
{
    if (netaddr_family(a) == AF_INET) {
        return &((const struct sockaddr_in *)&a->ss)->sin_addr;
    }

    if (netaddr_family(a) == AF_INET6) {
        return &((const struct sockaddr_in6 *)&a->ss)->sin6_addr;
    }

    return NULL;
}

static const char *netaddr_ip_to_string(const netaddr_t *a, char *buf, size_t buflen)
{
    const void *src = netaddr_addr_ptr(a);
    if (!src) {
        return NULL;
    }

    return inet_ntop(netaddr_family(a), src, buf, (socklen_t)buflen);
}

static uint16_t netaddr_port(const netaddr_t *a)
{
    if (netaddr_family(a) == AF_INET) {
        return ntohs(((const struct sockaddr_in *)&a->ss)->sin_port);
    }

    if (netaddr_family(a) == AF_INET6) {
        return ntohs(((const struct sockaddr_in6 *)&a->ss)->sin6_port);
    }

    return 0;
}

static void netaddr_to_string(const netaddr_t *a, char *buf, size_t buflen)
{
    char ip[INET6_ADDRSTRLEN] = { 0 };
    const char *ip_s = netaddr_ip_to_string(a, ip, sizeof(ip));
    if (!ip_s) {
        snprintf(buf, buflen, "(invalid)");
        return;
    }

    if (netaddr_family(a) == AF_INET6) {
        snprintf(buf, buflen, "[%s]:%u", ip_s, (unsigned)netaddr_port(a));
    } else {
        snprintf(buf, buflen, "%s:%u", ip_s, (unsigned)netaddr_port(a));
    }
}

static int32_t parse_addrport(const char *val, netaddr_t *out)
{
    char *tmp = strdup(val);
    if (!tmp) {
        return -ENOMEM;
    }

    char *s = tmp;
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == 0) {
        free(tmp);
        return -EINVAL;
    }

    char *end = s + strlen(s) - 1;
    while (end >= s && isspace((unsigned char)*end)) {
        *end-- = 0;
    }

    char *host = NULL;
    char *port_str = NULL;

    if (*s == '[') {
        char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':') {
            free(tmp);
            return -EINVAL;
        }
        *rb = 0;
        host = s + 1;
        port_str = rb + 2;
    } else {
        char *first = strchr(s, ':');
        char *last = strrchr(s, ':');

        if (!first || first != last) {
            free(tmp);
            return -EINVAL;
        }

        *last = 0;
        host = s;
        port_str = last + 1;
    }

    while (*host && isspace((unsigned char)*host)) {
        host++;
    }
    while (*port_str && isspace((unsigned char)*port_str)) {
        port_str++;
    }

    if (*host == 0 || *port_str == 0) {
        free(tmp);
        return -EINVAL;
    }

    char *endp = NULL;
    errno = 0;
    long port = strtol(port_str, &endp, 10);
    if (errno != 0 || endp == port_str || *endp != 0 || port <= 0 || port > 65535) {
        free(tmp);
        return -EINVAL;
    }

    struct sockaddr_in sa4;
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
    sa4.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &sa4.sin_addr) == 1) {
        netaddr_clear(out);
        memcpy(&out->ss, &sa4, sizeof(sa4));
        out->len = sizeof(sa4);
        free(tmp);
        return 0;
    }

    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port = htons((uint16_t)port);

    if (inet_pton(AF_INET6, host, &sa6.sin6_addr) == 1) {
        netaddr_clear(out);
        memcpy(&out->ss, &sa6, sizeof(sa6));
        out->len = sizeof(sa6);
        free(tmp);
        return 0;
    }

    free(tmp);
    return -EINVAL;
}

/* ===================== stats ===================== */

typedef struct {
    uint64_t sendto_input[MAX_ERRNO];
    uint64_t sendto_peer[MAX_ERRNO];
    uint64_t recvfrom_input[MAX_ERRNO];
    uint64_t recvfrom_peer[MAX_ERRNO];
} errors_stat_t;
static errors_stat_t errors_stat;

typedef struct {
    uint64_t recvfrom_input_ptks;
    uint64_t recvfrom_input_bytes;

    uint64_t recvfrom_peer_ptks;
    uint64_t recvfrom_peer_bytes;

    uint64_t sendto_input_ptks;
    uint64_t sendto_input_bytes;

    uint64_t sendto_peer_ptks;
    uint64_t sendto_peer_bytes;

    uint64_t drop_input_ptks;
    uint64_t drop_input_bytes;

    uint64_t drop_peer_ptks;
    uint64_t drop_peer_bytes;
} data_stat_t;
static data_stat_t data_stat;

#define ERRNO_ADD(prefix)                     \
    do {                                      \
        if (errno > 0 && errno < MAX_ERRNO) { \
            errors_stat.prefix[errno]++;      \
        }                                     \
    } while (0)

#define STAT_ADD(prefix, len)                        \
    do {                                             \
        data_stat.prefix##_ptks++;                   \
        data_stat.prefix##_bytes += (uint64_t)(len); \
    } while (0)

#define PRINT_DATA_STAT(fp, prefix)                                                       \
    do {                                                                                  \
        if (data_stat.prefix##_ptks != 0) {                                               \
            fprintf((fp), "  " #prefix "_ptks %" PRIu64 "\n", data_stat.prefix##_ptks);   \
        }                                                                                 \
        if (data_stat.prefix##_bytes != 0) {                                              \
            fprintf((fp), "  " #prefix "_bytes %" PRIu64 "\n", data_stat.prefix##_bytes); \
        }                                                                                 \
    } while (0)

#define PRINT_ERRNO_STAT(fp, arr_field)                                           \
    do {                                                                          \
        for (int32_t e = 1; e < MAX_ERRNO; e++) {                                 \
            if (errors_stat.arr_field[e] != 0) {                                  \
                fprintf((fp), "  " #arr_field " errno=%d count=%" PRIu64 "\n", e, \
                        errors_stat.arr_field[e]);                                \
            }                                                                     \
        }                                                                         \
    } while (0)

/* ===================== config ===================== */

typedef struct {
    int32_t have_input_listen;
    netaddr_t input_listen_addr;

    int32_t have_input_target;
    netaddr_t input_target_addr;

    int32_t have_peer_listen;
    netaddr_t peer_listen_addr;

    int32_t have_peer_endpoint;
    netaddr_t peer_endpoint_addr;

    int32_t have_log_path;
    char *log_path;

    int32_t have_stat_path;
    char *stat_path;

    int32_t have_psk;
    uint8_t pre_shared_key[KEY_SIZE];

    int32_t have_info_hash;
    uint8_t info_hash[INFO_HASH_SIZE];

    int32_t have_peer_id_prefix;
    char peer_id_prefix[9];

    int32_t have_max_payload_size;
    size_t max_payload_size;
} torrenttun_config_t;

static torrenttun_config_t cfg_global;

/* ===================== runtime ===================== */

typedef struct {
    int32_t role;

    int32_t input_sock;
    int32_t peer_sock;

    netaddr_t input_listen_addr;
    netaddr_t input_target_addr;
    netaddr_t peer_listen_addr;

    netaddr_t peer_remote_addr;
    int32_t have_peer_remote;

    uint8_t info_hash[INFO_HASH_SIZE];
    uint8_t peer_id[PEER_ID_SIZE];
    uint8_t remote_peer_id[PEER_ID_SIZE];

    int32_t session_state;
    int32_t unchoke_sent;
    int32_t unchoke_recv;

    uint32_t send_seq;
    uint32_t recv_seq;
    uint64_t rx_packets_mark;

    EVP_CIPHER_CTX *enc_ctx;
    EVP_CIPHER_CTX *dec_ctx;

    uint8_t key[KEY_SIZE];
    uint8_t nonce_prefix[8];

    size_t max_payload_size;
} app_t;

static volatile sig_atomic_t exit_flag = 0;
static FILE *log_file = NULL;
static FILE *stat_file = NULL;

/* ===================== helpers ===================== */

static void errmsg(const char *format, ...)
{
    va_list args;

    fprintf(stderr, "Error: ");

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fflush(stderr);
    exit(1);
}

static void main_catch_function(int32_t signo)
{
    (void)signo;
    exit_flag = 1;
}

static int32_t set_sock_nonblocking(int32_t fd)
{
    int32_t flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }

    if (flags & O_NONBLOCK) {
        return 0;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    return 0;
}

static int32_t make_udp_socket_bind(const netaddr_t *bind_addr)
{
    int32_t fd = socket(netaddr_family(bind_addr), SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -errno;
    }

    if (set_sock_nonblocking(fd) < 0) {
        int32_t rc = -errno;
        close(fd);
        return rc;
    }

    if (bind(fd, (const struct sockaddr *)&bind_addr->ss, bind_addr->len) < 0) {
        int32_t rc = -errno;
        close(fd);
        return rc;
    }

    return fd;
}

static void random_bytes_or_die(uint8_t *p, size_t n)
{
    if (RAND_bytes(p, (int32_t)n) != 1) {
        errmsg("RAND_bytes failed\n");
    }
}

static void hex_encode(const uint8_t *in, size_t n, char *out, size_t out_sz)
{
    static const char hexd[] = "0123456789abcdef";

    if (out_sz < n * 2 + 1) {
        if (out_sz > 0) {
            out[0] = 0;
        }
        return;
    }

    for (size_t i = 0; i < n; i++) {
        out[i * 2 + 0] = hexd[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hexd[in[i] & 0x0F];
    }

    out[n * 2] = 0;
}

static void log_line(const char *fmt, ...)
{
    va_list args;

    PRINT_TS_TO(stderr);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");

    if (log_file) {
        PRINT_TS_TO(log_file);
        va_start(args, fmt);
        vfprintf(log_file, fmt, args);
        va_end(args);
        fprintf(log_file, "\n");
    }
}

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }

    if (*s == 0) {
        return s;
    }

    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) {
        *e-- = 0;
    }

    return s;
}

static void strip_comment(char *s)
{
    for (; *s; s++) {
        if (*s == '#' || *s == ';') {
            *s = 0;
            return;
        }
    }
}

static int32_t set_string(char **dst, const char *src)
{
    char *p = strdup(src);
    if (!p) {
        return -ENOMEM;
    }

    free(*dst);
    *dst = p;
    return 0;
}

static int32_t parse_hex_exact(const char *src, uint8_t *out, size_t out_len)
{
    size_t src_len = strlen(src);
    if (src_len != out_len * 2) {
        return -EINVAL;
    }

    for (size_t i = 0; i < out_len; i++) {
        char a = src[i * 2 + 0];
        char b = src[i * 2 + 1];

        int hi = isdigit((unsigned char)a)  ? a - '0' :
                 isxdigit((unsigned char)a) ? (tolower((unsigned char)a) - 'a' + 10) :
                                              -1;
        int lo = isdigit((unsigned char)b)  ? b - '0' :
                 isxdigit((unsigned char)b) ? (tolower((unsigned char)b) - 'a' + 10) :
                                              -1;
        if (hi < 0 || lo < 0) {
            return -EINVAL;
        }

        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static void cfg_init(torrenttun_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_payload_size = DEFAULT_MAX_PAYLOAD_SIZE;
}

static void cfg_free(torrenttun_config_t *cfg)
{
    free(cfg->log_path);
    free(cfg->stat_path);
    cfg_init(cfg);
}

static int32_t apply_interface_kv(torrenttun_config_t *cfg, const char *key, const char *val)
{
    if (strcmp(key, "InputListen") == 0) {
        if (cfg->have_input_listen) {
            return -EEXIST;
        }

        int32_t rc = parse_addrport(val, &cfg->input_listen_addr);
        if (rc == 0) {
            if (netaddr_is_unspecified(&cfg->input_listen_addr)) {
                return -EINVAL;
            }
            cfg->have_input_listen = 1;
        }
        return rc;
    }

    if (strcmp(key, "InputTarget") == 0) {
        if (cfg->have_input_target) {
            return -EEXIST;
        }

        int32_t rc = parse_addrport(val, &cfg->input_target_addr);
        if (rc == 0) {
            if (netaddr_is_unspecified(&cfg->input_target_addr)) {
                return -EINVAL;
            }
            cfg->have_input_target = 1;
        }
        return rc;
    }

    if (strcmp(key, "PeerListen") == 0) {
        if (cfg->have_peer_listen) {
            return -EEXIST;
        }

        int32_t rc = parse_addrport(val, &cfg->peer_listen_addr);
        if (rc == 0) {
            if (netaddr_is_unspecified(&cfg->peer_listen_addr)) {
                return -EINVAL;
            }
            cfg->have_peer_listen = 1;
        }
        return rc;
    }

    if (strcmp(key, "PeerEndpoint") == 0) {
        if (cfg->have_peer_endpoint) {
            return -EEXIST;
        }

        int32_t rc = parse_addrport(val, &cfg->peer_endpoint_addr);
        if (rc == 0) {
            if (netaddr_is_unspecified(&cfg->peer_endpoint_addr)) {
                return -EINVAL;
            }
            cfg->have_peer_endpoint = 1;
        }
        return rc;
    }

    if (strcmp(key, "LogPath") == 0) {
        if (cfg->have_log_path) {
            return -EEXIST;
        }

        int32_t rc = set_string(&cfg->log_path, trim((char *)val));
        if (rc == 0 && cfg->log_path && cfg->log_path[0] != 0) {
            cfg->have_log_path = 1;
            return 0;
        }
        return -EINVAL;
    }

    if (strcmp(key, "StatPath") == 0) {
        if (cfg->have_stat_path) {
            return -EEXIST;
        }

        int32_t rc = set_string(&cfg->stat_path, trim((char *)val));
        if (rc == 0 && cfg->stat_path && cfg->stat_path[0] != 0) {
            cfg->have_stat_path = 1;
            return 0;
        }
        return -EINVAL;
    }

    if (strcmp(key, "PreSharedKey") == 0) {
        if (cfg->have_psk) {
            return -EEXIST;
        }

        int32_t rc = parse_hex_exact(val, cfg->pre_shared_key, KEY_SIZE);
        if (rc == 0) {
            cfg->have_psk = 1;
        }
        return rc;
    }

    if (strcmp(key, "InfoHash") == 0) {
        if (cfg->have_info_hash) {
            return -EEXIST;
        }

        int32_t rc = parse_hex_exact(val, cfg->info_hash, INFO_HASH_SIZE);
        if (rc == 0) {
            cfg->have_info_hash = 1;
        }
        return rc;
    }

    if (strcmp(key, "PeerIdPrefix") == 0) {
        if (cfg->have_peer_id_prefix) {
            return -EEXIST;
        }

        size_t n = strlen(val);
        if (n == 0 || n > 8) {
            return -EINVAL;
        }

        memset(cfg->peer_id_prefix, 0, sizeof(cfg->peer_id_prefix));
        memcpy(cfg->peer_id_prefix, val, n);
        cfg->have_peer_id_prefix = 1;
        return 0;
    }

    if (strcmp(key, "MaxPayloadSize") == 0) {
        if (cfg->have_max_payload_size) {
            return -EEXIST;
        }

        char *endp = NULL;
        errno = 0;
        unsigned long v = strtoul(val, &endp, 10);
        if (errno != 0 || endp == val || *endp != 0) {
            return -EINVAL;
        }

        if (v == 0 || v > MAX_PACKET_SIZE - 128) {
            return -EINVAL;
        }

        cfg->max_payload_size = (size_t)v;
        cfg->have_max_payload_size = 1;
        return 0;
    }

    return -EINVAL;
}

static int32_t torrenttun_config_load_file(torrenttun_config_t *cfg, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -errno;
    }

    cfg_free(cfg);
    cfg_init(cfg);

    enum { SEC_NONE = 0, SEC_INTERFACE = 1 } sec = SEC_NONE;
    int32_t seen_interface = 0;

    char line[1024];
    uint32_t lineno = 0;
    int32_t rc = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        line[strcspn(line, "\r\n")] = 0;
        strip_comment(line);

        char *s = trim(line);
        if (*s == 0) {
            continue;
        }

        if (strcmp(s, "[Interface]") == 0) {
            if (seen_interface) {
                rc = -EEXIST;
                break;
            }
            seen_interface = 1;
            sec = SEC_INTERFACE;
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) {
            rc = -EINVAL;
            break;
        }

        *eq = 0;
        char *key = trim(s);
        char *val = trim(eq + 1);

        if (*key == 0 || *val == 0) {
            rc = -EINVAL;
            break;
        }

        if (sec != SEC_INTERFACE) {
            rc = -EINVAL;
            break;
        }

        rc = apply_interface_kv(cfg, key, val);
        if (rc != 0) {
            break;
        }
    }

    fclose(f);

    if (rc != 0) {
        cfg_free(cfg);

        if (rc == -EEXIST) {
            fprintf(stderr, "config parse error: %s:%u duplicate key or section\n", path, lineno);
        } else {
            fprintf(stderr, "config parse error: %s:%u rc=%d\n", path, lineno, rc);
        }
    }

    return rc;
}

static void cfg_print_addr(const char *name, int32_t have, const netaddr_t *a)
{
    if (!have) {
        fprintf(stderr, "%s: (not set)\n", name);
        return;
    }

    char full[128];
    netaddr_to_string(a, full, sizeof(full));
    fprintf(stderr, "%s: %s\n", name, full);
}

static void cfg_print_str(const char *name, int32_t have, const char *s)
{
    if (!have || !s) {
        fprintf(stderr, "%s: (not set)\n", name);
        return;
    }

    fprintf(stderr, "%s: %s\n", name, s);
}

static void cfg_print_hex(const char *name, int32_t have, const uint8_t *p, size_t n)
{
    if (!have) {
        fprintf(stderr, "%s: (not set)\n", name);
        return;
    }

    char buf[256];
    hex_encode(p, n, buf, sizeof(buf));
    fprintf(stderr, "%s: %s\n", name, buf);
}

static void torrenttun_config_log(const torrenttun_config_t *cfg)
{
    cfg_print_addr("InputListen", cfg->have_input_listen, &cfg->input_listen_addr);
    cfg_print_addr("InputTarget", cfg->have_input_target, &cfg->input_target_addr);
    cfg_print_addr("PeerListen", cfg->have_peer_listen, &cfg->peer_listen_addr);
    cfg_print_addr("PeerEndpoint", cfg->have_peer_endpoint, &cfg->peer_endpoint_addr);

    cfg_print_hex("PreSharedKey", cfg->have_psk, cfg->pre_shared_key, KEY_SIZE);
    cfg_print_hex("InfoHash", cfg->have_info_hash, cfg->info_hash, INFO_HASH_SIZE);

    if (cfg->have_peer_id_prefix) {
        fprintf(stderr, "PeerIdPrefix: %s\n", cfg->peer_id_prefix);
    } else {
        fprintf(stderr, "PeerIdPrefix: (default)\n");
    }

    fprintf(stderr, "MaxPayloadSize: %zu\n", cfg->max_payload_size);
    cfg_print_str("LogPath", cfg->have_log_path, cfg->log_path);
    cfg_print_str("StatPath", cfg->have_stat_path, cfg->stat_path);
}

/* ===================== peer id ===================== */

static void init_peer_id(uint8_t out[PEER_ID_SIZE], int32_t role, const torrenttun_config_t *cfg)
{
    memset(out, 0, PEER_ID_SIZE);

    if (cfg->have_peer_id_prefix) {
        size_t n = strlen(cfg->peer_id_prefix);
        memcpy(out, cfg->peer_id_prefix, n);
    } else if (role == CLIENT_MODE) {
        memcpy(out, "-BTCLN-", 7);
    } else {
        memcpy(out, "-BTSRV-", 7);
    }

    random_bytes_or_die(out + 8, PEER_ID_SIZE - 8);
}

/* ===================== crypto ===================== */

static int32_t crypto_init(app_t *app)
{
    random_bytes_or_die(app->nonce_prefix, sizeof(app->nonce_prefix));

    app->enc_ctx = EVP_CIPHER_CTX_new();
    app->dec_ctx = EVP_CIPHER_CTX_new();

    if (!app->enc_ctx || !app->dec_ctx) {
        return -ENOMEM;
    }

    if (EVP_EncryptInit_ex(app->enc_ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
        return -EINVAL;
    }

    if (EVP_DecryptInit_ex(app->dec_ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) {
        return -EINVAL;
    }

    if (EVP_CIPHER_CTX_ctrl(app->enc_ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_SIZE, NULL) != 1) {
        return -EINVAL;
    }

    if (EVP_CIPHER_CTX_ctrl(app->dec_ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_SIZE, NULL) != 1) {
        return -EINVAL;
    }

    if (EVP_EncryptInit_ex(app->enc_ctx, NULL, NULL, app->key, NULL) != 1) {
        return -EINVAL;
    }

    if (EVP_DecryptInit_ex(app->dec_ctx, NULL, NULL, app->key, NULL) != 1) {
        return -EINVAL;
    }

    return 0;
}

static void make_nonce_from_seq(const app_t *app, uint32_t seq, uint8_t nonce[NONCE_SIZE])
{
    memcpy(nonce, app->nonce_prefix, 8);

    uint32_t be_seq = htonl(seq);
    memcpy(nonce + 8, &be_seq, sizeof(be_seq));
}

/* ===================== protocol ===================== */

static size_t build_handshake(const app_t *app, uint8_t *out, size_t out_cap)
{
    if (out_cap < BT_HANDSHAKE_SIZE) {
        return 0;
    }

    size_t off = 0;

    out[off++] = PROTO_PSTRLEN;
    memcpy(out + off, PROTO_PSTR, PROTO_PSTRLEN);
    off += PROTO_PSTRLEN;

    memset(out + off, 0, RESERVED_SIZE);
    off += RESERVED_SIZE;

    memcpy(out + off, app->info_hash, INFO_HASH_SIZE);
    off += INFO_HASH_SIZE;

    memcpy(out + off, app->peer_id, PEER_ID_SIZE);
    off += PEER_ID_SIZE;

    return off;
}

static int32_t parse_handshake(app_t *app, const uint8_t *buf, size_t len)
{
    if (len != BT_HANDSHAKE_SIZE) {
        return -EINVAL;
    }

    if (buf[0] != PROTO_PSTRLEN) {
        return -EINVAL;
    }

    if (memcmp(buf + 1, PROTO_PSTR, PROTO_PSTRLEN) != 0) {
        return -EINVAL;
    }

    if (memcmp(buf + 1 + PROTO_PSTRLEN + RESERVED_SIZE, app->info_hash, INFO_HASH_SIZE) != 0) {
        return -EINVAL;
    }

    memcpy(app->remote_peer_id, buf + 1 + PROTO_PSTRLEN + RESERVED_SIZE + INFO_HASH_SIZE,
           PEER_ID_SIZE);

    return 0;
}

static size_t build_unchoke(uint8_t *out, size_t out_cap)
{
    if (out_cap < 5) {
        return 0;
    }

    uint32_t be_len = htonl(1);
    memcpy(out, &be_len, 4);
    out[4] = BT_MSG_UNCHOKE;

    return 5;
}

static int32_t parse_message_header(const uint8_t *buf, size_t len, uint32_t *msg_len,
                                    uint8_t *msg_id)
{
    if (len < 5) {
        return -EINVAL;
    }

    uint32_t be_len;
    memcpy(&be_len, buf, 4);

    *msg_len = ntohl(be_len);
    if (*msg_len == 0) {
        return -EINVAL;
    }

    if ((size_t)(4 + *msg_len) != len) {
        return -EINVAL;
    }

    *msg_id = buf[4];
    return 0;
}

static size_t build_piece(app_t *app, uint32_t piece_index, uint32_t begin_seq,
                          const uint8_t *payload, size_t payload_len, uint8_t *out, size_t out_cap)
{
    uint8_t nonce[NONCE_SIZE];
    uint8_t tag[TAG_SIZE];
    int32_t out_len = 0;
    int32_t fin_len = 0;

    if (payload_len > MAX_PACKET_SIZE) {
        return 0;
    }

    make_nonce_from_seq(app, begin_seq, nonce);

    size_t msg_body_len = 1 + 4 + 4 + NONCE_SIZE + TAG_SIZE + payload_len;
    size_t total_len = 4 + msg_body_len;

    if (total_len > out_cap || msg_body_len > UINT32_MAX) {
        return 0;
    }

    uint32_t be_len = htonl((uint32_t)msg_body_len);
    uint32_t be_index = htonl(piece_index);
    uint32_t be_begin = htonl(begin_seq);

    memcpy(out, &be_len, 4);
    out[4] = BT_MSG_PIECE;
    memcpy(out + 5, &be_index, 4);
    memcpy(out + 9, &be_begin, 4);
    memcpy(out + 13, nonce, NONCE_SIZE);

    if (EVP_EncryptInit_ex(app->enc_ctx, NULL, NULL, NULL, nonce) != 1) {
        return 0;
    }

    if (EVP_EncryptUpdate(app->enc_ctx, out + 13 + NONCE_SIZE + TAG_SIZE, &out_len, payload,
                          (int32_t)payload_len) != 1) {
        return 0;
    }

    if (EVP_EncryptFinal_ex(app->enc_ctx, out + 13 + NONCE_SIZE + TAG_SIZE + out_len, &fin_len) !=
        1) {
        return 0;
    }

    if (EVP_CIPHER_CTX_ctrl(app->enc_ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE, tag) != 1) {
        return 0;
    }

    memcpy(out + 13 + NONCE_SIZE, tag, TAG_SIZE);
    return total_len;
}

static int32_t parse_piece(app_t *app, const uint8_t *buf, size_t len, uint32_t *piece_index,
                           uint32_t *begin_seq, uint8_t *plaintext, size_t *plaintext_len)
{
    uint32_t msg_len = 0;
    uint8_t msg_id = 0;

    if (parse_message_header(buf, len, &msg_len, &msg_id) != 0) {
        return -EINVAL;
    }

    if (msg_id != BT_MSG_PIECE) {
        return -EINVAL;
    }

    if (msg_len < 1 + 4 + 4 + NONCE_SIZE + TAG_SIZE) {
        return -EINVAL;
    }

    uint32_t be_index;
    uint32_t be_begin;

    memcpy(&be_index, buf + 5, 4);
    memcpy(&be_begin, buf + 9, 4);

    *piece_index = ntohl(be_index);
    *begin_seq = ntohl(be_begin);

    const uint8_t *nonce = buf + 13;
    const uint8_t *tag = buf + 13 + NONCE_SIZE;
    const uint8_t *ciphertext = buf + 13 + NONCE_SIZE + TAG_SIZE;
    size_t ciphertext_len = msg_len - (1 + 4 + 4 + NONCE_SIZE + TAG_SIZE);

    int32_t out_len = 0;
    int32_t fin_len = 0;

    if (EVP_DecryptInit_ex(app->dec_ctx, NULL, NULL, NULL, nonce) != 1) {
        return -EINVAL;
    }

    if (EVP_CIPHER_CTX_ctrl(app->dec_ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, (void *)tag) != 1) {
        return -EINVAL;
    }

    if (EVP_DecryptUpdate(app->dec_ctx, plaintext, &out_len, ciphertext, (int32_t)ciphertext_len) !=
        1) {
        return -EINVAL;
    }

    if (EVP_DecryptFinal_ex(app->dec_ctx, plaintext + out_len, &fin_len) != 1) {
        return -EINVAL;
    }

    *plaintext_len = (size_t)(out_len + fin_len);
    return 0;
}

/* ===================== send helpers ===================== */

static int32_t sendto_addr(int32_t fd, const uint8_t *buf, size_t len, const netaddr_t *dst)
{
    ssize_t rc = sendto(fd, buf, len, 0, (const struct sockaddr *)&dst->ss, dst->len);

    if (rc < 0) {
        return -errno;
    }

    if ((size_t)rc != len) {
        return -EIO;
    }

    return 0;
}

/* ===================== session tx ===================== */

static void maybe_send_handshake(app_t *app)
{
    if (!app->have_peer_remote) {
        return;
    }

    if (app->session_state != SESSION_INIT) {
        return;
    }

    uint8_t buf[BT_HANDSHAKE_SIZE];
    size_t n = build_handshake(app, buf, sizeof(buf));
    if (n == 0) {
        return;
    }

    int32_t rc = sendto_addr(app->peer_sock, buf, n, &app->peer_remote_addr);
    if (rc != 0) {
        errno = -rc;
        ERRNO_ADD(sendto_peer);
        return;
    }

    app->session_state = SESSION_HANDSHAKE_SENT;
    STAT_ADD(sendto_peer, n);
    log_line("sent handshake");
}

static void maybe_send_unchoke(app_t *app)
{
    if (!app->have_peer_remote) {
        return;
    }

    if (app->unchoke_sent) {
        return;
    }

    if (app->session_state < SESSION_HANDSHAKE_DONE) {
        return;
    }

    uint8_t buf[5];
    size_t n = build_unchoke(buf, sizeof(buf));
    if (n == 0) {
        return;
    }

    int32_t rc = sendto_addr(app->peer_sock, buf, n, &app->peer_remote_addr);
    if (rc != 0) {
        errno = -rc;
        ERRNO_ADD(sendto_peer);
        return;
    }

    app->unchoke_sent = 1;
    STAT_ADD(sendto_peer, n);
    log_line("sent unchoke");
}

/* ===================== peer rx ===================== */

static void handle_peer_packet(app_t *app)
{
    uint8_t buf[MAX_PACKET_SIZE];
    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);
    memset(&from, 0, sizeof(from));

    ssize_t n = recvfrom(app->peer_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);

    if (n < 0) {
        ERRNO_ADD(recvfrom_peer);
        return;
    }

    STAT_ADD(recvfrom_peer, n);

    netaddr_t from_addr;
    if (netaddr_from_sockaddr(&from_addr, (struct sockaddr *)&from, from_len) != 0) {
        STAT_ADD(drop_peer, n);
        return;
    }

    if (!app->have_peer_remote) {
        netaddr_copy(&app->peer_remote_addr, &from_addr);
        app->have_peer_remote = 1;

        char full[128];
        netaddr_to_string(&app->peer_remote_addr, full, sizeof(full));
        log_line("peer remote learned: %s", full);
    } else if (!netaddr_equal(&app->peer_remote_addr, &from_addr)) {
        char full[128];
        netaddr_to_string(&from_addr, full, sizeof(full));
        log_line("dropped peer packet from unexpected addr: %s", full);
        STAT_ADD(drop_peer, n);
        return;
    }

    if ((size_t)n == BT_HANDSHAKE_SIZE && parse_handshake(app, buf, (size_t)n) == 0) {
        log_line("received handshake");

        if (app->session_state == SESSION_INIT) {
            uint8_t hs[BT_HANDSHAKE_SIZE];
            size_t hs_len = build_handshake(app, hs, sizeof(hs));

            if (hs_len != 0) {
                int32_t rc = sendto_addr(app->peer_sock, hs, hs_len, &app->peer_remote_addr);
                if (rc == 0) {
                    STAT_ADD(sendto_peer, hs_len);
                    log_line("replied handshake");
                } else {
                    errno = -rc;
                    ERRNO_ADD(sendto_peer);
                }
            }
        }

        app->session_state = SESSION_HANDSHAKE_DONE;
        maybe_send_unchoke(app);
        return;
    }

    uint32_t msg_len = 0;
    uint8_t msg_id = 0;

    if (parse_message_header(buf, (size_t)n, &msg_len, &msg_id) != 0) {
        log_line("dropped malformed peer packet");
        STAT_ADD(drop_peer, n);
        return;
    }

    if (msg_id == BT_MSG_UNCHOKE) {
        app->unchoke_recv = 1;

        if (app->session_state < SESSION_READY) {
            app->session_state = SESSION_READY;
        }

        log_line("received unchoke");
        return;
    }

    if (msg_id == BT_MSG_PIECE) {
        uint8_t plain[MAX_PACKET_SIZE];
        size_t plain_len = 0;
        uint32_t piece_index = 0;
        uint32_t begin_seq = 0;

        if (parse_piece(app, buf, (size_t)n, &piece_index, &begin_seq, plain, &plain_len) != 0) {
            log_line("dropped invalid piece");
            STAT_ADD(drop_peer, n);
            return;
        }

        if (app->rx_packets_mark != 0 && begin_seq < app->recv_seq) {
            log_line("received old seq=%" PRIu32 " last=%" PRIu32, begin_seq, app->recv_seq);
        }

        app->recv_seq = begin_seq;
        app->rx_packets_mark = 1;

        int32_t rc = sendto_addr(app->input_sock, plain, plain_len, &app->input_target_addr);
        if (rc != 0) {
            errno = -rc;
            ERRNO_ADD(sendto_input);
            STAT_ADD(drop_peer, n);
            return;
        }

        STAT_ADD(sendto_input, plain_len);

        log_line("received piece index=%" PRIu32 " begin(seq)=%" PRIu32 " bytes=%zu", piece_index,
                 begin_seq, plain_len);
        return;
    }

    log_line("received unsupported msg id=%u", (unsigned)msg_id);
    STAT_ADD(drop_peer, n);
}

/* ===================== input rx ===================== */

static void handle_input_packet(app_t *app)
{
    uint8_t plain[MAX_PACKET_SIZE];
    struct sockaddr_storage from;
    socklen_t from_len = sizeof(from);
    memset(&from, 0, sizeof(from));

    ssize_t n = recvfrom(app->input_sock, plain, app->max_payload_size, 0, (struct sockaddr *)&from,
                         &from_len);

    if (n < 0) {
        ERRNO_ADD(recvfrom_input);
        return;
    }

    STAT_ADD(recvfrom_input, n);

    if (!app->have_peer_remote) {
        log_line("input packet dropped: remote peer address is unknown");
        STAT_ADD(drop_input, n);
        return;
    }

    if (app->session_state == SESSION_INIT) {
        maybe_send_handshake(app);
        log_line("input packet dropped: waiting for handshake");
        STAT_ADD(drop_input, n);
        return;
    }

    if (app->session_state < SESSION_HANDSHAKE_DONE) {
        log_line("input packet dropped: handshake not done");
        STAT_ADD(drop_input, n);
        return;
    }

    maybe_send_unchoke(app);

    if (!app->unchoke_sent || !app->unchoke_recv) {
        log_line("input packet dropped: waiting for mutual unchoke");
        STAT_ADD(drop_input, n);
        return;
    }

    uint8_t out[MAX_PACKET_SIZE];
    uint32_t seq = app->send_seq++;

    size_t out_len = build_piece(app, PIECE_INDEX_DATA, seq, plain, (size_t)n, out, sizeof(out));
    if (out_len == 0) {
        log_line("build_piece failed");
        STAT_ADD(drop_input, n);
        return;
    }

    int32_t rc = sendto_addr(app->peer_sock, out, out_len, &app->peer_remote_addr);
    if (rc != 0) {
        errno = -rc;
        ERRNO_ADD(sendto_peer);
        STAT_ADD(drop_input, n);
        return;
    }

    STAT_ADD(sendto_peer, out_len);

    log_line("sent piece index=%d begin(seq)=%" PRIu32 " bytes=%zd", PIECE_INDEX_DATA, seq, n);
}

/* ===================== stats print ===================== */

static void stat_print(void)
{
    FILE *fp = stat_file ? stat_file : stderr;

    if (stat_file) {
        if (ftruncate(fileno(stat_file), 0) != 0) {
            return;
        }
        fseek(stat_file, 0, SEEK_SET);
    }

    fprintf(fp, "errnos:\n");
    PRINT_ERRNO_STAT(fp, sendto_input);
    PRINT_ERRNO_STAT(fp, sendto_peer);
    PRINT_ERRNO_STAT(fp, recvfrom_input);
    PRINT_ERRNO_STAT(fp, recvfrom_peer);
    fprintf(fp, "\n");

    fprintf(fp, "data:\n");
    PRINT_DATA_STAT(fp, recvfrom_input);
    PRINT_DATA_STAT(fp, recvfrom_peer);
    PRINT_DATA_STAT(fp, sendto_input);
    PRINT_DATA_STAT(fp, sendto_peer);
    PRINT_DATA_STAT(fp, drop_input);
    PRINT_DATA_STAT(fp, drop_peer);
    fprintf(fp, "\n");

    fflush(fp);
}

/* ===================== print ===================== */

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage:\n  %s <config.conf>\n", prog);
}

static void print_runtime_config(const app_t *app)
{
    char a1[128];
    char a2[128];
    char a3[128];

    netaddr_to_string(&app->input_listen_addr, a1, sizeof(a1));
    netaddr_to_string(&app->input_target_addr, a2, sizeof(a2));
    netaddr_to_string(&app->peer_listen_addr, a3, sizeof(a3));

    fprintf(stderr, "role: %s\n", app->role == CLIENT_MODE ? "client" : "server");
    fprintf(stderr, "input listen: %s\n", a1);
    fprintf(stderr, "input target: %s\n", a2);
    fprintf(stderr, "peer  listen: %s\n", a3);

    if (app->have_peer_remote) {
        char a4[128];
        netaddr_to_string(&app->peer_remote_addr, a4, sizeof(a4));
        fprintf(stderr, "peer endpoint: %s\n", a4);
    } else {
        fprintf(stderr, "peer endpoint: (learn from first peer packet)\n");
    }
}

/* ===================== main ===================== */

int32_t main(int32_t argc, char **argv)
{
    fprintf(stderr, "--------------------------------------------\n");
    fprintf(stderr, "TorrentTun " TORRENTTUN_VERSION "\n");
    fprintf(stderr, "--------------------------------------------\n");

    if (signal(SIGINT, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGINT handler\n");
    }

    if (signal(SIGTERM, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGTERM handler\n");
    }

    if (signal(SIGHUP, main_catch_function) == SIG_ERR) {
        errmsg("Can't set SIGHUP handler\n");
    }

    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    cfg_init(&cfg_global);

    if (torrenttun_config_load_file(&cfg_global, argv[1]) != 0) {
        errmsg("Config parse failed\n");
    }

    torrenttun_config_log(&cfg_global);

    if (!cfg_global.have_input_listen) {
        errmsg("InputListen is required\n");
    }

    if (!cfg_global.have_input_target) {
        errmsg("InputTarget is required\n");
    }

    if (!cfg_global.have_peer_listen) {
        errmsg("PeerListen is required\n");
    }

    if (!cfg_global.have_psk) {
        errmsg("PreSharedKey is required\n");
    }

    if (!cfg_global.have_info_hash) {
        errmsg("InfoHash is required\n");
    }

    int32_t work_mode = cfg_global.have_peer_endpoint ? CLIENT_MODE : SERVER_MODE;

    fprintf(stderr, "%s mode\n", work_mode == CLIENT_MODE ? "Client" : "Server");

    if (cfg_global.have_log_path) {
        log_file = fopen(cfg_global.log_path, "w");
        if (!log_file) {
            errmsg("Can't open LogPath\n");
        }
    }

    if (cfg_global.have_stat_path) {
        stat_file = fopen(cfg_global.stat_path, "w");
        if (!stat_file) {
            errmsg("Can't open StatPath\n");
        }
    }

    app_t app;
    memset(&app, 0, sizeof(app));

    app.role = work_mode;
    app.input_sock = -1;
    app.peer_sock = -1;
    app.max_payload_size = cfg_global.max_payload_size;

    netaddr_copy(&app.input_listen_addr, &cfg_global.input_listen_addr);
    netaddr_copy(&app.input_target_addr, &cfg_global.input_target_addr);
    netaddr_copy(&app.peer_listen_addr, &cfg_global.peer_listen_addr);

    if (cfg_global.have_peer_endpoint) {
        netaddr_copy(&app.peer_remote_addr, &cfg_global.peer_endpoint_addr);
        app.have_peer_remote = 1;
    }

    memcpy(app.key, cfg_global.pre_shared_key, KEY_SIZE);
    memcpy(app.info_hash, cfg_global.info_hash, INFO_HASH_SIZE);

    init_peer_id(app.peer_id, app.role, &cfg_global);

    if (crypto_init(&app) != 0) {
        errmsg("crypto_init failed\n");
    }

    app.input_sock = make_udp_socket_bind(&app.input_listen_addr);
    if (app.input_sock < 0) {
        errmsg("Can't create/bind input socket: %s\n", strerror(-app.input_sock));
    }

    app.peer_sock = make_udp_socket_bind(&app.peer_listen_addr);
    if (app.peer_sock < 0) {
        errmsg("Can't create/bind peer socket: %s\n", strerror(-app.peer_sock));
    }

    print_runtime_config(&app);

    if (app.role == CLIENT_MODE) {
        maybe_send_handshake(&app);
    }

    time_t last_stat_ts = time(NULL);

    while (!exit_flag) {
        struct pollfd socks[2];
        memset(socks, 0, sizeof(socks));

        socks[0].fd = app.input_sock;
        socks[0].events = POLLIN;

        socks[1].fd = app.peer_sock;
        socks[1].events = POLLIN;

        int32_t rc = poll(socks, 2, 200);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }

            errmsg("poll failed: %s\n", strerror(errno));
        }

        if (rc > 0) {
            if (socks[1].revents & POLLIN) {
                handle_peer_packet(&app);
            }

            if (socks[0].revents & POLLIN) {
                handle_input_packet(&app);
            }
        }

        time_t now_ts = time(NULL);
        if (now_ts != (time_t)-1 && last_stat_ts != (time_t)-1 && now_ts - last_stat_ts >= 10) {
            stat_print();

            if (log_file) {
                fflush(log_file);
            }
            if (stat_file) {
                fflush(stat_file);
            }

            last_stat_ts = now_ts;
        }
    }

    stat_print();

    if (app.enc_ctx) {
        EVP_CIPHER_CTX_free(app.enc_ctx);
    }

    if (app.dec_ctx) {
        EVP_CIPHER_CTX_free(app.dec_ctx);
    }

    OPENSSL_cleanse(app.key, sizeof(app.key));
    OPENSSL_cleanse(app.nonce_prefix, sizeof(app.nonce_prefix));

    if (app.input_sock >= 0) {
        close(app.input_sock);
    }

    if (app.peer_sock >= 0) {
        close(app.peer_sock);
    }

    if (log_file) {
        fclose(log_file);
    }

    if (stat_file) {
        fclose(stat_file);
    }

    cfg_free(&cfg_global);

    fprintf(stderr, "TorrentTun finished\n");
    return 0;
}
