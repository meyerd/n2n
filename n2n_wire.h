/* (c) 2009 Richard Andrews <andrews@ntop.org> 
 *
 * Contributions by:
 *    Luca Deri
 *    Lukasz Taczuk
 */

#if !defined( N2N_WIRE_H_ )
#define N2N_WIRE_H_

#include <stdlib.h>

#if defined(WIN32)
#include "win32/n2n_win32.h"

#if defined(__MINGW32__)
#include <stdint.h>
#endif /* #ifdef __MINGW32__ */

#else /* #if defined(WIN32) */
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h> /* AF_INET and AF_INET6 */
#endif /* #if defined(WIN32) */

#define N2N_PROTOCOL_VERSION_MAJOR      3
#define N2N_PROTOCOL_VERSION_MINOR      0
#define N2N_MAJOR_VERSION               3
#define N2N_MINOR_VERSION               0
#define N2N_COMMUNITY_SIZE              8
/* Warning: Builds with a different N2N_COMMUNITY_SIZE are incompatible! */
#define N2N_MAC_SIZE                    6
#define N2N_COOKIE_SIZE                 4
#define N2N_PKT_BUF_SIZE                2048
#define N2N_SOCKBUF_SIZE                64      /* string representation of INET or INET6 sockets */

typedef uint8_t  n2n_community_t[N2N_COMMUNITY_SIZE];
typedef uint8_t  n2n_mac_t[N2N_MAC_SIZE];
typedef uint8_t  n2n_cookie_t[N2N_COOKIE_SIZE];
typedef uint32_t n2n_spi_t;

typedef char n2n_sock_str_t[N2N_SOCKBUF_SIZE]; /* tracing string buffer */

enum n2n_pc {
    n2n_ping = 0, /* Not used */
    n2n_pre_handshake,
    n2n_handshake,
    n2n_holepunch,
    n2n_supernode_register,
    n2n_address_resolution,
    n2n_keep_alive,
    n2n_edge_connect,
    n2n_edge_resume
};

typedef enum n2n_pc n2n_pc_t;

enum n2n_flags {
    n2n_ack = 0x1
};

typedef enum n2n_flags n2n_flags_t;

#define IPV4_SIZE                       4
#define IPV6_SIZE                       16

#define ETH_FRAMEHDRSIZE                   14
#define IP4_SRCOFFSET                   12

#define N2N_AUTH_TOKEN_SIZE             32      /* bytes */

#define N2N_EUNKNOWN                    -1
#define N2N_ENOTIMPL                    -2
#define N2N_EINVAL                      -3
#define N2N_ENOSPACE                    -4

typedef uint16_t n2n_transform_t; /* Encryption, compression type. */
typedef uint32_t n2n_sa_t; /* security association number */
typedef uint8_t n2n_version_major_t;
typedef uint8_t n2n_version_minor_t;

struct n2n_sock {
    uint8_t family; /* AF_INET or AF_INET6; or 0 if invalid */
    uint16_t port; /* host order */
    union {
        uint8_t v6[IPV6_SIZE]; /* byte sequence */
        uint8_t v4[IPV4_SIZE]; /* byte sequence */
    } addr;
};

typedef struct n2n_sock n2n_sock_t;

/* currently only IPv4 address supported */
struct n2n_ip {
    uint8_t addr[IPV4_SIZE];
};

typedef struct n2n_ip n2n_ip_t;

struct n2n_auth {
    uint16_t scheme; /* What kind of auth */
    uint16_t toksize; /* Size of auth token */
    uint8_t token[N2N_AUTH_TOKEN_SIZE]; /* Auth data interpreted based on scheme */
};

typedef struct n2n_auth n2n_auth_t;

struct n2n_preauth {
    n2n_community_t community;
    n2n_spi_t spi_dest;
    n2n_spi_t spi_src;
};

union n2n_supernode_register {
    struct {
        n2n_mac_t a_mac;
        n2n_ip_t a_n2n_ip;
    } syn;
    struct {
        n2n_sock_t a_pub_sock;
    } ack;
};

typedef union n2n_supernode_register n2n_supernode_register_t;

struct n2n_REGISTER_ACK {
    n2n_cookie_t cookie; /* Return cookie from REGISTER */
    n2n_mac_t srcMac; /* MAC of acknowledging party (supernode or edge) */
    n2n_mac_t dstMac; /* Reflected MAC of registering edge from REGISTER */
    n2n_sock_t sock; /* Supernode's view of edge socket (IP Addr, port) */
};

typedef struct n2n_REGISTER_ACK n2n_REGISTER_ACK_t;

struct n2n_PACKET {
    n2n_transform_t transform;
};

typedef struct n2n_PACKET n2n_PACKET_t;

struct n2n_ETHFRAMEHDR {
    n2n_mac_t srcMac;
    n2n_mac_t dstMac;
/* uint16_t            ethertype; *//* is there a reason to use this? */
};

typedef struct n2n_ETHFRAMEHDR n2n_ETHFRAMEHDR_t;

/* Linked with n2n_register_super in n2n_pc_t. Only from edge to supernode. */
struct n2n_REGISTER_SUPER {
    uint16_t aflags; /* additional flags */
    n2n_cookie_t cookie; /* Link REGISTER_SUPER and REGISTER_SUPER_ACK */
    uint16_t timeout;
    n2n_mac_t edgeMac; /* MAC to register with edge sending socket */
    n2n_auth_t auth; /* Authentication scheme and tokens */
    n2n_sock_t local_sock;
};

typedef struct n2n_REGISTER_SUPER n2n_REGISTER_SUPER_t;

/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
struct n2n_REGISTER_SUPER_ACK {
    n2n_cookie_t cookie; /* Return cookie from REGISTER_SUPER */
    n2n_mac_t edgeMac; /* MAC registered to edge sending socket */
    uint16_t lifetime; /* How long the registration will live */
    n2n_sock_t sock; /* Sending sockets associated with edgeMac */

    /* The packet format provides additional supernode definitions here. 
     * uint8_t count, then for each count there is one
     * n2n_sock_t.
     */
    uint8_t num_sn; /* Number of supernodes that were send
     * even if we cannot store them all. If
     * non-zero then sn_bak is valid. */
    n2n_sock_t sn_bak; /* Socket of the first backup supernode */

};

typedef struct n2n_REGISTER_SUPER_ACK n2n_REGISTER_SUPER_ACK_t;

/* Linked with n2n_register_super_ack in n2n_pc_t. Only from supernode to edge. */
struct n2n_REGISTER_SUPER_NAK {
    n2n_cookie_t cookie; /* Return cookie from REGISTER_SUPER */
};

typedef struct n2n_REGISTER_SUPER_NAK n2n_REGISTER_SUPER_NAK_t;

struct n2n_PEER_INFO {
    uint16_t aflags;
    uint16_t timeout;
    n2n_mac_t mac;
    n2n_sock_t sockets[2];
};

typedef struct n2n_PEER_INFO n2n_PEER_INFO_t;

struct n2n_QUERY_PEER {
    n2n_mac_t srcMac;
    n2n_mac_t targetMac;
};

typedef struct n2n_QUERY_PEER n2n_QUERY_PEER_t;

struct n2n_HEADER {
    n2n_pc_t pc;
    n2n_flags_t flags;
};

typedef struct n2n_HEADER n2n_HEADER_t;

struct n2n_buf {
    uint8_t * data;
    size_t size;
};

typedef struct n2n_buf n2n_buf_t;

int encode_uint8(uint8_t * base, size_t * idx, const uint8_t v);

int decode_uint8(const uint8_t * base, size_t * idx, size_t * rem,
        uint8_t * out);

int encode_uint16(uint8_t * base, size_t * idx, const uint16_t v);

int decode_uint16(const uint8_t * base, size_t * idx, size_t * rem,
        uint16_t * out);

int encode_uint32(uint8_t * base, size_t * idx, const uint32_t v);

int decode_uint32(const uint8_t * base, size_t * idx, size_t * rem,
        uint32_t * out);

int encode_buf(uint8_t * base, size_t * idx, const void * p, size_t s);

int decode_buf(const uint8_t * base, size_t * idx, size_t * rem,
        uint8_t * out, size_t bufsize);

int encode_ip(uint8_t * base, size_t * idx, const n2n_ip_t ip);

int decode_ip(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_ip_t ip);

int encode_mac(uint8_t * base, size_t * idx, const n2n_mac_t m);

int decode_mac(const uint8_t * base, size_t * idx, size_t * rem,
        uint8_t * out /* of size N2N_MAC_SIZE.
                         This clearer than passing a n2n_mac_t */ );

int encode_sock(uint8_t * base, size_t * idx, const n2n_sock_t * sock);

int decode_sock(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_sock_t * sock);

int encode_supernode_register(uint8_t * base, size_t * idx,
        int ack, const n2n_supernode_register_t * reg);

int decode_supernode_register(const uint8_t * base, size_t * idx, size_t * rem,
        int ack, n2n_supernode_register_t * reg);

int fill_sockaddr(struct sockaddr * addr, size_t addrlen,
        const n2n_sock_t * sock);

int encode_HEADER(uint8_t * base, size_t * idx, const n2n_HEADER_t *hdr);
int decode_HEADER(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_HEADER_t *hdr);

void decode_ETHFRAMEHDR(const uint8_t * base, n2n_ETHFRAMEHDR_t * eth);

int copy_ETHFRAMEHDR(uint8_t * base, uint8_t * pkt);

#endif /* #if !defined( N2N_WIRE_H_ ) */

