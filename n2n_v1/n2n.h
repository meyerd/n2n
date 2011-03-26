/*
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *               Richard Andrews <andrews@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 * Babak Farrokhi <babak@farrokhi.net> [FreeBSD port]
 *
*/

#ifndef _N2N_H_
#define _N2N_H_

/*
   tunctl -t tun0
   tunctl -t tun1
   ifconfig tun0 1.2.3.4 up
   ifconfig tun1 1.2.3.5 up
   ./edge -d tun0 -l 2000 -r 127.0.0.1:3000 -c hello
   ./edge -d tun1 -l 3000 -r 127.0.0.1:2000 -c hello


   tunctl -u UID -t tunX
*/

#if defined(__APPLE__) && defined(__MACH__)
#define _DARWIN_
#endif

#ifdef WIN32
#include "win32/n2n_win32.h"
#endif

#include <time.h>
#include <ctype.h>
#include <stdlib.h>

#ifndef WIN32
#include <netdb.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <pthread.h>

#ifdef __linux__
#include <linux/if.h>
#include <linux/if_tun.h>
#endif

#ifdef __FreeBSD__
#include <netinet/in_systm.h>
#endif

#include <syslog.h>
#include <sys/wait.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>

#define closesocket(a) close(a)
#endif

#include <string.h>
#ifdef WIN32
#include "win32/getopt.h"
#else
#define _GNU_SOURCE
#include <getopt.h>
#endif

#include <stdarg.h>

#ifdef WIN32
#include "win32/wintap.h"
#endif

#include "twofish.h"

#ifndef WIN32
typedef struct tuntap_dev {
  int           fd;
  u_int8_t      mac_addr[6];
  u_int32_t     ip_addr, device_mask;
  u_int         mtu;
} tuntap_dev;

#define SOCKET int
#endif /* #ifndef WIN32 */

#define QUICKLZ               1
#define N2N_PKT_VERSION       1

#define MSG_TYPE_REGISTER     1 /* FIX invece di usare il sender del pacchetto scriverlo nel pacchetto stesso */
#define MSG_TYPE_DEREGISTER   2
#define MSG_TYPE_PACKET       3
#define MSG_TYPE_REGISTER_ACK 4
#define MSG_TYPE_ACK_RESPONSE 5

#define COMMUNITY_LEN           16
#define MIN_COMPRESSED_PKT_LEN  32

/* Set N2N_COMPRESSION_ENABLED to 0 to disable lzo1x compression of ethernet
 * frames. Doing this will break compatibility with the standard n2n packet
 * format so do it only for experimentation. All edges must be built with the
 * same value if they are to understand each other. */
#define N2N_COMPRESSION_ENABLED 1

#define DEFAULT_MTU   1400

/* Maximum enum value is 255 due to marshalling into 1 byte */
enum packet_type {
  packet_unreliable_data = 0,  /* no ACK needed */
  packet_reliable_data,    /* needs ACK     */
  packet_ping,
  packet_pong
};

/* All information is always in network byte-order */
struct peer_addr {
  u_int8_t family;
  u_int16_t port;
  union {
    u_int8_t  v6_addr[16];
    u_int32_t v4_addr;
  } addr_type;
};

struct n2n_packet_header {
  u_int8_t version, msg_type, ttl, sent_by_supernode;
  char community_name[COMMUNITY_LEN], src_mac[6], dst_mac[6];
  struct peer_addr public_ip, private_ip;
  enum packet_type pkt_type;
  u_int32_t sequence_id;
  u_int32_t crc; // FIX - It needs to be handled for detcting forged packets
};

int marshall_n2n_packet_header( u_int8_t * buf, const struct n2n_packet_header * hdr );
int unmarshall_n2n_packet_header( struct n2n_packet_header * hdr, const u_int8_t * buf );

#define N2N_PKT_HDR_SIZE (sizeof(struct n2n_packet_header))


/** Common type used to hold stringified IP addresses. */
typedef char ipstr_t[32];

/** Common type used to hold stringified MAC addresses. */
typedef char macstr_t[32];

struct n2n_sock_info
{
    int                 sock;
    char                is_udp_socket /*= 1*/;    
};

typedef struct n2n_sock_info    n2n_sock_info_t;

struct peer_info {
  char community_name[COMMUNITY_LEN], mac_addr[6];
  struct peer_addr public_ip, private_ip;
  time_t last_seen;
  struct peer_info *next;
  /* socket */
  n2n_sock_info_t sinfo;
};

struct n2n_edge; /* defined in edge.c */
typedef struct n2n_edge         n2n_edge_t;


/* ************************************** */

#if defined(DEBUG)
#define SOCKET_TIMEOUT_INTERVAL_SECS    5
#define REGISTER_FREQUENCY              20 /* sec */
#else  /* #if defined(DEBUG) */
#define SOCKET_TIMEOUT_INTERVAL_SECS    10
#define REGISTER_FREQUENCY              60 /* sec */
#endif /* #if defined(DEBUG) */

#define TRACE_ERROR     0, __FILE__, __LINE__
#define TRACE_WARNING   1, __FILE__, __LINE__
#define TRACE_NORMAL    2, __FILE__, __LINE__
#define TRACE_INFO      3, __FILE__, __LINE__

/* ************************************** */

#define SUPERNODE_IP    "127.0.0.1"
#define SUPERNODE_PORT  1234

/* ************************************** */

#ifndef max
#define max(a, b) ((a < b) ? b : a)
#endif

#ifndef min
#define min(a, b) ((a > b) ? b : a)
#endif

/* ************************************** */

/* Variables */
// extern TWOFISH *tf;
extern int traceLevel;
extern char broadcast_addr[6];
extern char multicast_addr[6];

/* Functions */
extern void sockaddr_in2peer_addr(struct sockaddr_in *in, struct peer_addr *out);
extern void peer_addr2sockaddr_in(const struct peer_addr *in, struct sockaddr_in *out);
// extern int  init_n2n(u_int8_t *encrypt_pwd, u_int32_t encrypt_pwd_len );
// extern void term_n2n();
extern void send_ack(n2n_sock_info_t * sinfo,
		     u_int16_t last_rcvd_seq_id,
		     struct n2n_packet_header *header,
		     struct peer_addr *remote_peer,
		     char *src_mac);

extern void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...);
extern int  tuntap_open(tuntap_dev *device, char *dev, char *device_ip, 
			char *device_mask, const char * device_mac, int mtu);
extern int  tuntap_read(struct tuntap_dev *tuntap, unsigned char *buf, int len);
extern int  tuntap_write(struct tuntap_dev *tuntap, unsigned char *buf, int len);
extern void tuntap_close(struct tuntap_dev *tuntap);

extern SOCKET open_socket(u_int16_t local_port, int udp_sock, int server_mode);
extern int connect_socket(int sock_fd, struct peer_addr* dest);

extern void send_packet(n2n_sock_info_t * sinfo,
			char *packet, size_t *packet_len,
			const struct peer_addr *remote_peer,
			u_int8_t compress_data);
extern char* intoa(u_int32_t addr, char* buf, u_short buf_len);
extern char* macaddr_str(const char *mac, char *buf, int buf_len);
extern int   str2mac( u_int8_t * outmac /* 6 bytes */, const char * s );
extern void fill_standard_header_fields(n2n_sock_info_t * eee,
					struct n2n_packet_header *hdr,
					char *src_mac);

extern u_int receive_data(n2n_sock_info_t * sinfo,
			  char *packet, size_t packet_len, 
			  struct peer_addr *from, u_int8_t *discarded_pkt,
			  char *tun_mac_addr, u_int8_t decompress_data,
			  struct n2n_packet_header *hdr);
extern u_int reliable_sendto(n2n_sock_info_t * sinfo,
			     char *packet, size_t *packet_len, 
			     const struct peer_addr *from, u_int8_t compress_data);
extern u_int unreliable_sendto(n2n_sock_info_t * sinfo,
			       char *packet, size_t *packet_len, 
			       const struct peer_addr *from, u_int8_t compress_data);
extern u_int send_data(n2n_sock_info_t * sinfo,
		       char *packet, size_t *packet_len, 
		       const struct peer_addr *to, u_int8_t compress_data);
extern u_int8_t is_multi_broadcast(char *dest_mac);
extern char* msg_type2str(u_short msg_type);
extern void hexdump(char *buf, u_int len);

void print_n2n_version();


/* Operations on peer_info lists. */
struct peer_info * find_peer_by_mac( struct peer_info * list,
                                     const char * mac );
void   peer_list_add( struct peer_info * * list,
                      struct peer_info * new );
size_t peer_list_size( const struct peer_info * list );
size_t purge_peer_list( struct peer_info ** peer_list, 
                        time_t purge_before );
size_t purge_expired_registrations( struct peer_info ** peer_list );

/* version.c */
extern char *version, *osName, *buildDate;

#endif /* _N2N_H_ */
