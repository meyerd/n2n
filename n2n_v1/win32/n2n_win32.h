/*

	(C) 2007 - Luca Deri <deri@ntop.org>

*/

#ifndef _N2N_WIN32_H_
#define _N2N_WIN32_H_

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "wintap.h"

typedef unsigned int u_int32_t;
typedef unsigned short u_int16_t;
typedef unsigned char u_int8_t;
typedef int int32_t;
typedef short int16_t;
typedef char int8_t;

#define snprintf _snprintf
#define strdup _strdup

#define socklen_t int

#define ETHER_ADDR_LEN 6
/*                                                                                                                                                                                     
 * Structure of a 10Mb/s Ethernet header.                                                                                                                                              
 */
struct  ether_header {
        u_char  ether_dhost[ETHER_ADDR_LEN];
        u_char  ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
};

/* ************************************* */

struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN
        u_char  ip_hl:4,                /* header length */
                ip_v:4;                 /* version */
#else
        u_char  ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
#endif
        u_char  ip_tos;                 /* type of service */
        short   ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        short   ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


/* ************************************* */

typedef struct tuntap_dev {
	HANDLE device_handle;
	char *device_name;
	char *ifName;
	OVERLAPPED overlap_read, overlap_write;
	u_int8_t      mac_addr[6];
	u_int32_t     ip_addr, device_mask;
	u_int         mtu;
} tuntap_dev;

#endif