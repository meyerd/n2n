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
 * Richard Andrews <bbmaj7@yahoo.com.au>
 * Massimo Torquati <torquati@ntop.org>
 *
 */

#include "n2n.h"

#include "minilzo.h"

#include <assert.h>

#if defined(DEBUG)
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT          120
#else /* #if defined(DEBUG) */
#   define PURGE_REGISTRATION_FREQUENCY   60
#   define REGISTRATION_TIMEOUT           (60*5)
#endif /* #if defined(DEBUG) */


char broadcast_addr[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
char multicast_addr[6] = { 0x01, 0x00, 0x05, 0x00, 0x00, 0x00 }; /* First 3 bytes are meaningful */

/* ************************************** */

static void print_header( const char * msg, const struct n2n_packet_header * hdr )
{
  ipstr_t buf;
  ipstr_t buf2;

  traceEvent(TRACE_INFO, "%s hdr: public_ip=(%d)%s:%d, private_ip=(%d)%s:%d", msg,
	     hdr->public_ip.family,
	     intoa(ntohl(hdr->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
	     ntohs(hdr->public_ip.port),
	     hdr->private_ip.family,
	     intoa(ntohl(hdr->private_ip.addr_type.v4_addr), buf2, sizeof(buf2)),
	     ntohs(hdr->private_ip.port)
	     );
}

/* *********************************************** */

extern void sockaddr_in2peer_addr(struct sockaddr_in *in, struct peer_addr *out) {
  out->family            = (u_int8_t)in->sin_family;
  out->port              = in->sin_port;
  out->addr_type.v4_addr = in->sin_addr.s_addr;
}

/* *********************************************** */

extern void peer_addr2sockaddr_in(const struct peer_addr *in, struct sockaddr_in *out) {
  out->sin_family      = in->family;
  out->sin_port        = in->port;
  out->sin_addr.s_addr = in->addr_type.v4_addr;
}

/* ************************************** */

static
int marshall_peer_addr( u_int8_t * buf, size_t * offset, const struct peer_addr * s )
{
 /* RA: I'm pretty sure that this is broken. There is no guarantee that the
  * peer_addr structure is packed. This will always work between like hosts but
  * is almost certainly broken between different host types. */
  memcpy( buf + *offset, s, sizeof(struct peer_addr));
  *offset += sizeof(struct peer_addr);

  return sizeof(struct peer_addr); /* bytes written */
}

/* ************************************** */

static
int marshall_uint32( u_int8_t * buf, size_t * offset, u_int32_t val )
{
    buf[*offset + 0] = ((val >> 24) & 0xff);
    buf[*offset + 1] = ((val >> 16) & 0xff);
    buf[*offset + 2] = ((val >>  8) & 0xff);
    buf[*offset + 3] = ((val      ) & 0xff);

    *offset += 4;
    return 4;
}

/* ************************************** */

int marshall_n2n_packet_header( u_int8_t * buf, const struct n2n_packet_header * hdr )
{
  size_t offset = 0;

  print_header( "Marshalling ", hdr );

  *(buf+offset) = hdr->version;
  ++offset;

  *(buf+offset) = hdr->msg_type;
  ++offset;

  *(buf+offset) = hdr->ttl;
  ++offset;

  *(buf+offset) = hdr->sent_by_supernode;
  ++offset;

  memcpy( buf+offset, hdr->community_name, COMMUNITY_LEN );
  offset += COMMUNITY_LEN;

  memcpy( buf+offset, hdr->src_mac, 6 );
  offset += 6;

  memcpy( buf+offset, hdr->dst_mac, 6 );
  offset += 6;

  marshall_peer_addr( buf, &offset, &(hdr->public_ip) );
  marshall_peer_addr( buf, &offset, &(hdr->private_ip) );

  *(buf+offset) = (hdr->pkt_type & 0xff);
  ++offset;

  marshall_uint32( buf, &offset, hdr->sequence_id );
  marshall_uint32( buf, &offset, hdr->crc );

  return offset;
}

/* ************************************** */

static
int unmarshall_peer_addr( struct peer_addr * s, size_t * offset,
			  const u_int8_t * buf )
{
  memcpy(s, buf + *offset, sizeof(struct peer_addr));
  *offset += sizeof(struct peer_addr);
  return (sizeof(struct peer_addr)); /* bytes written */
}

/* ************************************** */

static
int unmarshall_uint32( u_int32_t * val, size_t * offset, const u_int8_t * buf )
{
  *val  = ( (buf[*offset + 0] & 0xff) << 24 );
  *val |= ( (buf[*offset + 1] & 0xff) << 16 );
  *val |= ( (buf[*offset + 2] & 0xff) <<  8 );
  *val |= ( (buf[*offset + 3] & 0xff)       );

  *offset += 4;
  return 4;
}

/* ************************************** */

int unmarshall_n2n_packet_header( struct n2n_packet_header * hdr, const u_int8_t * buf )
{
  size_t offset=0;

  hdr->version = *(buf + offset);
  ++offset;

  hdr->msg_type = *(buf + offset);
  ++offset;

  hdr->ttl = *(buf + offset);
  ++offset;

  hdr->sent_by_supernode = *(buf + offset);
  ++offset;

  memcpy( hdr->community_name, (buf + offset), COMMUNITY_LEN );
  offset += COMMUNITY_LEN;

  memcpy( hdr->src_mac, (buf + offset), 6 );
  offset += 6;

  memcpy( hdr->dst_mac, (buf + offset), 6 );
  offset += 6;

  unmarshall_peer_addr( &(hdr->public_ip),  &offset, buf );
  unmarshall_peer_addr( &(hdr->private_ip), &offset, buf );

  hdr->pkt_type = (*(buf + offset) & 0xff); /* Make sure only 8 bits are copied. */
  ++offset;

  unmarshall_uint32( &(hdr->sequence_id), &offset, buf );
  unmarshall_uint32( &(hdr->crc),         &offset, buf );

  print_header( "Unmarshalled ", hdr );

  return offset;
}

/* ************************************** */

SOCKET open_socket(u_int16_t local_port, int udp_sock, int server_mode) {
  SOCKET sock_fd;
  struct sockaddr_in local_address;
  int sockopt = 1;

  if((sock_fd = socket(PF_INET, udp_sock ? SOCK_DGRAM : SOCK_STREAM, 0))  < 0) {
    traceEvent(TRACE_ERROR, "Unable to create socket [%s][%d]\n",
	       strerror(errno), sock_fd);
    return(-1);
  }

#ifndef WIN32
  /* fcntl(sock_fd, F_SETFL, O_NONBLOCK); */
#endif

  setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&sockopt, sizeof(sockopt));

  memset(&local_address, 0, sizeof(local_address));
  local_address.sin_family = AF_INET;
  local_address.sin_port = htons(local_port);
  local_address.sin_addr.s_addr = INADDR_ANY;
  if(bind(sock_fd, (struct sockaddr*) &local_address, sizeof(local_address)) == -1) {
    traceEvent(TRACE_ERROR, "Bind error [%s]\n", strerror(errno));
    return(-1);
  }

  if((!udp_sock) && server_mode) {
    if(listen(sock_fd, 255) == -1) {
      traceEvent(TRACE_ERROR, "Listen error [%s]\n", strerror(errno));
      return(-1);
    }
  }

  return(sock_fd);
}

/* ************************************** */

int connect_socket(int sock_fd, struct peer_addr* _dest) {
  char *http_header;
  int len, rc;
  struct sockaddr_in dest;

  peer_addr2sockaddr_in(_dest, &dest);

  /* FIX: add IPv6 support */
  rc = connect(sock_fd, (struct sockaddr*)&dest, sizeof(struct sockaddr_in));

  if(rc == -1) {
    traceEvent(TRACE_WARNING, "connect() error [%s]\n", strerror(errno));
    return(-1);
  }

  /* Send dummy http header */
  http_header = "GET / HTTP/1.0\r\n\r\n";
  len = strlen(http_header);
  rc = send(sock_fd, http_header, len, 0);

  return((rc == len) ? 0 : -1);
}


/* *********************************************** */

void send_packet(n2n_sock_info_t * sinfo, 
		 char *packet, size_t *packet_len,
		 const struct peer_addr *remote_peer, u_int8_t compress_data) {
  int data_sent_len;

  data_sent_len = unreliable_sendto(sinfo,
				    packet, packet_len, remote_peer, compress_data);

  if(data_sent_len != *packet_len)
    traceEvent(TRACE_WARNING,
	       "sendto() [sent=%d][attempted_to_send=%d] [%s]\n",
	       data_sent_len, *packet_len, strerror(errno));
}

/* *********************************************** */

int traceLevel = 2 /* NORMAL */;
int useSyslog = 0, syslog_opened = 0;

#define N2N_TRACE_DATESIZE 32
void traceEvent(int eventTraceLevel, char* file, int line, char * format, ...) {
  va_list va_ap;

  if(eventTraceLevel <= traceLevel) {
    char buf[2048];
    char out_buf[640];
    char theDate[N2N_TRACE_DATESIZE];
    char *extra_msg = "";
    time_t theTime = time(NULL);
#ifdef WIN32
	int i;
#endif

    /* We have two paths - one if we're logging, one if we aren't
     *   Note that the no-log case is those systems which don't support it (WIN32),
     *                                those without the headers !defined(USE_SYSLOG)
     *                                those where it's parametrically off...
     */

    memset(buf, 0, sizeof(buf));
    strftime(theDate, N2N_TRACE_DATESIZE, "%d/%b/%Y %H:%M:%S", localtime(&theTime));

    va_start (va_ap, format);
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);
    va_end(va_ap);

    if(eventTraceLevel == 0 /* TRACE_ERROR */)
      extra_msg = "ERROR: ";
    else if(eventTraceLevel == 1 /* TRACE_WARNING */)
      extra_msg = "WARNING: ";

    while(buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';

#ifndef WIN32
    if(useSyslog) {
      if(!syslog_opened) {
        openlog("n2n", LOG_PID, LOG_DAEMON);
        syslog_opened = 1;
      }

      snprintf(out_buf, sizeof(out_buf), "%s%s", extra_msg, buf);
      syslog(LOG_INFO, out_buf);
    } else {
      snprintf(out_buf, sizeof(out_buf), "%s [%11s:%4d] %s%s", theDate, file, line, extra_msg, buf);
      printf("%s\n", out_buf);
      fflush(stdout);
    }
#else
    /* this is the WIN32 code */
	for(i=strlen(file)-1; i>0; i--) if(file[i] == '\\') { i++; break; };
    snprintf(out_buf, sizeof(out_buf), "%s [%11s:%4d] %s%s", theDate, &file[i], line, extra_msg, buf);
    printf("%s\n", out_buf);
    fflush(stdout);
#endif
  }

}

/* *********************************************** */

/* addr should be in network order. Things are so much simpler that way. */
char* intoa(u_int32_t /* host order */ addr, char* buf, u_short buf_len) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[buf_len];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
        *--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* *********************************************** */

char* macaddr_str(const char *mac, char *buf, int buf_len) {
  snprintf(buf, buf_len, "%02X:%02X:%02X:%02X:%02X:%02X",
	   mac[0] & 0xFF, mac[1] & 0xFF, mac[2] & 0xFF,
	   mac[3] & 0xFF, mac[4] & 0xFF, mac[5] & 0xFF);
  return(buf);
}

/* *********************************************** */

void fill_standard_header_fields(n2n_sock_info_t * sinfo,
				 struct n2n_packet_header *hdr, char *src_mac) {
  socklen_t len = sizeof(hdr->private_ip);
  memset(hdr, 0, N2N_PKT_HDR_SIZE);
  hdr->version = N2N_PKT_VERSION;
  hdr->crc = 0; // FIX
  if(src_mac != NULL) memcpy(hdr->src_mac, src_mac, 6);
  getsockname(sinfo->sock, (struct sockaddr*)&hdr->private_ip, &len);
  hdr->public_ip.family = AF_INET;
}

/* *********************************************** */

void send_ack(n2n_sock_info_t * sinfo,
	      u_int16_t last_rcvd_seq_id,
	      struct n2n_packet_header *header,
	      struct peer_addr *remote_peer,
	      char *src_mac) {

  /* marshalling double-checked. */
  struct n2n_packet_header hdr;
  u_int8_t pkt[ N2N_PKT_HDR_SIZE ];
  size_t len = sizeof(hdr);
  size_t len2;
  int compress_data = N2N_COMPRESSION_ENABLED;

  fill_standard_header_fields(sinfo, &hdr, src_mac);
  hdr.msg_type = MSG_TYPE_ACK_RESPONSE;
  hdr.sequence_id = last_rcvd_seq_id;
  memcpy(hdr.community_name, header->community_name, COMMUNITY_LEN);

  len2=marshall_n2n_packet_header( pkt, &hdr );
  assert( len2 == len );

  send_packet(sinfo, (char*)pkt, &len, remote_peer, compress_data);
}

/* *********************************************** */

u_int8_t is_multi_broadcast(char *dest_mac) {
  return(((!memcmp(broadcast_addr, dest_mac, 6))
	  || (!memcmp(multicast_addr, dest_mac, 3))) ? 1 : 0);
}

/* *********************************************** */

/* http://www.faqs.org/rfcs/rfc908.html */

u_int receive_data(n2n_sock_info_t * sinfo,
		   char *packet, size_t packet_len,
		   struct peer_addr *from, u_int8_t *discarded_pkt,
		   char *tun_mac_addr, u_int8_t decompress_data,
		   struct n2n_packet_header *hdr) {
  socklen_t fromlen = sizeof(struct sockaddr_in);
  int len;
  char *payload, *pkt_type;
  macstr_t src_mac_buf;
  macstr_t dst_mac_buf;
  ipstr_t ip_buf;
  ipstr_t from_ip_buf;

  if(sinfo->is_udp_socket) {
    struct sockaddr_in _from;
    len = recvfrom(sinfo->sock, packet, packet_len, 0, (struct sockaddr*)&_from, &fromlen);
    sockaddr_in2peer_addr(&_from, from);
  } else {
    len = recv(sinfo->sock, packet, 4, 0);
    if(len == 4) {
      packet[4] = '\0';
      len = atoi(packet);
      len = recv(sinfo->sock, packet, len, 0);
    } else {
      traceEvent(TRACE_WARNING, "Unable to receive n2n packet length");
      return(-1);
    }
  }

  unmarshall_n2n_packet_header(hdr, (u_int8_t *)packet);

  payload = &packet[N2N_PKT_HDR_SIZE];

  if(len < 0) {
#ifdef WIN32
    if(WSAGetLastError() != WSAECONNRESET /* http://support.microsoft.com/kb/263823 */ ) {
      traceEvent(TRACE_WARNING, "recvfrom returned %d [err=%d]", len, WSAGetLastError());
    }
#endif
    return(0);
  } else if(len > MIN_COMPRESSED_PKT_LEN) {
#define N2N_DECOMPRESS_BUFSIZE 2048
    char decompressed[N2N_DECOMPRESS_BUFSIZE];
    int rc;
    lzo_uint decompressed_len=N2N_DECOMPRESS_BUFSIZE;
    size_t insize = len-N2N_PKT_HDR_SIZE;

    if(decompress_data) {
      rc = lzo1x_decompress_safe((u_char*)&packet[N2N_PKT_HDR_SIZE],
                                 insize,
                                 (u_char*)decompressed, &decompressed_len, NULL);

      if(rc == LZO_E_OK)
      {
	traceEvent(TRACE_INFO, "%u bytes decompressed into %u", insize, decompressed_len);
      }
      else
      {
        traceEvent(TRACE_WARNING, "Failed to decompress %u byte packet. LZO error=%d", insize, rc );
        return -1;
      }

      if(packet_len > decompressed_len) {
	memcpy(&packet[N2N_PKT_HDR_SIZE], decompressed, decompressed_len);
	len = decompressed_len+N2N_PKT_HDR_SIZE;
      } else {
	traceEvent(TRACE_WARNING, "Uncompressed packet is too large [decompressed_len=%d]",
		   decompressed_len);
	return(0);
      }
    }

    (*discarded_pkt) = 0;

    if(!hdr->sent_by_supernode) {
      memcpy( &packet[offsetof(struct n2n_packet_header, public_ip)], from, sizeof(struct sockaddr_in) );
    }

    switch(hdr->pkt_type) {
    case packet_unreliable_data:
      pkt_type = "unreliable data";
      break;
    case packet_reliable_data:
      pkt_type = "reliable data";
      break;
    case packet_ping:
      pkt_type = "ping";
      break;
    case packet_pong:
      pkt_type = "pong";
      break;
    default:
      pkt_type = "???";
    }

    traceEvent(TRACE_INFO, "+++ Received %s packet [rcvd_from=%s:%d][msg_type=%s][seq_id=%d]",
	       pkt_type,
	       intoa(ntohl(from->addr_type.v4_addr), from_ip_buf, sizeof(from_ip_buf)),
	       ntohs(from->port), msg_type2str(hdr->msg_type),
	       hdr->sequence_id);
    traceEvent(TRACE_INFO, "    [src_mac=%s][dst_mac=%s][original_sender=%s:%d]",
	       macaddr_str(hdr->src_mac, src_mac_buf, sizeof(src_mac_buf)),
	       macaddr_str(hdr->dst_mac, dst_mac_buf, sizeof(dst_mac_buf)),
	       intoa(ntohl(hdr->public_ip.addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
	       ntohs(hdr->public_ip.port));

#ifdef HANDLE_RETRANSMISSION
    if((hdr->pkt_type == packet_reliable_data)
       && (hdr->msg_type == MSG_TYPE_PACKET)) {
      (*discarded_pkt) = handle_ack(sock_fd,  is_udp_socket, hdr,
				    &payload[6], payload, from, tun_mac_addr);
    } else
      (*discarded_pkt) = 0;
#endif
  } else
    traceEvent(TRACE_WARNING, "Receive error [%s] or pkt too short [len=%d]\n",
	       strerror(errno), len);

  return(len);
}

/* *********************************************** */

#if 0
static u_int32_t queue_packet(struct send_hash_entry *scan,
			      char *packet,
			      u_int16_t packet_len) {
  struct packet_list *pkt = (struct packet_list*)malloc(sizeof(struct packet_list));

  if(pkt == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory!");
    return(0);
  }

  if((pkt->packet = (char*)malloc(packet_len)) == NULL) {
    traceEvent(TRACE_ERROR, "Not enough memory!");
    return(0);
  }

  memcpy(pkt->packet, packet, packet_len);
  pkt->packet_len = packet_len;
  pkt->seq_id = scan->last_seq_id;
  pkt->next = scan->unacked_packet_list;
  scan->unacked_packet_list = pkt;
  scan->num_unacked_pkts++;
  return(pkt->seq_id);
}
#endif

/* *********************************************** */

/* Work-memory needed for compression. Allocate memory in units
 * of `lzo_align_t' (instead of `char') to make sure it is properly aligned.
 */

#define HEAP_ALLOC(var,size)						\
  lzo_align_t __LZO_MMODEL var [ ((size) + (sizeof(lzo_align_t) - 1)) / sizeof(lzo_align_t) ]

static HEAP_ALLOC(wrkmem,LZO1X_1_MEM_COMPRESS);

/* ******************************************************* */

u_int send_data(n2n_sock_info_t * sinfo,
		char *packet, size_t *packet_len,
		const struct peer_addr *to, u_int8_t compress_data) {
  char compressed[1650];
  int rc;
  lzo_uint compressed_len=0;
  struct sockaddr_in destsock;

  if(*packet_len < N2N_PKT_HDR_SIZE) {
    traceEvent(TRACE_WARNING, "The packet about to be sent is too short [len=%d]\n", *packet_len);
    return(-1);
  }

  memcpy(compressed, packet, N2N_PKT_HDR_SIZE);

  peer_addr2sockaddr_in(to, &destsock);

  if(compress_data) {
    rc = lzo1x_1_compress((u_char*)&packet[N2N_PKT_HDR_SIZE],
			  *packet_len - N2N_PKT_HDR_SIZE,
			  (u_char*)&compressed[N2N_PKT_HDR_SIZE],
			  &compressed_len, wrkmem);

    if ( 0 == compressed_len )
    {
      traceEvent(TRACE_WARNING, "failed to compress %u bytes.", (*packet_len - N2N_PKT_HDR_SIZE) );
      return -1;
    }

    compressed_len += N2N_PKT_HDR_SIZE;

    traceEvent(TRACE_INFO, "%u bytes compressed into %u", *packet_len, compressed_len);
    /* *packet_len = compressed_len; */

    if(sinfo->is_udp_socket) {
      rc = sendto(sinfo->sock, compressed, compressed_len, 0,
		  (struct sockaddr*)&destsock, sizeof(struct sockaddr_in));
    } else {
      char send_len[5];

      /* 4 bytes packet length */
      snprintf(send_len, sizeof(send_len), "%04d", (int)compressed_len);
      if((rc = send(sinfo->sock, send_len, 4, 0)) != 4)
	return(-1);
      if((rc = send(sinfo->sock, compressed, compressed_len, 0)) != compressed_len) {
	traceEvent(TRACE_WARNING, "send error [%d][%s]",
		   errno, strerror(errno));
      }
    }
  } else {
    compressed_len = *packet_len;
    if(sinfo->is_udp_socket)
      rc = sendto(sinfo->sock, packet, compressed_len, 0,
		  (struct sockaddr*)&destsock, sizeof(struct sockaddr_in));
    else {
      char send_len[5];

      /* 4 bytes packet length */
      snprintf(send_len, sizeof(send_len), "%04d", (int)compressed_len);
      if((rc = send(sinfo->sock, send_len, 4, 0)) != 4)
        return(-1);
      rc = send(sinfo->sock, compressed, compressed_len, 0);
    }

    if(rc == -1) {
      ipstr_t ip_buf;

      traceEvent(TRACE_WARNING, "sendto() failed while attempting to send data to %s:%d",
		 intoa(ntohl(to->addr_type.v4_addr), ip_buf, sizeof(ip_buf)),
		 ntohs(to->port));
    }
  }

  if ( rc >= 0) {
    traceEvent(TRACE_INFO, "### Tx N2N Msg -> network");
  }

  if(rc == compressed_len)
    return(*packet_len); /* fake just to avoid warnings */
  else
    return(rc);
}

/* *********************************************** */

u_int reliable_sendto(n2n_sock_info_t * sinfo,
		      char *packet, size_t *packet_len,
		      const struct peer_addr *to, u_int8_t compress_data) {
  /*   char *payload = &packet[N2N_PKT_HDR_SIZE]; */
  struct n2n_packet_header hdr_storage;
  struct n2n_packet_header *hdr = &hdr_storage;
  macstr_t src_mac_buf;
  macstr_t dst_mac_buf;

  /* REVISIT: efficiency of unmarshal + re-marshal just to change a couple of bits. */
  unmarshall_n2n_packet_header( hdr, (u_int8_t *)packet );

  /* hdr->sequence_id = (hdr->msg_type == MSG_TYPE_PACKET) ? mac2sequence((u_char*)payload, packet, *packet_len) : 0; */
  hdr->sequence_id = 0;
  hdr->pkt_type    = packet_reliable_data;

  traceEvent(TRACE_INFO, "Sent reliable packet [msg_type=%s][seq_id=%d][src_mac=%s][dst_mac=%s]",
             msg_type2str(hdr->msg_type), hdr->sequence_id,
             macaddr_str(&packet[6], src_mac_buf, sizeof(src_mac_buf)),
             macaddr_str(packet, dst_mac_buf, sizeof(dst_mac_buf)));

  marshall_n2n_packet_header( (u_int8_t *)packet, hdr );

  return(send_data(sinfo, packet, packet_len, to, compress_data));
}

/* *********************************************** */

/* unreliable_sendto is passed a fully marshalled, packet. Its purpose is to set
 * the unreliable flags but leave the rest of the packet untouched. */
u_int unreliable_sendto(n2n_sock_info_t * sinfo,
			char *packet, size_t *packet_len,
			const struct peer_addr *to, u_int8_t compress_data) {
  struct n2n_packet_header hdr_storage;
  struct n2n_packet_header *hdr = &hdr_storage;
  macstr_t src_mac_buf;
  macstr_t dst_mac_buf;

  /* REVISIT: efficiency of unmarshal + re-marshal just to change a couple of bits. */
  unmarshall_n2n_packet_header( hdr, (u_int8_t *)packet );

  hdr->sequence_id = 0; /* Unreliable messages have 0 as sequence number */
  hdr->pkt_type    = packet_unreliable_data;

  traceEvent(TRACE_INFO, "Sent unreliable packet [msg_type=%s][seq_id=%d][src_mac=%s][dst_mac=%s]",
	     msg_type2str(hdr->msg_type), hdr->sequence_id,
	     macaddr_str(hdr->src_mac, src_mac_buf, sizeof(src_mac_buf)),
	     macaddr_str(hdr->dst_mac, dst_mac_buf, sizeof(dst_mac_buf)));

  marshall_n2n_packet_header( (u_int8_t *)packet, hdr );

  return(send_data(sinfo, packet, packet_len, to, compress_data));
}

/* *********************************************** */

char* msg_type2str(u_short msg_type) {
  switch(msg_type) {
  case MSG_TYPE_REGISTER: return("MSG_TYPE_REGISTER");
  case MSG_TYPE_DEREGISTER: return("MSG_TYPE_DEREGISTER");
  case MSG_TYPE_PACKET: return("MSG_TYPE_PACKET");
  case MSG_TYPE_REGISTER_ACK: return("MSG_TYPE_REGISTER_ACK");
  case MSG_TYPE_ACK_RESPONSE: return("MSG_TYPE_ACK_RESPONSE");
  }

  return("???");
}

/* *********************************************** */

void hexdump(char *buf, u_int len) {
  u_int i;

  for(i=0; i<len; i++) {
    if((i > 0) && ((i % 16) == 0)) printf("\n");
    printf("%02X ", buf[i] & 0xFF);
  }

  printf("\n");
}

/* *********************************************** */

void print_n2n_version() {
  printf("Welcome to n2n v.%s for %s\n"
         "Built on %s\n"
	 "Copyright 2007-08 - http://www.ntop.org\n\n",
         version, osName, buildDate);
}




/** Find the peer entry in list with mac_addr equal to mac.
 *
 *  Does not modify the list.
 *
 *  @return NULL if not found; otherwise pointer to peer entry.
 */
struct peer_info * find_peer_by_mac( struct peer_info * list, const char * mac )
{
  while(list != NULL)
    {
      if( 0 == memcmp(mac, list->mac_addr, 6) )
        {
	  return list;
        }
      list = list->next;
    }

  return NULL;
}


/** Return the number of elements in the list.
 *
 */
size_t peer_list_size( const struct peer_info * list )
{
  size_t retval=0;

  while ( list )
    {
      ++retval;
      list = list->next;
    }

  return retval;
}

/** Add new to the head of list. If list is NULL; create it.
 *
 *  The item new is added to the head of the list. New is modified during
 *  insertion. list takes ownership of new.
 */
void peer_list_add( struct peer_info * * list,
                    struct peer_info * new )
{
  new->next = *list;
  new->last_seen = time(NULL);
  *list = new;
}


size_t purge_expired_registrations( struct peer_info ** peer_list ) {
  static time_t last_purge = 0;
  time_t now = time(NULL);
  size_t num_reg = 0;

  if((now - last_purge) < PURGE_REGISTRATION_FREQUENCY) return 0;

  traceEvent(TRACE_INFO, "Purging old registrations");

  num_reg = purge_peer_list( peer_list, now-REGISTRATION_TIMEOUT );

  last_purge = now;
  traceEvent(TRACE_INFO, "Remove %ld registrations", num_reg);

  return num_reg;
}

/** Purge old items from the peer_list and return the number of items that were removed. */
size_t purge_peer_list( struct peer_info ** peer_list,
                        time_t purge_before )
{
  struct peer_info *scan;
  struct peer_info *prev;
  size_t retval=0;

  scan = *peer_list;
  prev = NULL;
  while(scan != NULL)
    {
      if(scan->last_seen < purge_before)
        {
	  struct peer_info *next = scan->next;

	  if(prev == NULL)
            {
	      *peer_list = next;
            }
	  else
            {
	      prev->next = next;
            }

	  ++retval;
	  free(scan);
	  scan = next;
        }
      else
        {
	  prev = scan;
	  scan = scan->next;
        }
    }

  return retval;
}

static u_int8_t hex2byte( const char * s )
{
  char tmp[3];
  tmp[0]=s[0];
  tmp[1]=s[1];
  tmp[2]=0; /* NULL term */

  return((u_int8_t)strtol( s, NULL, 16 ));
}

extern int str2mac( u_int8_t * outmac /* 6 bytes */, const char * s )
{
  size_t i;

  /* break it down as one case for the first "HH", the 5 x through loop for
   * each ":HH" where HH is a two hex nibbles in ASCII. */

  *outmac=hex2byte(s);
  ++outmac;
  s+=2; /* don't skip colon yet - helps generalise loop. */

  for (i=1; i<6; ++i )
    {
      s+=1;
      *outmac=hex2byte(s);
      ++outmac;
      s+=2;
    }

  return 0; /* ok */
}
