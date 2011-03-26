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
*/

#include "n2n.h"

struct tx_stats
{
    size_t pkts;
    size_t errors;
};


/* *********************************************** */

static void help() {
  print_n2n_version();
  printf("supernode -l <listening port> [-v] [-h]\n");
  exit(0);
}

/* *********************************************** */

static struct peer_info *known_peers = NULL;
static struct tx_stats supernode_stats = {0,0};

/* *********************************************** */

/** Turn a REGISTER request around and send a REGISTER_ACK packet back to the
 *  sender.
 *
 *  This needs to be done for all incoming REGISTER packets to keep firewalls
 *  open
 */
static void send_register_ack( n2n_sock_info_t * sinfo,
                               const struct peer_addr *destination_peer,
                               const struct n2n_packet_header * reqhdr )
{
    struct n2n_packet_header hdr;
    u_int8_t pkt[N2N_PKT_HDR_SIZE];
    size_t len = sizeof(hdr);

    fill_standard_header_fields(sinfo, &hdr, NULL /* zero src MAC */ );
    hdr.sent_by_supernode = 1;
    hdr.msg_type = MSG_TYPE_REGISTER_ACK;
    memcpy( hdr.community_name, reqhdr->community_name, COMMUNITY_LEN);
    memcpy( hdr.dst_mac, reqhdr->src_mac, 6); /* turn it around */
    /* leave IP sockets unfilled. */

    marshall_n2n_packet_header( pkt, &hdr );
    send_packet(sinfo, (char *)pkt, &len, destination_peer, N2N_COMPRESSION_ENABLED);
}

static void register_peer(struct n2n_packet_header *hdr,
			  struct peer_addr *sender,
			  n2n_sock_info_t * sinfo) {
  struct peer_info *scan = known_peers;
  ipstr_t buf, buf1;
  macstr_t mac_buf;

  send_register_ack( sinfo, sender, hdr ); /* keep firewalls open */

  while(scan != NULL) {
    if((strcmp(scan->community_name, hdr->community_name) == 0)
       && (memcmp(&scan->mac_addr, hdr->src_mac, 6) == 0)) {

      scan->last_seen = time(NULL);
      if ( ( 0 != memcmp(&scan->public_ip, sender, sizeof(struct peer_addr)) ) ||
           ( 0 != memcmp(&scan->private_ip, &hdr->private_ip, sizeof(struct peer_addr)) ) ) 
      {
        /* Something is actually different. */
        memcpy(&scan->public_ip, sender, sizeof(struct peer_addr));
        memcpy(&scan->private_ip, &hdr->private_ip, sizeof(struct peer_addr));

        /* Overwrite existing peer */
        traceEvent(TRACE_NORMAL, "Re-registered node [public_ip=(%d)%s:%hu][private_ip=%s:%hu][mac=%s][community=%s]",
                   scan->public_ip.family,
                   intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
                   ntohs(scan->public_ip.port),
                   intoa(ntohl(scan->private_ip.addr_type.v4_addr), buf1, sizeof(buf1)),
                   ntohs(scan->private_ip.port),
                   macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
                   scan->community_name);
      }
      
      return; /* Found the registration entry so stop. */
    }

    scan = scan->next;
  }

  /* FIX mettere un limite alla lista dei peer */

  scan = (struct peer_info*)calloc(1, sizeof(struct peer_info));
  memcpy(scan->community_name, hdr->community_name, COMMUNITY_LEN);
  memcpy(&scan->public_ip, sender, sizeof(struct peer_addr));
  memcpy(&scan->private_ip, &hdr->private_ip, sizeof(struct peer_addr));
  memcpy(&scan->mac_addr, hdr->src_mac, 6);
  scan->last_seen       = time(NULL); // FIX aggiungere un timeout
  scan->next            = known_peers;
  scan->sinfo           = *sinfo;
  known_peers           = scan;

  traceEvent(TRACE_NORMAL, "Registered new node [public_ip=(%d)%s:%d][private_ip=%s:%d][mac=%s][community=%s]",
             scan->public_ip.family,
	     intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
	     ntohs(scan->public_ip.port),
	     intoa(ntohl(scan->private_ip.addr_type.v4_addr), buf1, sizeof(buf1)),
	     ntohs(scan->private_ip.port),
	     macaddr_str(scan->mac_addr, mac_buf, sizeof(mac_buf)),
	     scan->community_name);
}

/* *********************************************** */

static void deregister_peer(struct n2n_packet_header *hdr,
			    struct peer_addr *sender) {
  struct peer_info *scan = known_peers, *prev = NULL;
  ipstr_t buf, buf1;

  while(scan != NULL) {
    if((strcmp(scan->community_name, hdr->community_name) == 0)
       && (memcmp(&scan->mac_addr, hdr->src_mac, 6) == 0)) {
      /* Overwrite existing peer */
      if(prev == NULL)
	known_peers = scan->next;
      else
	prev->next = scan->next;

      traceEvent(TRACE_INFO, "Degistered node [public_ip=%s:%hu][private_ip=%s:%hu]",
		 intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
		 ntohs(scan->public_ip.port),
		 intoa(ntohl(scan->private_ip.addr_type.v4_addr), buf1, sizeof(buf1)),
		 ntohs(scan->private_ip.port));

      free(scan);
      return;
    }

    scan = scan->next;
  }

  traceEvent(TRACE_WARNING, "Unable to delete specified peer [%s:%hu]",
	     intoa(ntohl(sender->addr_type.v4_addr), buf, sizeof(buf)),
	     ntohs(sender->port));
}

/* *********************************************** */

/* *********************************************** */

static const struct option long_options[] = {
  { "community",       required_argument, NULL, 'c' },
  { "listening-port",  required_argument, NULL, 'l' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};

/* *********************************************** */


/** Forward a L2 packet to every edge registered for the community of the
 * originator.
 *
 *  @return number of copies of the packet sent
 */
static size_t broadcast_packet(char *packet, u_int packet_len, 
                               struct peer_addr *sender,
                               n2n_sock_info_t * sinfo,
                               struct n2n_packet_header *hdr )
{
    size_t numsent=0;
    struct peer_info *scan;

    scan = known_peers;
    while(scan != NULL) {
        if((strcmp(scan->community_name, hdr->community_name) == 0)
           && (memcmp(sender, &scan->public_ip, sizeof(struct peer_addr)) /* No L3 self-send */) )
        {
            int data_sent_len;
            size_t len = packet_len;
          
            data_sent_len = send_data( &(scan->sinfo), packet, &len, &scan->public_ip, 0);

            if(data_sent_len != len)
            {
                ++(supernode_stats.errors);
                traceEvent(TRACE_WARNING, "sendto() [sent=%d][attempted_to_send=%d] [%s]\n",
                           data_sent_len, len, strerror(errno));
            }
            else 
            {
                ipstr_t buf;
                ipstr_t buf1;

                ++numsent;
                ++(supernode_stats.pkts);
                traceEvent(TRACE_INFO, "Sent multicast message to remote node [%s:%hu][mac=%s]",
                           intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
                           ntohs(scan->public_ip.port),
                           macaddr_str(scan->mac_addr, buf1, sizeof(buf1)));
            }
        }

        scan = scan->next;
    } /* while */


    return numsent;
}


/** Forward a L2 packet. This may involve a broadcast operation.
 *
 *  Rules are as follows:
 *
 *  1. If the dest MAC is a multicast address, broadcast to all edges in the
 *  community.
 *
 *  2. If the dest MAC is known forward to the destination edge only.
 *     Else broadcast to all edges in the community.
 *
 *  @return number of copies of the packet sent
 */
static size_t forward_packet(char *packet, u_int packet_len, 
                             struct peer_addr *sender,
                             n2n_sock_info_t * sinfo,
                             struct n2n_packet_header *hdr )
{
    size_t numsent=0;
    u_int8_t is_dst_broad_multi_cast;
    struct peer_info *scan;

    ipstr_t buf;
    ipstr_t buf1;

    hdr->ttl++; /* FIX discard packets with a high TTL */
    is_dst_broad_multi_cast = is_multi_broadcast(hdr->dst_mac);

    /* Put the original packet sender (public) address */
    memcpy(&hdr->public_ip, sender, sizeof(struct peer_addr));
    hdr->sent_by_supernode = 1;

    marshall_n2n_packet_header( (u_int8_t *)packet, hdr );


    if ( is_dst_broad_multi_cast )
    {
        traceEvent(TRACE_INFO, "Broadcasting. Multicast address [mac=%s]",
                   macaddr_str(hdr->dst_mac, buf, sizeof(buf)));

        numsent = broadcast_packet( packet, packet_len, sender, sinfo, hdr );
    }
    else
    {
        scan = find_peer_by_mac( known_peers, hdr->dst_mac );
        if ( scan )
        {
            int data_sent_len;
            size_t len = packet_len;
          
            data_sent_len = send_data( &(scan->sinfo), packet, &len, &scan->public_ip, 0);

            if(data_sent_len != len)
            {
                ++(supernode_stats.errors);
                traceEvent(TRACE_WARNING, "sendto() [sent=%d][attempted_to_send=%d] [%s]\n",
                           data_sent_len, len, strerror(errno));
            }
            else {
                ++(supernode_stats.pkts);
                traceEvent(TRACE_INFO, "Sent message to remote node [%s:%hu][mac=%s]",
                           intoa(ntohl(scan->public_ip.addr_type.v4_addr), buf, sizeof(buf)),
                           ntohs(scan->public_ip.port),
                           macaddr_str(scan->mac_addr, buf1, sizeof(buf1)));
            }

            numsent = 1;
        }
        else
        {
            traceEvent(TRACE_INFO, "Broadcasting because unknown dest [mac=%s]",
                       macaddr_str(hdr->dst_mac, buf, sizeof(buf)));
            numsent = broadcast_packet( packet, packet_len, sender, sinfo, hdr );
        }
    }

    return numsent;
}

static void handle_packet(char *packet, u_int packet_len, 
                          struct peer_addr *sender,
                          n2n_sock_info_t * sinfo) {
    ipstr_t buf;

    traceEvent(TRACE_INFO, "Received message from node [%s:%hu]",
               intoa(ntohl(sender->addr_type.v4_addr), buf, sizeof(buf)),
               ntohs(sender->port));

    if(packet_len < N2N_PKT_HDR_SIZE)
        traceEvent(TRACE_WARNING, "Received packet too short [len=%d]\n", packet_len);
    else {
        struct n2n_packet_header hdr_storage;
        struct n2n_packet_header *hdr = &hdr_storage;

        unmarshall_n2n_packet_header( hdr, (u_int8_t *)packet );

        if(hdr->version != N2N_PKT_VERSION) {
            traceEvent(TRACE_WARNING,
                       "Received packet with unknown protocol version (%d): discarded\n",
                       hdr->version);
            return;
        }

        if(hdr->msg_type == MSG_TYPE_REGISTER) 
        {
            register_peer(hdr, sender, sinfo);
        }
        else if(hdr->msg_type == MSG_TYPE_DEREGISTER) {
            deregister_peer(hdr, sender);
        } else if(hdr->msg_type == MSG_TYPE_PACKET) {
            forward_packet( packet, packet_len, sender, sinfo, hdr );
        } else {
            traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored\n",
                       hdr->msg_type);
        }
    }
}

/* *********************************************** */

static
#ifdef WIN32
DWORD tcpReadThread(LPVOID lpArg)
#else
  void* tcpReadThread(void *lpArg)
#endif
{
  n2n_sock_info_t sinfo;
  char c[1600];
  int new_line = 0;

  sinfo.sock=(int)lpArg;
  sinfo.is_udp_socket=0; /* TCP in this case */

  traceEvent(TRACE_NORMAL, "Handling sock_fd %d", sinfo.sock);

  while(1) {
    int rc;

    if((rc = recv(sinfo.sock, c, 2, 0)) > 0) {
      if((c[0] == '\r') && (c[1] == '\n')) {
	if(!new_line)
	  new_line = 1;
	else
	  break; /* Double \r\n\r\n, the http header is over */
      } else
	printf("%c%c [%d][%d] ", c[0], c[1], c[0], c[1]); fflush(stdout);
    } else {
      traceEvent(TRACE_NORMAL, "recv() error [rc=%d][%s]", rc, strerror(errno));
      break;
    }
  }

  /* Beginning of n2n protocol over TCP */
  c[5] = 0;

  while(1) {
    int rc;

    // FIX: add select
    if((rc = recv(sinfo.sock, c, 4, 0)) == 4) {
      int len = atoi(c);
      socklen_t from_len = sizeof(struct sockaddr_in );
      struct sockaddr_in from;

      /* Check packet length */
      if((len <= 0) || (len >= 1600)) break;
      rc = recvfrom(sinfo.sock, c, len, 0, (struct sockaddr*)&from, &from_len);

      if((rc <= 0) || (rc != len))
	break;
      else {
	struct peer_addr _from;

	sockaddr_in2peer_addr(&from, &_from);
	handle_packet(c, len, &_from, &sinfo);
      }
    } else
      break;
  }

  closesocket(sinfo.sock);
#ifdef WIN32
	return(0);
#else
  return(NULL);
#endif
}


/* *********************************************** */

static void startTcpReadThread(int sock_fd) {
#ifdef WIN32
  HANDLE hThread;
  DWORD dwThreadId;

  hThread = CreateThread(NULL, /* no security attributes */
			 0,    /* use default stack size */
			 (LPTHREAD_START_ROUTINE)tcpReadThread, /* thread function */
			 (void*)sock_fd, /* argument to thread function */
			 0,              /* use default creation flags */
			 &dwThreadId);   /* returns the thread identifier */
#else
  int rc;
  pthread_t threadId;

  rc = pthread_create(&threadId, NULL, tcpReadThread, (void*)sock_fd);
#endif
}

/* *********************************************** */

int main(int argc, char* argv[]) {
  int opt; 
  u_int16_t local_port = 0;
  n2n_sock_info_t udp_sinfo;
  n2n_sock_info_t tcp_sinfo;

#ifdef WIN32
  initWin32();
#endif

  optarg = NULL;
  while((opt = getopt_long(argc, argv, "l:vh", long_options, NULL)) != EOF) {
    switch (opt) {
    case 'l': /* local-port */
      local_port = atoi(optarg) & 0xffff;
      break;
    case 'h': /* help */
      help();
      break;
    case 'v': /* verbose */
      traceLevel = 3;
      break;
    }
  }

  if(!(local_port))
    help();

  udp_sinfo.is_udp_socket=1;
  udp_sinfo.sock = open_socket(local_port, 1, 0);
  if(udp_sinfo.sock < 0) return(-1);

  tcp_sinfo.is_udp_socket=0;
  tcp_sinfo.sock = open_socket(local_port, 0, 1);
  if(tcp_sinfo.sock < 0) return(-1);

  traceEvent(TRACE_NORMAL, "Supernode ready: listening on port %hu [TCP/UDP]", local_port);

  while(1) {
    int rc, max_sock;
    fd_set socket_mask;
    struct timeval wait_time;

    FD_ZERO(&socket_mask);
    max_sock = max(udp_sinfo.sock, tcp_sinfo.sock);
    FD_SET(udp_sinfo.sock, &socket_mask);
    FD_SET(tcp_sinfo.sock, &socket_mask);

    wait_time.tv_sec = 10; wait_time.tv_usec = 0;
    rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);

    if(rc > 0) {
      if(FD_ISSET(udp_sinfo.sock, &socket_mask)) {
	char packet[2048];
	size_t len;
	struct peer_addr sender;
	u_int8_t discarded_pkt;
	struct n2n_packet_header hdr;

	len = receive_data( &udp_sinfo, packet, sizeof(packet), &sender, &discarded_pkt, NULL, 0, &hdr);

	if(len <= 0)
	  traceEvent(TRACE_WARNING, "recvfrom()=%d [%s]\n", len, strerror(errno));
	else {
	  handle_packet(packet, len, &sender, &udp_sinfo);
	}
      } else if(FD_ISSET(tcp_sinfo.sock, &socket_mask)) {
	struct sockaddr from;
	int from_len = sizeof(from);
	int new_sock = accept(tcp_sinfo.sock, (struct sockaddr*)&from,
			      (socklen_t*)&from_len);

	if(new_sock < 0) {
	  traceEvent(TRACE_WARNING, "TCP connection accept() failed [%s]\n", strerror(errno));
	} else {
	  startTcpReadThread(new_sock);
	}
      }
    }

    purge_expired_registrations( &known_peers );
  } /* while */

  closesocket(udp_sinfo.sock);
  closesocket(tcp_sinfo.sock);

  return(0);
}
