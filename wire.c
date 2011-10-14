/* (c) 2009 Richard Andrews <andrews@ntop.org> */

/** Routines for encoding and decoding n2n packets on the wire.
 *
 *  encode_X(base,idx,v) prototypes are inspired by the erlang internal
 *  encoding model. Passing the start of a buffer in base and a pointer to an
 *  integer (initially set to zero). Each encode routine increases idx by the
 *  amount written and returns the amount written. In this way complex sequences
 *  of encodings can be represented cleanly. See encode_register() for an
 *  example.
 */

#include "n2n_wire.h"
#include <string.h>

int encode_uint8(uint8_t * base, size_t * idx, const uint8_t v)
{
    *(base + (*idx)) = (v & 0xff);
    ++(*idx);
    return 1;
}

int decode_uint8(const uint8_t * base, size_t * idx, size_t * rem,
        uint8_t * out)
{
    if (*rem < 1) {
        return 0;
    }

    *out = (base[*idx] & 0xff );
    ++(*idx);
    --(*rem);
    return 1;
}

int encode_uint16(uint8_t * base, size_t * idx, const uint16_t v)
{
    *(base + (*idx)) = (v >> 8) & 0xff;
    *(base + (1 + *idx)) = (v & 0xff );
    *idx += 2;
    return 2;
}

int decode_uint16(const uint8_t * base, size_t * idx, size_t * rem,
        uint16_t * out)
{
    if (*rem < 2) {
        return 0;
    }

    *out = (base[*idx] & 0xff) << 8;
    *out |= (base[1 + *idx] & 0xff );
    *idx += 2;
    *rem -= 2;
    return 2;
}

int encode_uint32(uint8_t * base, size_t * idx, const uint32_t v)
{
    *(base + (0 + *idx)) = (v >> 24) & 0xff;
    *(base + (1 + *idx)) = (v >> 16) & 0xff;
    *(base + (2 + *idx)) = (v >> 8) & 0xff;
    *(base + (3 + *idx)) = (v & 0xff );
    *idx += 4;
    return 4;
}

int decode_uint32(const uint8_t * base, size_t * idx, size_t * rem,
        uint32_t * out)
{
    if (*rem < 4) {
        return 0;
    }

    *out = (base[0 + *idx] & 0xff) << 24;
    *out |= (base[1 + *idx] & 0xff) << 16;
    *out |= (base[2 + *idx] & 0xff) << 8;
    *out |= (base[3 + *idx] & 0xff );
    *idx += 4;
    *rem -= 4;
    return 4;
}

int encode_buf(uint8_t * base, size_t * idx, const void * p, size_t s)
{
    memcpy((base + (*idx)), p, s );
    *idx += s;
    return s;
}

/* Copy from base to out of size bufsize */
int decode_buf(const uint8_t * base, size_t * idx, size_t * rem,
        uint8_t * out, size_t bufsize)
{
    if (*rem < bufsize) {
        return 0;
    }

    memcpy(out, (base + *idx), bufsize );
    *idx += bufsize;
    *rem -= bufsize;
    return bufsize;
}

int encode_mac(uint8_t * base, size_t * idx, const n2n_mac_t m)
{
    return encode_buf(base, idx, m, N2N_MAC_SIZE);
}

int decode_mac(const uint8_t * base, size_t * idx, size_t * rem,
        uint8_t * out /* of size N2N_MAC_SIZE. This clearer than passing a
                         n2n_mac_t */ )
{
    return decode_buf(base, idx, rem, out, N2N_MAC_SIZE);
}

int encode_sock(uint8_t * base, size_t * idx, const n2n_sock_t * sock)
{
    int retval = 0;
    uint16_t f;

    switch (sock->family) {
    case AF_INET:
    {
        f = 0;
        retval += encode_uint16(base, idx, f);
        retval += encode_uint16(base, idx, sock->port);
        retval += encode_buf(base, idx, sock->addr.v4, IPV4_SIZE);
        break;
    }
    case AF_INET6:
    {
        f = 0x8000;
        retval += encode_uint16(base, idx, f);
        retval += encode_uint16(base, idx, sock->port);
        retval += encode_buf(base, idx, sock->addr.v6, IPV6_SIZE);
        break;
    }
    default:
        retval = -1;
    }

    return retval;
}

int decode_sock(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_sock_t * sock)
{
    size_t * idx0 = idx;
    uint16_t f;

    decode_uint16(base, idx, rem, &f);

    if (f & 0x8000) {
        /* IPv6 */
        sock->family = AF_INET6;
        decode_uint16(base, idx, rem, &(sock->port));
        decode_buf(base, idx, rem, sock->addr.v6, IPV6_SIZE);
    } else {
        /* IPv4 */
        sock->family = AF_INET;
        decode_uint16(base, idx, rem, &(sock->port));
        memset(sock->addr.v6, 0, IPV6_SIZE); /* so memcmp() works for equality. */
        decode_buf(base, idx, rem, sock->addr.v4, IPV4_SIZE);
    }

    return (idx - idx0);
}

int encode_supernode_register(uint8_t * base, size_t * idx,
        int ack, const n2n_supernode_register_t * reg)
{
    int retval = 0;
    if (!ack) {
        retval += encode_mac(base, idx, reg->syn.a_mac);
        retval += encode_ip(base, idx, reg->syn.a_n2n_ip);
    } else {
        retval += encode_sock(base, idx, reg->ack.a_pub_sock);
    }
    return retval;
}

int decode_supernode_register(const uint8_t * base, size_t * idx, size_t * rem,
        int ack, n2n_supernode_register_t * reg)
{
    int retval = 0;
    if(!ack) {
        retval += decode_mac(base, idx, rem, reg->syn.a_mac);
        retval += decode_ip(base, idx, rem, reg->syn.a_n2n_ip);
    } else {
        retval += decode_sock(base, idx, rem, reg->syn.a_n2n_ip);
    }
    return retval;
}

int encode_REGISTER_SUPER(uint8_t * base, size_t * idx,
        const n2n_common_t * common, const n2n_REGISTER_SUPER_t * reg)
{
    int retval = 0;
    retval += encode_common(base, idx, common);
    retval += encode_uint16(base, idx, reg->aflags);
    retval += encode_uint16(base, idx, reg->timeout);
    retval += encode_buf(base, idx, reg->cookie, N2N_COOKIE_SIZE);
    retval += encode_mac(base, idx, reg->edgeMac);
    retval += encode_uint16(base, idx, 0); /* NULL auth scheme */
    retval += encode_uint16(base, idx, 0); /* No auth data */
    if (reg->aflags & N2N_AFLAGS_LOCAL_SOCKET)
        retval += encode_sock(base, idx, &(reg->local_sock));

    return retval;
}

int decode_REGISTER_SUPER(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_REGISTER_SUPER_t * reg,
        const n2n_common_t * cmn /* info on how to interpret it */ )
{
    size_t retval = 0;
    memset(reg, 0, sizeof(n2n_REGISTER_SUPER_t));
    retval += decode_uint16(base, idx, rem, &(reg->aflags));
    retval += decode_uint16(base, idx, rem, &(reg->timeout));
    retval += decode_buf(base, idx, rem, reg->cookie, N2N_COOKIE_SIZE);
    retval += decode_mac(base, idx, rem, reg->edgeMac);
    retval += decode_uint16(base, idx, rem, &(reg->auth.scheme));
    retval += decode_uint16(base, idx, rem, &(reg->auth.toksize));
    retval += decode_buf(base, idx, rem, reg->auth.token, reg->auth.toksize);
    if (reg->aflags & N2N_AFLAGS_LOCAL_SOCKET)
        retval += decode_sock(base, idx, rem, &(reg->local_sock));

    return retval;
}

int encode_PEER_INFO(uint8_t * base, size_t * idx, const n2n_common_t * common,
        const n2n_PEER_INFO_t * pi)
{
    int retval = 0;
    retval += encode_common(base, idx, common);
    retval += encode_uint16(base, idx, pi->aflags);
    retval += encode_uint16(base, idx, pi->timeout);
    retval += encode_mac(base, idx, pi->mac);
    retval += encode_sock(base, idx, pi->sockets);
    if (pi->aflags & N2N_AFLAGS_LOCAL_SOCKET)
        retval += encode_sock(base, idx, pi->sockets + 1);

    return retval;
}

int decode_PEER_INFO(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_PEER_INFO_t * pi,
        const n2n_common_t * cmn /* info on how to interpret it */ )
{
    size_t retval = 0;
    memset(pi, 0, sizeof(n2n_PEER_INFO_t));
    retval += decode_uint16(base, idx, rem, &(pi->aflags));
    retval += decode_uint16(base, idx, rem, &(pi->timeout));
    retval += decode_mac(base, idx, rem, pi->mac);
    retval += decode_sock(base, idx, rem, pi->sockets);
    if (pi->aflags & N2N_AFLAGS_LOCAL_SOCKET
        )
        retval += decode_sock(base, idx, rem, pi->sockets + 1);

    return retval;
}

int encode_QUERY_PEER(uint8_t * base, size_t * idx, const n2n_common_t * common,
        const n2n_QUERY_PEER_t * qp)
{
    int retval = 0;
    retval += encode_common(base, idx, common);
    retval += encode_mac(base, idx, qp->srcMac);
    retval += encode_mac(base, idx, qp->targetMac);

    return retval;
}

int decode_QUERY_PEER(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_QUERY_PEER_t * qp,
        const n2n_common_t * cmn /* info on how to interpret it */)
{
    size_t retval = 0;
    memset(qp, 0, sizeof(n2n_QUERY_PEER_t));
    retval += decode_mac(base, idx, rem, qp->srcMac);
    retval += decode_mac(base, idx, rem, qp->targetMac);

    return retval;
}

int encode_REGISTER_ACK(uint8_t * base, size_t * idx,
        const n2n_common_t * common, const n2n_REGISTER_ACK_t * reg)
{
    int retval = 0;
    retval += encode_common(base, idx, common);
    retval += encode_buf(base, idx, reg->cookie, N2N_COOKIE_SIZE);
    retval += encode_mac(base, idx, reg->dstMac);
    retval += encode_mac(base, idx, reg->srcMac);

    return retval;
}

int decode_REGISTER_ACK(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_REGISTER_ACK_t * reg,
        const n2n_common_t * cmn /* info on how to interpret it */ )
{
    size_t retval = 0;
    memset(reg, 0, sizeof(n2n_REGISTER_ACK_t));
    retval += decode_buf(base, idx, rem, reg->cookie, N2N_COOKIE_SIZE);
    retval += decode_mac(base, idx, rem, reg->dstMac);
    retval += decode_mac(base, idx, rem, reg->srcMac);

    return retval;
}

int encode_REGISTER_SUPER_ACK(uint8_t * base, size_t * idx,
        const n2n_common_t * common, const n2n_REGISTER_SUPER_ACK_t * reg)
{
    int retval = 0;
    retval += encode_common(base, idx, common);
    retval += encode_buf(base, idx, reg->cookie, N2N_COOKIE_SIZE);
    retval += encode_mac(base, idx, reg->edgeMac);
    retval += encode_uint16(base, idx, reg->lifetime);
    retval += encode_sock(base, idx, &(reg->sock));
    retval += encode_uint8(base, idx, reg->num_sn);
    if (reg->num_sn > 0) {
        /* We only support 0 or 1 at this stage */
        retval += encode_sock(base, idx, &(reg->sn_bak));
    }

    return retval;
}

int decode_REGISTER_SUPER_ACK(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_REGISTER_SUPER_ACK_t * reg,
        const n2n_common_t * cmn, /* info on how to interpret it */ )
{
    size_t retval = 0;

    memset(reg, 0, sizeof(n2n_REGISTER_SUPER_ACK_t));
    retval += decode_buf(base, idx, rem, reg->cookie, N2N_COOKIE_SIZE);
    retval += decode_mac(base, idx, rem, reg->edgeMac);
    retval += decode_uint16(base, idx, rem, &(reg->lifetime));

    /* Socket is mandatory in this message type */
    retval += decode_sock(base, idx, rem, &(reg->sock));

    /* Following the edge socket are an array of backup supernodes. */
    retval += decode_uint8(base, idx, rem, &(reg->num_sn));
    if (reg->num_sn > 0) {
        /* We only support 0 or 1 at this stage */
        retval += decode_sock(base, idx, rem, &(reg->sn_bak));
    }

    return retval;
}

int fill_sockaddr(struct sockaddr * addr, size_t addrlen,
        const n2n_sock_t * sock)
{
    int retval = -1;

    if (AF_INET == sock->family) {
        if (addrlen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in * si = (struct sockaddr_in *) addr;
            si->sin_family = sock->family;
            si->sin_port = htons(sock->port);
            memcpy(&(si->sin_addr.s_addr), sock->addr.v4, IPV4_SIZE);
            retval = 0;
        }
    }

    return retval;
}

int encode_PACKET(uint8_t * base, size_t * idx, const n2n_common_t * common,
        const n2n_PACKET_t * pkt)
{
    int retval = 0;
    retval += encode_common(base, idx, common);
    retval += encode_uint16(base, idx, pkt->transform);

    return retval;
}

int decode_PACKET(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_PACKET_t * pkt,
        const n2n_common_t * cmn /* info on how to interpret it */ )
{
    size_t retval = 0;
    memset(pkt, 0, sizeof(n2n_PACKET_t));
    retval += decode_uint16(base, idx, rem, &(pkt->transform));

    return retval;
}

int encode_HEADER(uint8_t * base, size_t * idx, const n2n_HEADER_t *hdr)
{
    encode_uint8(base, idx, hdr->version_major);
    encode_uint8(base, idx, hdr->version_minor);
    encode_uint8(base, idx, hdr->pc);
    encode_uint8(base, idx, hdr->flags);
    return 0;
}

int decode_HEADER(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_HEADER_t * hdr)
{
    decode_uint8(base, idx, rem, &hdr->version_major);
    decode_uint8(base, idx, rem, &hdr->version_minor);
    decode_uint8(base, idx, rem, &hdr->packet_type);
    decode_uint8(base, idx, rem, &hdr->flags);
    return 0;
}


void decode_ETHFRAMEHDR(const uint8_t * base, n2n_ETHFRAMEHDR_t * eth)
{
    memcpy(eth->dstMac, base, N2N_MAC_SIZE);
    base += N2N_MAC_SIZE;
    memcpy(eth->srcMac, base, N2N_MAC_SIZE);
}

int copy_ETHFRAMEHDR(uint8_t * base, uint8_t * pkt)
{
    memcpy(base, pkt, ETH_FRAMEHDRSIZE);
    return ETH_FRAMEHDRSIZE;
}

