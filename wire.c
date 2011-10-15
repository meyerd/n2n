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
        retval += encode_sock(base, idx, &reg->ack.a_pub_sock);
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
        retval += decode_sock(base, idx, rem, &reg->ack.a_pub_sock);
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

int encode_HEADER(uint8_t * base, size_t * idx, const n2n_HEADER_t *hdr)
{
    encode_uint8(base, idx, N2N_MAJOR_VERSION);
    encode_uint8(base, idx, N2N_MINOR_VERSION);
    encode_uint8(base, idx, hdr->pc);
    encode_uint8(base, idx, hdr->flags);
    return 0;
}

int decode_HEADER(const uint8_t * base, size_t * idx, size_t * rem,
        n2n_HEADER_t * hdr)
{
    uint8_t major_version, minor_version;
    decode_uint8(base, idx, rem, &major_version);
    decode_uint8(base, idx, rem, &minor_version);
    if(major_version != N2N_MAJOR_VERSION ||
            minor_version != N2N_MINOR_VERSION) {
        /* error: version missmatch */
        return 1;
    }
    decode_uint8(base, idx, rem, (uint8_t *) &hdr->pc);
    decode_uint8(base, idx, rem, (uint8_t *) &hdr->flags);
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

