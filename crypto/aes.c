#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "../n2n.h"

#include "aes.h"
#include "crypto.h"

//TODO code real xmalloc function
#define xmalloc xmalloc_sec

//TODO malloc check

/* usage for AES session keys:
 * derive_key(*dh_ss, dh_sslen, *from_spi, *to_spi, *salt_a, saltlen,
 *         "N2N AES-GCM 256 session key", algoidlen,
 *         NULL, 0, **sesskey_a, 32) */
int aes_sa_create(sa_t *sa, void *sk, int sklen)
{
    CHECK_CRYPTO();
    gnutls_datum_t iv;
    iv.size = AEAD_IV_SIZE;

    /* create IV */
    sa->salt = xmalloc_sec(sizeof(uint32_t));
    sa->counter = xmalloc_sec(sizeof(uint64_t));
    GTLS(gnutls_rnd(GNUTLS_RND_RANDOM, sa->salt, sizeof(uint32_t)));
    GTLS(gnutls_rnd(GNUTLS_RND_RANDOM, sa->counter, sizeof(uint64_t)));

    iv.data = xmalloc_sec(AEAD_IV_SIZE);
    memcpy(iv.data, sa->salt, 4);
    memcpy(iv.data + 4, sa->salt, 8);

    GTLS(gnutls_cipher_init(&sa->ctx, GNUTLS_CIPHER_AES_256_GCM, sk, &iv));

    gnutls_free(iv.data);

    return 0;
}


/* free security association */
void aes_sa_destroy(sa_t *sa)
{
    gnutls_free(sa->salt);
    gnutls_free(sa->counter);
    free(sa);
}


/* Authenticated encryption with authenticated data. Return negative error code
 * or size of encrypted text.
 */
int aes_authenc(sa_t *sa, void *pt, size_t pt_len, void *ad, size_t ad_len,
        void *out, size_t out_len)
{
    CHECK_CRYPTO();
    uint8_t *ptr;

    if (out_len < AEAD_IV_SIZE + pt_len + AEAD_TAG_SIZE)
        return GNUTLS_E_APPLICATION_ERROR_MIN;

    ptr = out;

    /* set new IV */
    sa->counter++;  // increment IV
    memcpy(out, sa->salt, 4);
    memcpy(out, sa->counter, 8);
    gnutls_cipher_set_iv(sa->ctx, out, AEAD_IV_SIZE);
    ptr += AEAD_IV_SIZE;

    /* add associated data to be authenticated but not encrypted */
    GTLS(gnutls_cipher_add_auth(sa->ctx, ad, ad_len));

    /* encrypt plaintext */
    GTLS(gnutls_cipher_encrypt2(sa->ctx, pt, pt_len, ptr, out_len -
                AEAD_IV_SIZE - AEAD_TAG_SIZE));
    ptr += pt_len;

    /* get integrity check vector */
    uint8_t tag[AEAD_TAG_SIZE];
    GTLS(gnutls_cipher_tag(sa->ctx, tag, AEAD_TAG_SIZE));
    memcpy(ptr, tag, AEAD_TAG_SIZE);
    ptr += AEAD_TAG_SIZE;
    return (int) (ptr - (uint8_t *) out);
}


/* Authenticated decryption with authenticated data. Return negative error code
 * or size of plaintext. On authentication failure no plaintext will be
 * returned.
 */
int aes_authdec(sa_t *sa, void *in, size_t in_len, void *ad, size_t ad_len,
        void *out, size_t out_len)
{
    CHECK_CRYPTO();
    uint8_t *ptr;
    size_t ct_size;  // size of encrypted text == size of plain text
    uint8_t tag[AEAD_TAG_SIZE];

    ct_size = in_len - AEAD_IV_SIZE - AEAD_TAG_SIZE;
    if (in_len < AEAD_IV_SIZE + AEAD_TAG_SIZE || out_len < ct_size)
        return GNUTLS_E_APPLICATION_ERROR_MIN;

    /* read IV */
    gnutls_cipher_set_iv(sa->ctx, in, AEAD_IV_SIZE);
    ptr = (uint8_t *) in + AEAD_IV_SIZE;

    /* authenticate additional plain data */
    GTLS(gnutls_cipher_add_auth(sa->ctx, ad, ad_len));

    /* decrypt */
    GTLS(gnutls_cipher_decrypt2(sa->ctx, ptr, ct_size, out, out_len));
    ptr += ct_size;

    /* get integrity check vector aka tag */
    GTLS(gnutls_cipher_tag(sa->ctx, tag, AEAD_TAG_SIZE));

    /* compare tags */
    if (memcmp(ptr, tag, AEAD_TAG_SIZE)) {
        traceEvent(TRACE_WARNING, "gnutls error: packet auth failed");
        /* make sure no information is returned */
        memset(in, 0, in_len);
        memset(out, 0, out_len);
        return GNUTLS_E_APPLICATION_ERROR_MAX;
    }
    return (int) ct_size;
}
