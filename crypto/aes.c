#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "../n2n.h"

#include "aes.h"
#include "crypto.h"

/* create a new encryption context with the session key */
int aes_gcm_session_create(gnutls_datum_t *key, gnutls_cipher_hd_t **ctx)
{
    CHECK_CRYPTO();

    /* set dummy IV; actual IV must be set before we do encryption */
    gnutls_datum_t *iv;
    iv = (gnutls_datum_t *) gnutls_secure_malloc(sizeof(gnutls_datum_t));
    iv->data = (uint8_t *) gnutls_secure_malloc(12);
    iv->size = 12;

    /* create encryption context */
    gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_AES_128_GCM;
    *ctx = (gnutls_cipher_hd_t *) gnutls_secure_malloc(sizeof(gnutls_cipher_hd_t));
    GTLS(gnutls_cipher_init(*ctx, cipher, key, iv));
    return 0;
}

/* free an encryption handle */
void aes_gcm_session_destroy(gnutls_cipher_hd_t *ctx)
{
    CHECK_CRYPTO();
    if (ctx) {
        gnutls_cipher_deinit(*ctx);
        traceEvent(TRACE_DEBUG, "AES session closed");
    } else {
        traceEvent(TRACE_DEBUG, "no AES session to be closed");
    }
}

/* for testing purposes TODO: remove */
void *aes_gcm_dummy_key(void)
{
    gnutls_datum_t *key = gnutls_secure_malloc(sizeof(gnutls_datum_t));
    key->data = gnutls_secure_malloc(AEAD_KEY_SIZE);
    key->size = AEAD_KEY_SIZE;
    memset(key->data, 0, key->size);
    return key;
}

/* Authenticated encryption with authenticated data. Currently uses gnutls with
 * nettle as crypto backend. Return negative error code or size of crypttext.
 */
int aes_gcm_authenc(gnutls_cipher_hd_t ctx, uint8_t *pt, size_t pt_len,
        uint8_t *out, size_t out_len, uint8_t *ad, size_t ad_len)
{
    CHECK_CRYPTO();
    uint8_t *ptr;
    uint8_t iv[AEAD_IV_SIZE]; //TODO generate & store actual IV
    memset(iv, 0x15, AEAD_IV_SIZE);

    // TODO we might want to consider padding as in rfc5246 6.2.3.2
    // TODO check output sizes against available space
    // TODO overwrite output buffer on any failure condition

    /* set new IV */
    gnutls_cipher_set_iv(ctx, iv, (size_t) AEAD_IV_SIZE);
    memcpy(out, iv, AEAD_IV_SIZE);
    ptr = out + AEAD_IV_SIZE;

    /* add associated data to be authenticated but not encrypted */
    if (ad_len > 0)
        GTLS(gnutls_cipher_add_auth(ctx, ad, ad_len));

    /* encrypt plaintext */
    if (pt_len > 0) {
        GTLS(gnutls_cipher_encrypt2(ctx, pt, pt_len, ptr,
                out_len - AEAD_IV_SIZE));
        ptr += pt_len;
    }

    /* get integrity check vector */
    uint8_t tag[AEAD_TAG_SIZE];
    GTLS(gnutls_cipher_tag(ctx, tag, AEAD_TAG_SIZE));
    memcpy(ptr, tag, AEAD_TAG_SIZE);
    ptr += AEAD_TAG_SIZE;
    return (int) (ptr - out);
}

/* Authenticated decryption with authenticated data. Will not return data
 * if authentication failed. Return negative error code or size of plaintext.
 */
int aes_gcm_authdec(gnutls_cipher_hd_t ctx, uint8_t *in, size_t in_len,
        uint8_t *out, size_t out_len, uint8_t *ad, size_t ad_len)
{
    CHECK_CRYPTO();
    uint8_t *ptr;

    // TODO we might want to consider padding as in rfc5246 6.2.3.2
    // TODO check output sizes against available space
    // TODO overwrite output buffer on any failure condition
    // authenticate with padding of wrong lenght, else timing attack

    /* abuse the pkcs #12 MAC error to signal failed authentication */
    if (in_len < AEAD_IV_SIZE + AEAD_TAG_SIZE)
        return GNUTLS_E_MAC_VERIFY_FAILED;

    /* set new IV */
    gnutls_cipher_set_iv(ctx, in, (size_t) AEAD_IV_SIZE);
    ptr = in + AEAD_IV_SIZE;

    /* add associated data to be authenticated */
    if (ad_len > 0)
        GTLS(gnutls_cipher_add_auth(ctx, ad, ad_len));

    size_t pt_size = in_len - AEAD_IV_SIZE - AEAD_TAG_SIZE; /* plaintext size */
    if (in_len > 0) {
        /* decrypt ciphertext */
        GTLS(gnutls_cipher_decrypt2(ctx, ptr, pt_size, out, out_len));
        ptr += pt_size;
    }

    /* get integrity check vector */
    uint8_t tag[AEAD_TAG_SIZE];
    GTLS(gnutls_cipher_tag(ctx, tag, AEAD_TAG_SIZE));

    if (memcmp(ptr, tag, AEAD_TAG_SIZE)) {
        traceEvent(TRACE_WARNING, "gnutls error: packet auth failed");
        /* make sure no information is returned */
        memset(ptr - pt_size, 0, pt_size);
        return GNUTLS_E_MAC_VERIFY_FAILED;
    }
    return (int) pt_size;
}
