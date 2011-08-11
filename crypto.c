#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gcrypt.h>
#include "n2n.h"
#include "crypto.h"

#define GCRYPT_NO_DEPRECATED
#define AEAD_KEY_SIZE 16  // TODO remove
#define AEAD_IV_SIZE 12
#define AEAD_TAG_SIZE 16
#define DERIV_HMAC_SIZE 48

static int CRYPTO_INITIALIZED = 0;

/* initialize global values for the cryptographic engine */
int crypto_init(void)
{
    gcry_error_t gc_err;
    int gt_err;
    /* initialize libgcrypt */
    if (!gcry_check_version(GCRYPT_VERSION)) {
        traceEvent(TRACE_ERROR, "gcrypt init error: unsuitable version");
        return -1;
    }

    /* Allocate a pool of 16k secure memory.  This make the secure memory
     * available and also drops privileges where needed.
     */
    //TODO dynamic secure memory management
    gc_err = gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    if (gc_err != GPG_ERR_NO_ERROR) {
        traceEvent(TRACE_ERROR, "gcrypt init error: init sec mem");
        return (int) gcry_err_code(gc_err);
    }

    /* Tell Libgcrypt that initialization has completed. */
    gc_err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (gc_err != GPG_ERR_NO_ERROR) {
        traceEvent(TRACE_ERROR, "gcrypt init error: init finalize");
        return (int) gcry_err_code(gc_err);
    }

    /* Import secure memory handling functions from libgcrypt into gnutls,
     * since gnutls doesn't have any.
     */
    gnutls_global_set_mem_functions(gcry_malloc, gcry_malloc_secure,
            gcry_is_secure, gcry_realloc, gcry_free);

    /* initialize gnutls engine */
    gt_err = gnutls_global_init();
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls init error: global init");
        return gt_err;
    }

    CRYPTO_INITIALIZED = 1;
    return 0;
}


/* free gnutls structures */
void crypto_deinit(void)
{
    CRYPTO_INITIALIZED = 0;
    gnutls_global_deinit();
}


/* derive a session key from the shared secret 'ss' as source_key and the salt
 * using a HMAC based key derivation function (RFC 5869):
 * HKDF(salt, source_key, infostring, outlen) = K1 | K2 | ... | Kt
 *     prk = HMAC(salt, source_key)
 *     K1 = HMAC(prk, infostring | 0x01)
 *     K2 = HMAC(prk, K1 | infostring | 0x02)
 *     K3 = HMAC(prk, K2 | infostring | 0x03) ...
 */
static int derive_key(const void **salt, size_t saltlen, const void **ss,
        size_t sslen, void **derived, size_t derivedlen)
{
    if (!CRYPTO_INITIALIZED)
        return 1;
    /* salt and ss should have a length of at least the digest size */
    if (saltlen < DERIV_HMAC_SIZE || sslen < DERIV_HMAC_SIZE)
        return 2;
    /* currently not supported, but could be done by completely implementing
     * rfc 5869
     */
    if (derivedlen > DERIV_HMAC_SIZE)
        return 3;

    int gt_err;

    /* data is optional and may be constant */
    int datalen = 29;
    char data[] = "n2n edge aes-gcm session key ";
    data[datalen - 1] = (uint8_t) 0x01;

    uint8_t *prk;
    uint8_t *okm;
    prk = gnutls_malloc(DERIV_HMAC_SIZE);  // pseudorandom key
    okm = gnutls_malloc(DERIV_HMAC_SIZE);  // output key material
    derived = gnutls_malloc(derivedlen);

    /* the salt is used as the key, the shared secret is used as data */
    gt_err = gnutls_hmac_fast(GNUTLS_MAC_SHA384, *salt, saltlen,
            *ss, sslen, prk);
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls error: key derivation");
        return gt_err;
    }

    gt_err = gnutls_hmac_fast(GNUTLS_MAC_SHA384, prk, DERIV_HMAC_SIZE,
            data, datalen, okm);
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls error: key derivation");
        return gt_err;
    }

    memcpy(*derived, okm, derivedlen);
    gnutls_free(prk);
    gnutls_free(okm);
    return 0;
}


/* create a new encryption context with the session key */
int aes_gcm_session_create(gnutls_datum_t *key, gnutls_cipher_hd_t **ctx)
{
    if (!CRYPTO_INITIALIZED)
        return 1;

    int gt_err;

    /* set dummy IV; actual IV must be set before we do encryption */
    gnutls_datum_t *iv;
    iv = (gnutls_datum_t *) gnutls_malloc(sizeof(gnutls_datum_t));
    iv->data = (uint8_t *) gnutls_malloc(12);
    iv->size = 12;

    /* create encryption context */
    gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_AES_128_GCM;
    *ctx = (gnutls_cipher_hd_t *) gnutls_malloc(sizeof(gnutls_cipher_hd_t));
    gt_err = gnutls_cipher_init(*ctx, cipher, key, iv);
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls error: cipher init");
        return gt_err;
    }
    return 0;
}


/* free an encryption handle */
void aes_gcm_session_destroy(gnutls_cipher_hd_t *ctx)
{
    if (ctx) {
        gnutls_cipher_deinit(*ctx);
        traceEvent(TRACE_DEBUG, "AES session closed");
    } else  {
        traceEvent(TRACE_DEBUG, "no AES session to be closed");
    }
}


/* for testing purposes TODO: remove */
void *aes_gcm_dummy_key(void)
{
    gnutls_datum_t *key = gnutls_malloc(sizeof(gnutls_datum_t));
    key->data = gnutls_malloc(AEAD_KEY_SIZE);
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
    if (!CRYPTO_INITIALIZED)
        return 1;
    int gt_err;
    uint8_t *ptr;
    uint8_t iv[AEAD_IV_SIZE];  //TODO generate & store actual IV
    memset(iv, 0x15, AEAD_IV_SIZE);

    // TODO we might want to consider padding as in rfc5246 6.2.3.2
    // TODO check output sizes against available space
    // TODO overwrite output buffer on any failure condition

    /* set new IV */
    gnutls_cipher_set_iv(ctx, iv, (size_t) AEAD_IV_SIZE);
    memcpy(out, iv, AEAD_IV_SIZE);
    ptr = out + AEAD_IV_SIZE;

    /* add associated data to be authenticated but not encrypted */
    if (ad_len > 0) {
        gt_err = gnutls_cipher_add_auth(ctx, ad, ad_len);
        if (gt_err != GNUTLS_E_SUCCESS) {
            traceEvent(TRACE_ERROR, "gnutls error: add auth data");
            return gt_err;
        }
    }

    /* encrypt plaintext */
    if (pt_len > 0) {
        gt_err = gnutls_cipher_encrypt2(ctx, pt, pt_len, ptr,
                out_len - AEAD_IV_SIZE);
        if (gt_err != GNUTLS_E_SUCCESS) {
            traceEvent(TRACE_ERROR, "gnutls error: encrypt");
            return gt_err;
        }
        ptr += pt_len;
    }

    /* get integrity check vector */
    uint8_t tag[AEAD_TAG_SIZE];
    gt_err = gnutls_cipher_tag(ctx, tag, AEAD_TAG_SIZE);
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls error: authentication tag");
        return gt_err;
    }
    memcpy(ptr, tag, AEAD_TAG_SIZE);
    ptr += AEAD_TAG_SIZE;
    return (int) (ptr - out);
}


/* Authenticated decryption with authenticated data. Will not return data
 * if authentication failed. Return negative error code or size of plaintext.
 */
int aes_gcm_authdec(gnutls_cipher_hd_t ctx, uint8_t *in, size_t in_len, uint8_t
        *out, size_t out_len, uint8_t *ad, size_t ad_len)
{
    if (!CRYPTO_INITIALIZED)
        return 1;
    int gt_err;
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
    if (ad_len > 0) {
        gt_err = gnutls_cipher_add_auth(ctx, ad, ad_len);
        if (gt_err != GNUTLS_E_SUCCESS) {
            traceEvent(TRACE_ERROR, "gnutls error: add auth data");
            return gt_err;
        }
    }

    size_t pt_size = in_len - AEAD_IV_SIZE - AEAD_TAG_SIZE;  /* plaintext size */
    if (in_len > 0) {
        /* decrypt ciphertext */
        gt_err = gnutls_cipher_decrypt2(ctx, ptr, pt_size, out,
                out_len);
        if (gt_err != GNUTLS_E_SUCCESS) {
            traceEvent(TRACE_ERROR, "gnutls error: decrypt");
            return gt_err;
        }
        ptr += pt_size;
    }

    /* get integrity check vector */
    uint8_t tag[AEAD_TAG_SIZE];
    gt_err = gnutls_cipher_tag(ctx, tag, AEAD_TAG_SIZE);
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls error: authentication tag");
        return gt_err;
    }
    if (memcmp(ptr, tag, AEAD_TAG_SIZE)) {
        traceEvent(TRACE_WARNING, "gnutls error: packet auth failed");
        /* make sure no information is returned */
        memset(ptr - pt_size, 0, pt_size);
        return GNUTLS_E_MAC_VERIFY_FAILED;
    }
    return (int) pt_size;
}
