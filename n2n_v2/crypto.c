#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gcrypt.h>
#include "n2n.h"
#include "crypto.h"

#define GCRYPT_NO_DEPRECATED
#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16

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
    gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_AES_256_GCM;
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
    // TODO remove debug output
    if (ctx) {
        gnutls_cipher_deinit(*ctx);
        printf("AES session closed\n");
    } else  {
        printf("no AES session to be closed\n");
    }
}


/* for testing purposes TODO: remove */
void *aes_gcm_dummy_key(void)
{
    gnutls_datum_t *key = gnutls_malloc(sizeof(gnutls_datum_t));
    key->data = gnutls_malloc(KEY_SIZE);
    key->size = KEY_SIZE;
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
    uint8_t iv[IV_SIZE];  //TODO generate & store actual IV

    // TODO we might want to consider padding as in rfc5246 6.2.3.2
    // TODO check output sizes against available space

    /* set new IV */
    gnutls_cipher_set_iv(ctx, iv, (size_t) IV_SIZE);
    memcpy(out, iv, IV_SIZE);
    ptr = out + IV_SIZE;

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
                out_len - IV_SIZE);
        if (gt_err != GNUTLS_E_SUCCESS) {
            traceEvent(TRACE_ERROR, "gnutls error: encrypt");
            return gt_err;
        }
        ptr += pt_len;
    }

    /* get integrity check vector */
    uint8_t tag[TAG_SIZE];
    gt_err = gnutls_cipher_tag(ctx, tag, TAG_SIZE);
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls error: authentication tag");
        return gt_err;
    }
    memcpy(ptr, tag, TAG_SIZE);
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

    /* abuse the pkcs #12 MAC error to signal failed authentication */
    if (in_len < IV_SIZE + TAG_SIZE)
        return GNUTLS_E_MAC_VERIFY_FAILED;

    /* set new IV */
    gnutls_cipher_set_iv(ctx, in, (size_t) IV_SIZE);
    ptr = in + IV_SIZE;

    /* add associated data to be authenticated */
    if (ad_len > 0) {
        gt_err = gnutls_cipher_add_auth(ctx, ad, ad_len);
        if (gt_err != GNUTLS_E_SUCCESS) {
            traceEvent(TRACE_ERROR, "gnutls error: add auth data");
            return gt_err;
        }
    }

    size_t pt_size = in_len - IV_SIZE - TAG_SIZE;  /* plaintext size */
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
    uint8_t tag[TAG_SIZE];
    gt_err = gnutls_cipher_tag(ctx, tag, TAG_SIZE);
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls error: authentication tag");
        return gt_err;
    }
    if (memcmp(ptr, tag, TAG_SIZE)) {
        traceEvent(TRACE_WARNING, "gnutls error: packet auth failed");
        /* make sure no information is returned */
        memset(ptr - pt_size, 0, pt_size);
        return GNUTLS_E_MAC_VERIFY_FAILED;
    }
    return (int) pt_size;
}
