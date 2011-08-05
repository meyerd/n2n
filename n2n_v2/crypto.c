#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gcrypt.h>
#include "n2n.h"
#include "crypto.h"

#define GCRYPT_NO_DEPRECATED
#define KEY_SIZE 32
#define IV_SIZE 12

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
int aes_gcm_session_create(gnutls_datum_t *key, void *ctx)
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
    ctx = (gnutls_cipher_hd_t *) gnutls_malloc(sizeof(gnutls_cipher_hd_t));
    gt_err = gnutls_cipher_init(ctx, cipher, key, iv);
    if (gt_err != GNUTLS_E_SUCCESS) {
        traceEvent(TRACE_ERROR, "gnutls error: cipher init");
        return gt_err;
    }
    return 0;
}


/* free an encryption handle */
void aes_gcm_session_destroy(gnutls_datum_t *key, void *ctx)
{
    /* overwrite key */
    if (key != NULL) {
        memset(key->data, 0, key->size);
        gnutls_free(key->data);
        gnutls_free(key);
        key = NULL;
    }
    gnutls_cipher_deinit(ctx);
}


/* for testing purposes */
void *aes_gcm_dummy_key(void)
{
    gnutls_datum_t *key = gnutls_malloc(sizeof(gnutls_datum_t));
    key->data = gnutls_malloc(KEY_SIZE);
    key->size = KEY_SIZE;
    return key;
}
