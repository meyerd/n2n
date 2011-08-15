#include "crypto.h"
#include "hmac.h"

#define MASTER_KEY_SIZE 48
#define HMAC_SIZE 48

gnutls_datum_t *master_key_p2p;
gnutls_datum_t *master_key_snode;

/* set symmetric master key; use snode = 1 for supernode or snode = 0 for p2p
 * key
 */
int hmac_set_key(void *key, size_t len, uint8_t snode)
{
    CHECK_CRYPTO();
    gnutls_datum_t *mkey;
    if (snode) {
        mkey = master_key_snode;
    } else {
        mkey = master_key_p2p;
    }
    if (mkey->size > 0 || len != MASTER_KEY_SIZE)
        return GNUTLS_E_APPLICATION_ERROR_MIN;
    mkey->data = gnutls_secure_malloc(len);
    memcpy(mkey->data, key, len);
    mkey->size = len;
    return 0;
}

void hmac_wipe_keys(void)
{
    gnutls_free(master_key_p2p->data);
    gnutls_free(master_key_snode->data);
}

/* Pick a salt, derive special key, authenticate the data. This function
 * writes the salt before the MAC tag itself.
 * Returns negative error code or length of allocated salt + digest value.
 * */
int hmac_auth_tag(void *ad, size_t adlen, uint32_t *spi_from, uint32_t *spi_to,
        void **digest, uint8_t snode)
{
    CHECK_CRYPTO();
    gnutls_datum_t *key;
    void **mac_key = NULL;
    // HMAC tag size is also used as salt size
    int size = HMAC_SIZE * 2;  // salt and MAC tag

    /* find out which symmetric key to use for derivation */
    if (snode) {
        key = master_key_snode;
    } else {
        key = master_key_p2p;
    }
    if (key->size != MASTER_KEY_SIZE)
        return GNUTLS_E_APPLICATION_ERROR_MIN;

    /* create salt */
    *digest = malloc(size);
    GTLS(gnutls_rnd(GNUTLS_RND_RANDOM, *digest, HMAC_SIZE));

    /* derive a salted key from the master key */
    GTLS(derive_key(key->data, key->size, spi_from, spi_to, *digest, HMAC_SIZE,
            "N2N HMAC-SHA384 authentication key", 34, NULL, 0, mac_key,
            HMAC_SIZE));

    /* compute mac over authentication data */
    GTLS(gnutls_hmac_fast(GNUTLS_MAC_SHA384, *mac_key, HMAC_SIZE, ad, adlen,
            (uint8_t *) *digest + HMAC_SIZE));
    gnutls_free(*mac_key);
    return size;
}
//TODO make sure to free() digest

/* Returns size of successfully authenticated data or a negative error code.
 */
int hmac_auth_verify(void *ad, size_t adlen, uint32_t *spi_from,
        uint32_t *spi_to, void *salt, uint8_t snode, void *digest)
{
    CHECK_CRYPTO();
    gnutls_datum_t *key;
    void **mac_key = NULL;
    uint8_t computed_digest[HMAC_SIZE];

    /* find out which symmetric key to use for derivation */
    if (snode) {
        key = master_key_snode;
    } else {
        key = master_key_p2p;
    }
    if (key->size != MASTER_KEY_SIZE)
        return GNUTLS_E_APPLICATION_ERROR_MIN;

    /* derive a salted key from the master key; salt size = HMAC tag size */
    GTLS(derive_key(key->data, key->size, spi_from, spi_to, salt, HMAC_SIZE,
            "N2N HMAC-SHA384 authentication key", 34, NULL, 0, mac_key,
            HMAC_SIZE));

    GTLS(gnutls_hmac_fast(GNUTLS_MAC_SHA384, *mac_key, HMAC_SIZE, ad, adlen,
            computed_digest));
    gnutls_free(*mac_key);

    if (memcmp(computed_digest, digest, HMAC_SIZE)) {
        return GNUTLS_E_APPLICATION_ERROR_MAX;
    } else {
        return adlen;
    }
}
