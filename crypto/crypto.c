#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gcrypt.h>
#include "../n2n.h"
#include "crypto.h"
#include "aes.h"
#include "hmac.h"

#define GCRYPT_NO_DEPRECATED
#define DERIV_HASH_SIZE 48

int CRYPTO_INITIALIZED = 0;

/* initialize global values for the cryptographic engine */
int crypto_init(void)
{
    /* initialize libgcrypt */
    //TODO remove debug
    //gcry_control(GCRYCTL_SET_VERBOSITY, 9, 0);
    //gcry_control(GCRYCTL_SET_DEBUG_FLAGS, 0x03);
    if (!gcry_check_version(GCRYPT_VERSION)) {
        traceEvent(TRACE_ERROR, "gcrypt init error");
        return -1;
    }

    /* Allocate a pool of 16k secure memory.  This make the secure memory
     * available and also drops privileges where needed.
     */
    GCRY(gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0));

    /* Tell Libgcrypt that initialization has completed. */
    GCRY(gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0));

    /* Import secure memory handling functions from libgcrypt into gnutls,
     * since gnutls doesn't have any.
     */
    gnutls_global_set_mem_functions(gcry_malloc, gcry_malloc_secure,
            gcry_is_secure, gcry_realloc, gcry_free);

    /* initialize gnutls engine */
    GTLS(gnutls_global_init());

    CRYPTO_INITIALIZED = 1;
    return 0;
}

/* free gnutls structures */
void crypto_deinit(void)
{
    CRYPTO_INITIALIZED = 0;
    /* wipe the keys */
    hmac_wipe_keys();
    gnutls_global_deinit();
}

/* check the state of the crypto engine */
int crypto_is_initialized(void)
{
    return CRYPTO_INITIALIZED;
}

/* usage for AES session keys:
 * derive_key(*dh_ss, dh_sslen, *from_spi, *to_spi, *salt_a, saltlen,
 *         "N2N AES-GCM 256 session key", algoidlen,
 *         NULL, 0, **sesskey_a, 32)
 *
 * usage for HMAC authentication keys:
 * derive_key(*masterkey, masterkeylen, *from_spi, *to_spi, *salt_a, saltlen,
 *         "N2N HMAC-SHA384 authentication key", algoidlen,
 *         NULL, 0, **hmackey_a, 48)
 */
/* NIST concatenation key derivation function as in NIST SP 800-56A */
int derive_key(const void *ss, size_t sslen,
        uint32_t *from_spi, uint32_t *to_spi,
        const void *salt, size_t saltlen,
        const char *algoid, size_t algoidlen,
        const void *other_ss, size_t other_sslen,
        void **derived, size_t derivedlen)
{
    CHECK_CRYPTO();
    /* salt and ss should have a length of at least the digest size */
    if (saltlen < DERIV_HASH_SIZE || sslen < DERIV_HASH_SIZE)
        return 2;
    /* currently not supported, but could be done by completely implementing
     * the kdf
     */
    if (derivedlen > DERIV_HASH_SIZE)
        return 3;

    uint8_t *input;  // the text input buffer to the hash function
    void *keymat;
    size_t ptr = 0;
    uint32_t counter = 1;
    size_t counterlen = sizeof(uint32_t);
    size_t spilen = sizeof(uint32_t);

    size_t inputlen = counterlen + sslen;
    inputlen += algoidlen + (2 * spilen) + saltlen + other_sslen;

    input = gnutls_secure_malloc(inputlen);

    /* hash(counter || shared_secret || otherinfo) */
    counter = htonl(counter);  // must be big endian
    memcpy(input + ptr, &counter, counterlen);
    ptr += counterlen;
    memcpy(input + ptr, ss, sslen);
    ptr += sslen;

    /* otherinfo = algoid || partyu || partyv || suppubinfo || supprivinfo */
    memcpy(input + ptr, algoid, algoidlen);
    ptr += algoidlen;
    memcpy(input + ptr, from_spi, spilen);
    ptr += spilen;
    memcpy(input + ptr, to_spi, spilen);
    ptr += spilen;
    memcpy(input + ptr, salt, saltlen);
    ptr += saltlen;
    memcpy(input + ptr, other_ss, other_sslen);

    keymat = gnutls_secure_malloc(DERIV_HASH_SIZE);
    GTLS(gnutls_hash_fast(GNUTLS_DIG_SHA384, input, inputlen, keymat));
    gnutls_free(input);

    *derived = gnutls_secure_malloc(DERIV_HASH_SIZE);
    memcpy(*derived, keymat, AEAD_KEY_SIZE);
    gnutls_free(keymat);
    return 0;
}

/* derive a session key from the shared secret 'ss' as source_key and the salt
 * using a HMAC based key derivation function (RFC 5869):
 * HKDF(salt, source_key, infostring, outlen) = K1 | K2 | ... | Kt
 *     prk = HMAC(salt, source_key)
 *     K1 = HMAC(prk, infostring | 0x01)
 *     K2 = HMAC(prk, K1 | infostring | 0x02)
 *     K3 = HMAC(prk, K2 | infostring | 0x03) ...
 * This function could be used instead of the concatenation function. For the
 * sake of Suite B compliance we will stick with concatenation for now.
 */
static int derive_key_rfc5869(const void **salt, size_t saltlen,
        const void **ss, size_t sslen, void **derived, size_t derivedlen)
{
    CHECK_CRYPTO();
    /* salt and ss should have a length of at least the digest size */
    if (saltlen < DERIV_HASH_SIZE || sslen < DERIV_HASH_SIZE)
        return 2;
    /* currently not supported, but could be done by completely implementing
     * rfc 5869
     */
    if (derivedlen > DERIV_HASH_SIZE)
        return 3;

    /* data is optional and may be constant */
    int datalen = 29;
    char data[] = "n2n edge aes-gcm session key ";
    data[datalen - 1] = (uint8_t) 0x01;

    uint8_t *prk;
    uint8_t *okm;
    prk = gnutls_secure_malloc(DERIV_HASH_SIZE); // pseudorandom key
    okm = gnutls_secure_malloc(DERIV_HASH_SIZE); // output key material
    derived = gnutls_secure_malloc(derivedlen);

    /* the salt is used as the key, the shared secret is used as data */
    GTLS(gnutls_hmac_fast(GNUTLS_MAC_SHA384, *salt, saltlen, *ss, sslen, prk));

    GTLS(gnutls_hmac_fast(GNUTLS_MAC_SHA384, prk, DERIV_HASH_SIZE, data,
                datalen, okm));

    memcpy(*derived, okm, derivedlen);
    gnutls_free(prk);
    gnutls_free(okm);
    return 0;
}

//TODO make sure this is dealloc'd correctly
/* Generate a random number in secure memory. Use this for SPI generation.
 * This will drain the entropy pool, use with care.
 */
int crypto_rnd(void **rnd, size_t len)
{
    CHECK_CRYPTO();

    *rnd = gnutls_secure_malloc(len);
    GTLS(gnutls_rnd(GNUTLS_RND_RANDOM, *rnd, len));
    return 0;
}
