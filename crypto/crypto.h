#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "../n2n.h"


int crypto_init(void);
int crypto_is_initialized(void);
void crypto_deinit(void);

int crypto_set_key_p2p(void *key, size_t len);
int crypto_set_key_snode(void *key, size_t len);

int crypto_rnd(void **rnd, size_t len);


/* internal stuff */

int derive_key(const void *ss, size_t sslen,
        uint32_t *from_spi, uint32_t *to_spi,
        const void *salt, size_t saltlen,
        const char *algoid, size_t algoidlen,
        const void *other_ss, size_t other_sslen,
        void **derived, size_t derivedlen);

#define GCRY(x) { gcry_error_t ret = (x); if (ret) { traceEvent(TRACE_ERROR, "gcrypt error %d:%s in %s on line %d\n", gcry_err_code(ret), gcry_strerror(ret), gcry_strsource(ret), __LINE__ ); return ret; } }

#define GTLS(x) { int ret = (x) ; if (ret) { traceEvent(TRACE_ERROR, "gnutls error %s (code %d): %s", gnutls_strerror_name(ret), ret, gnutls_strerror(ret)); return ret; } }

#define CHECK_CRYPTO() { if (crypto_is_initialized() == 0) { return GNUTLS_E_APPLICATION_ERROR_MIN; } }
