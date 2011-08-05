#include <gnutls/crypto.h>

int crypto_init(void);
void crypto_deinit(void);
int aes_gcm_session_create(gnutls_datum_t *key, void *ctx);
void aes_gcm_session_destroy(gnutls_datum_t *key, void *ctx);
void *aes_gcm_dummy_key(void);
