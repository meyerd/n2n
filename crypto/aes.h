#define AEAD_KEY_SIZE 16  // TODO remove
#define AEAD_IV_SIZE 12
#define AEAD_TAG_SIZE 16

int aes_gcm_session_create(gnutls_datum_t *key, gnutls_cipher_hd_t **ctx);
void aes_gcm_session_destroy(gnutls_cipher_hd_t *ctx);

int aes_gcm_authenc(gnutls_cipher_hd_t ctx, uint8_t *pt, size_t pt_len,
        uint8_t *out, size_t out_len, uint8_t *ad, size_t ad_len);
int aes_gcm_authdec(gnutls_cipher_hd_t ctx, uint8_t *in, size_t in_len,
        uint8_t *out, size_t out_len, uint8_t *ad, size_t ad_len);

void *aes_gcm_dummy_key(void);

