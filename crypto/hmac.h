
int hmac_set_key(void *key, size_t len, uint8_t snode);
void hmac_wipe_keys(void);
int hmac_auth_tag(void *ad, size_t adlen, uint32_t *spi_from, uint32_t *spi_to,
        void **digest, uint8_t snode);
int hmac_auth_verify(void *ad, size_t adlen, uint32_t *spi_from,
        uint32_t *spi_to, void *salt, uint8_t snode, void *digest);
