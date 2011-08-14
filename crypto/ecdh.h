int ecdh_init(void **keypair);
int ecdh_export(void *keypair, void **ephemeral_public_key);
int ecdh_receive_deinit(void **keypair, void *epubkey, void **shared_secret);
