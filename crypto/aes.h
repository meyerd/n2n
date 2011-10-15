#define AEAD_IV_SIZE 12
#define AEAD_TAG_SIZE 16

/* security association: never ever manipulate this outside of aes.c */
typedef struct {
    uint32_t *salt;
    uint64_t *counter;
    gnutls_cipher_hd_t ctx;
} sa_t;

int aes_sa_create(sa_t *sa, void *sk, int sklen);
void aes_sa_destroy(sa_t *sa);
int aes_authenc(sa_t *sa, void *pt, size_t pt_len, void *ad, size_t ad_len,
        void *out, size_t out_len);
int aes_authdec(sa_t *sa, void *in, size_t in_len, void *ad, size_t ad_len,
        void *out, size_t out_len);
