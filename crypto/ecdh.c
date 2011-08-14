#include <gcrypt.h>

#include "crypto.h"
#include "ecdh.h"

// TODO compute test vector

/* generate an ephemeral ecc key pair */
int ecdh_init(void **keypair)
{
    CHECK_CRYPTO();
    /* don't just change the curve, it might have other implications */
    gcry_sexp_t key_parms;
    GCRY(gcry_sexp_build(&key_parms, NULL, "(genkey (ecdh (curve \"NIST P-384\")))"));

    GCRY(gcry_pk_genkey(*keypair, key_parms));

    gcry_sexp_release(key_parms);
    return 0;
}

/* Export an ephemeral public key for ECDH. Send this over the wire immediately
 * after export and free() it. Returns a negative error code or the length of
 * the public key.
 */
int ecdh_export(void *keypair, void **ephemeral_public_key)
{
    CHECK_CRYPTO();
    gcry_sexp_t pubkey;
    gcry_sexp_t sexp_q;
    gcry_mpi_t mpi_q;
    size_t n;
    keypair = (gcry_sexp_t *) keypair;

    /* extract public key represented by point Q */
    pubkey = gcry_sexp_find_token(keypair, "public-key", 0);
    sexp_q = gcry_sexp_find_token(pubkey, "q", 0);

    /* convert it to mpi for export */
    mpi_q = gcry_sexp_nth_mpi(sexp_q, 1, GCRYMPI_FMT_USG);

    n = (mpi_get_nbits(mpi_q) + 7) / 8;
    *ephemeral_public_key = malloc(n);

    GCRY(gcry_mpi_print(GCRYMPI_FMT_USG, *ephemeral_public_key, n, &n, mpi_q));

    gcry_sexp_release(pubkey);
    gcry_sexp_release(sexp_q);
    gcry_mpi_release(mpi_q);
    return n;
}

static void printhex(void *h, int len)
{
    int i;
    unsigned char *val = (unsigned char *) h;
    printf("hex value:\n");
    for (i = 0; i < len; i++)
        printf("%02X", val[i]);
    printf("\n");
}

/* Extract the x coordinate (= shared secret) of the shared point. This closely
 * follows the gnupg and gcrypt ecc code.
 * Returns a negative error code or the size of the shared secret.
 */
static int extract_x(gcry_mpi_t *shared_point, void **shared_secret)
{
    CHECK_CRYPTO();
    size_t mpi_size;
    size_t x_size;
    unsigned char *buf;

    /* size of a point with two coordinates */
    mpi_size = (gcry_mpi_get_nbits(*shared_point) + 7) / 8;

    /* get shared point */
    buf = gnutls_secure_malloc(mpi_size);
    GCRY(gcry_mpi_print(GCRYMPI_FMT_USG, buf, mpi_size, &mpi_size,
                *shared_point));

    /* size of one coordinate */
    x_size = (mpi_size - 1) / 2;

    /* cut off first byte and throw away tail with y component */
    *shared_secret = gnutls_secure_malloc(x_size);
    memcpy(*shared_secret, buf + 1, x_size);

    /* zeroize buffer with shared secret point */
    memset(buf, 0, mpi_size);
    gnutls_free(buf);
    return x_size;
}


//TODO gnutls_free(shared secret)
/* Return a negative error code or the size of the shared secret
 */
int ecdh_receive_deinit(void **keypair, void *epubkey, void **shared_secret)
{
    CHECK_CRYPTO();
    gcry_sexp_t pubkey;
    gcry_sexp_t privkey;
    gcry_sexp_t sexp_d;
    gcry_mpi_t mpi_d;
    gcry_sexp_t plain;
    gcry_sexp_t enc;
    gcry_sexp_t sexp_s;
    gcry_mpi_t mpi_s;
    int sslen;
    size_t n;

    /* build public key */
    GCRY(gcry_sexp_build(&pubkey, 0, "(public-key (ecdh (q %m) (curve \"NIST P-384\")))", *(gcry_mpi_t *) epubkey));

    /* extract private scalar d */
    privkey = gcry_sexp_find_token(**(gcry_sexp_t **) keypair, "private-key", 0);
    sexp_d = gcry_sexp_find_token(privkey, "private-key", 0);
    mpi_d = gcry_sexp_nth_mpi(sexp_d, 1, GCRYMPI_FMT_USG);

    /* prepare d for computation */
    GCRY(gcry_sexp_build(&plain, 0, "(data (value %m))", mpi_d));

    /* encrypt our private key d with the other party's public key */
    GCRY(gcry_pk_encrypt(&enc, plain, pubkey));

    /* extract shared point s */
    sexp_s = gcry_sexp_find_token(enc, "s", 0 );
    mpi_s = gcry_sexp_nth_mpi(sexp_s, 1, GCRYMPI_FMT_USG);

    /* extract x coordinate of point: this is our shared secret */
    n = (((gcry_mpi_get_nbits(mpi_s) + 7) / 8) - 1) / 2;
    *shared_secret = gnutls_secure_malloc(n);
    sslen = extract_x(&mpi_s, shared_secret);
    if (sslen < 0)
        return GPG_ERR_GENERAL;

    //TODO remove debug
    printf("shared secret:");
    printhex(*shared_secret, sslen);

    gcry_sexp_release(pubkey);
    gcry_sexp_release(privkey);
    gcry_sexp_release(sexp_d);
    gcry_mpi_release(mpi_d);
    gcry_sexp_release(plain);
    gcry_sexp_release(enc);
    gcry_sexp_release(sexp_s);
    gcry_mpi_release(mpi_s);
    gcry_sexp_release(**(gcry_sexp_t **) keypair);
    return sslen;
}
