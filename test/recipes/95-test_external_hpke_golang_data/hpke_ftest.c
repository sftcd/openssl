#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hpke.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define MAX_PUBKEY 2048
#define MAX_ENC 2048
#define MAX_CT 4096
#define MAX_PT 4096
#define MAX_AAD 256
#define MAX_IKM 256

typedef struct {
    const char *flag;
    const char *name;
    OSSL_HPKE_SUITE suite;
    size_t ikmlen;
} suite_entry;

static const suite_entry suites[] = {
    {"x25519", "X25519", { OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }, 0},
    {"p256", "P-256", { OSSL_HPKE_KEM_ID_P256, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }, 0},
    {"mlkem512", "ML-KEM-512", { OSSL_HPKE_KEM_ID_ML_KEM_512, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }, 0},
    {"mlkem768", "ML-KEM-768", { OSSL_HPKE_KEM_ID_ML_KEM_768, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }, 0},
    {"mlkem1024", "ML-KEM-1024", { OSSL_HPKE_KEM_ID_ML_KEM_1024, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }, 0},
    {"xwing", "XWING (MLKEM768+X25519)", { OSSL_HPKE_KEM_ID_XWING, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }, 64},
    {"mlkem768p256", "MLKEM768-P256", { OSSL_HPKE_KEM_ID_MLKEM768_P256, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }, 128},
    {"mlkem1024p384", "MLKEM1024-P384", { OSSL_HPKE_KEM_ID_MLKEM1024_P384, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }, 80},
    {NULL, NULL, { 0, 0, 0 }, 0}
};

static const suite_entry *find_suite(const char *flag)
{
    for (int i = 0; suites[i].flag != NULL; i++)
        if (strcmp(suites[i].flag, flag) == 0)
            return &suites[i];
    return NULL;
}

static const unsigned char INFO[] = "hpke-interop-test";
#define INFO_LEN (sizeof(INFO) - 1)

static const unsigned char C_PLAINTEXT[] = "Hello from OpenSSL HPKE!!!!!!";

static void make_aad(const char *name, char *buf, size_t buflen, size_t *outlen)
{
    *outlen = (size_t)snprintf(buf, buflen, "hpke-interop-test %s kdf=HKDF-SHA256 aead=AES-128-GCM", name);
}

static void ssl_err(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    ERR_print_errors_fp(stderr);
}

static int read_file(const char *path, unsigned char *buf, size_t *len, size_t maxlen)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 0; }
    *len = fread(buf, 1, maxlen, f);
    fclose(f);
    return (*len > 0);
}

static int write_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return 0; }
    int ok = (fwrite(buf, 1, len, f) == len);
    fclose(f);
    return ok;
}

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t show = len > 8 ? 8 : len;
    printf("%-18s (%4zu bytes): ", label, len);
    for (size_t i = 0; i < show; i++) printf("%02x", buf[i]);
    if (len > 8) printf("...");
    printf("\n");
}

static int save_privkey(const char *path, EVP_PKEY *pkey, const unsigned char *ikm, size_t ikmlen)
{
    if (ikmlen > 0)
        return write_file(path, ikm, ikmlen);
    unsigned char *der = NULL;
    int derlen = i2d_PrivateKey(pkey, &der);
    if (derlen <= 0) { ssl_err("i2d_PrivateKey failed"); return 0; }
    int ok = write_file(path, der, (size_t)derlen);
    OPENSSL_free(der);
    return ok;
}

static EVP_PKEY *load_privkey(const char *path, const suite_entry *s)
{
    unsigned char buf[8192];
    size_t len;
    if (!read_file(path, buf, &len, sizeof(buf))) return NULL;
    if (s->ikmlen > 0) {
        unsigned char pub[MAX_PUBKEY];
        size_t publen = sizeof(pub);
        EVP_PKEY *priv = NULL;
        if (!OSSL_HPKE_keygen(s->suite, pub, &publen, &priv, buf, len, NULL, NULL)) {
            ssl_err("OSSL_HPKE_keygen (from IKM) failed");
            return NULL;
        }
        return priv;
    }
    const unsigned char *p = buf;
    EVP_PKEY *pkey = d2i_PrivateKey(EVP_PKEY_NONE, NULL, &p, (long)len);
    if (!pkey) ssl_err("d2i_PrivateKey failed");
    return pkey;
}

static int do_keygen(const suite_entry *s)
{
    EVP_PKEY *priv = NULL;
    unsigned char pub[MAX_PUBKEY];
    size_t publen = sizeof(pub);
    unsigned char ikm[MAX_IKM];
    size_t ikmlen = s->ikmlen;
    int ok = 0;

    printf("keygen: suite = %s\n", s->name);

    if (ikmlen > 0) {
        if (!RAND_bytes(ikm, (int)ikmlen)) { ssl_err("RAND_bytes failed"); goto done; }
        if (!OSSL_HPKE_keygen(s->suite, pub, &publen, &priv, ikm, ikmlen, NULL, NULL)) {
            ssl_err("OSSL_HPKE_keygen failed"); goto done;
        }
    } else {
        if (!OSSL_HPKE_keygen(s->suite, pub, &publen, &priv, NULL, 0, NULL, NULL)) {
            ssl_err("OSSL_HPKE_keygen failed"); goto done;
        }
    }

    if (!write_file("c_recipient.pub", pub, publen)) goto done;
    if (!save_privkey("c_recipient.priv", priv, ikm, ikmlen)) goto done;

    print_hex("public key", pub, publen);
    printf("c_recipient.pub (%zu bytes)\n", publen);
    printf("c_recipient.priv (%zu bytes)\n", ikmlen > 0 ? ikmlen : (size_t)0);
    ok = 1;

done:
    EVP_PKEY_free(priv);
    return ok;
}

static int do_encrypt(const suite_entry *s)
{
    unsigned char pub[MAX_PUBKEY];
    size_t publen;
    unsigned char enc[MAX_ENC];
    size_t enclen = OSSL_HPKE_get_public_encap_size(s->suite);
    unsigned char ct[MAX_CT];
    size_t ctlen = OSSL_HPKE_get_ciphertext_size(s->suite, sizeof(C_PLAINTEXT) - 1);
    char aad[MAX_AAD];
    size_t aadlen;
    OSSL_HPKE_CTX *sctx = NULL;
    int ok = 0;

    make_aad(s->name, aad, sizeof(aad), &aadlen);
    printf("encrypt: suite = %s\n", s->name);

    if (!read_file("go_recipient.pub", pub, &publen, sizeof(pub))) goto done;

    sctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, s->suite, OSSL_HPKE_ROLE_SENDER, NULL, NULL);
    if (!sctx) { ssl_err("OSSL_HPKE_CTX_new failed"); goto done; }

    if (!OSSL_HPKE_encap(sctx, enc, &enclen, pub, publen, INFO, INFO_LEN)) {
        ssl_err("OSSL_HPKE_encap failed"); goto done;
    }
    if (!OSSL_HPKE_seal(sctx, ct, &ctlen, (unsigned char *)aad, aadlen, C_PLAINTEXT, sizeof(C_PLAINTEXT) - 1)) {
        ssl_err("OSSL_HPKE_seal failed"); goto done;
    }

    if (!write_file("go_enc.bin", enc, enclen)) goto done;
    if (!write_file("go_ct.bin", ct, ctlen)) goto done;

    print_hex("enc", enc, enclen);
    print_hex("ct", ct, ctlen);
    ok = 1;

done:
    OSSL_HPKE_CTX_free(sctx);
    return ok;
}

static int do_decrypt(const suite_entry *s)
{
    unsigned char enc[MAX_ENC], ct[MAX_CT], pt[MAX_PT];
    size_t enclen, ctlen, ptlen = sizeof(pt);
    char aad[MAX_AAD];
    size_t aadlen;
    EVP_PKEY *recippriv = NULL;
    OSSL_HPKE_CTX *rctx = NULL;
    int ok = 0;

    make_aad(s->name, aad, sizeof(aad), &aadlen);
    printf("decrypt: suite = %s\n", s->name);

    recippriv = load_privkey("c_recipient.priv", s);
    if (!recippriv) goto done;

    if (!read_file("c_enc.bin", enc, &enclen, sizeof(enc))) goto done;
    if (!read_file("c_ct.bin", ct, &ctlen, sizeof(ct))) goto done;

    rctx = OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, s->suite, OSSL_HPKE_ROLE_RECEIVER, NULL, NULL);
    if (!rctx) { ssl_err("OSSL_HPKE_CTX_new failed"); goto done; }

    if (!OSSL_HPKE_decap(rctx, enc, enclen, recippriv, INFO, INFO_LEN)) {
        ssl_err("OSSL_HPKE_decap failed"); goto done;
    }
    if (!OSSL_HPKE_open(rctx, pt, &ptlen, (unsigned char *)aad, aadlen, ct, ctlen)) {
        ssl_err("OSSL_HPKE_open failed"); goto done;
    }

    pt[ptlen] = '\0';
    print_hex("enc", enc, enclen);
    print_hex("ct", ct, ctlen);
    printf("plaintext = \"%s\"\n", pt);
    printf("decrypt: success\n");
    ok = 1;

done:
    OSSL_HPKE_CTX_free(rctx);
    EVP_PKEY_free(recippriv);
    return ok;
}

int main(int argc, char *argv[])
{
    const char *suite_flag = "x25519";
    int i = 1;

    if (argc <= 1) {
        fprintf(stderr, "Usage: %s [-suite <suite>] keygen|encrypt|decrypt\n", argv[0]);
        exit(1);
    }

    if (strcmp(argv[i], "-suite") == 0) {
        suite_flag = argv[i + 1];
        i += 2;
    }

    const suite_entry *s = find_suite(suite_flag);

    const char *cmd = argv[i];
    int ok;
    if (strcmp(cmd, "keygen") == 0) ok = do_keygen(s);
    else if (strcmp(cmd, "encrypt") == 0) ok = do_encrypt(s);
    else if (strcmp(cmd, "decrypt") == 0) ok = do_decrypt(s);
    else { fprintf(stderr, "error: unknown command: %s\n", cmd); return 1; }

    return ok ? 0 : 1;
}
