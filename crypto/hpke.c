/*
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file
 * An OpenSSL-based HPKE implementation of RFC9180
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <internal/common.h>
#include <openssl/hpke.h>
#include <openssl/err.h>

/* constants defined in RFC9180 */
#define OSSL_HPKE_VERLABEL        "HPKE-v1"  /**< version string label */
#define OSSL_HPKE_SEC41LABEL      "KEM"      /**< "suite_id" label for 4.1 */
#define OSSL_HPKE_SEC51LABEL      "HPKE"     /**< "suite_id" label for 5.1 */
#define OSSL_HPKE_EAE_PRK_LABEL   "eae_prk"  /**< label in ExtractAndExpand */
#define OSSL_HPKE_PSKIDHASH_LABEL "psk_id_hash" /**< in key_schedule_context */
#define OSSL_HPKE_INFOHASH_LABEL  "info_hash"   /**< in key_schedule_context */
#define OSSL_HPKE_SS_LABEL        "shared_secret" /**< Yet another label */
#define OSSL_HPKE_NONCE_LABEL     "base_nonce"  /**< guess? */
#define OSSL_HPKE_EXP_LABEL       "exp" /**< guess again? */
#define OSSL_HPKE_KEY_LABEL       "key" /**< guess again? */
#define OSSL_HPKE_PSK_HASH_LABEL  "psk_hash" /**< guess again? */
#define OSSL_HPKE_SECRET_LABEL    "secret" /**< guess again? */
#define OSSL_HPKE_DPK_LABEL       "dkp_prk" /**< DeriveKeyPair label */
#define OSSL_HPKE_CAND_LABEL      "candidate" /**< sk label */
#define OSSL_HPKE_SK_LABEL        "sk" /**< sk label */

/* different RFC5869 "modes" used in RFC9180 */
#define OSSL_HPKE_5869_MODE_PURE   0 /**< Do "pure" RFC5869 */
#define OSSL_HPKE_5869_MODE_KEM    1 /**< Abide by HPKE section 4.1 */
#define OSSL_HPKE_5869_MODE_FULL   2 /**< Abide by HPKE section 5.1 */

/* An internal max size, based on the extenal */
#define INT_MAXSIZE (4 * OSSL_HPKE_MAXSIZE)

/*
 * PEM header/footer for private keys
 * PEM_STRING_PKCS8INF is just: "PRIVATE KEY"
 */
#define PEM_PRIVATEHEADER "-----BEGIN "PEM_STRING_PKCS8INF"-----\n"
#define PEM_PRIVATEFOOTER "\n-----END "PEM_STRING_PKCS8INF"-----\n"

/* max string len we'll try map to a suite */
#define OSSL_HPKE_MAX_SUITESTR 38

/* "strength" input to RAND_bytes_ex */
#define OSSL_HPKE_RSTRENGTH 10

#define OSSL_HPKE_err \
    { \
        if (erv == 1) { erv = - __LINE__; } \
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR); \
    }
/* an error macro just to make things easier */

/*
 * @brief info about an AEAD
 */
typedef struct {
    uint16_t            aead_id; /**< code point for aead alg */
    const char *        name;   /* alg name */
    size_t              taglen; /**< aead tag len */
    size_t              Nk; /**< size of a key for this aead */
    size_t              Nn; /**< length of a nonce for this aead */
} hpke_aead_info_t;

/*
 * @brief table of AEADs
 */
static hpke_aead_info_t hpke_aead_tab[] = {
    { 0, NULL, 0, 0, 0 }, /* treat 0 as error so nothing here */
    { OSSL_HPKE_AEAD_ID_AES_GCM_128, LN_aes_128_gcm, 16, 16, 12 },
    { OSSL_HPKE_AEAD_ID_AES_GCM_256, LN_aes_256_gcm, 16, 32, 12 },
#ifndef OPENSSL_NO_CHACHA20
# ifndef OPENSSL_NO_POLY1305
    { OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, LN_chacha20_poly1305, 16, 32, 12 }
# endif
#endif
};

/*
 * @brief info about a KEM
 */
typedef struct {
    uint16_t       kem_id; /**< code point for key encipherment method */
    const char     *keytype; /**< string form of algtype "EC"/"X25519"/"X448" */
    const char     *groupname; /**< string form of EC group for NIST curves  */
    int            groupid; /**< NID of KEM */
    const char     *mdname; /**< hash alg name for the HKDF */
    size_t         Nsecret; /**< size of secrets */
    size_t         Nenc; /**< length of encapsulated key */
    size_t         Npk; /**< length of public key */
    size_t         Npriv; /**< length of raw private key */
} hpke_kem_info_t;

/*
 * @brief table of KEMs
 */
static hpke_kem_info_t hpke_kem_tab[] = {
    { 0, NULL, NULL, 0, NULL, 0, 0, 0 }, /* treat 0 as error so nowt here */
    { OSSL_HPKE_KEM_ID_P256, "EC", OSSL_HPKE_KEMSTR_P256, NID_X9_62_prime256v1,
      LN_sha256, 32, 65, 65, 32 },
    { OSSL_HPKE_KEM_ID_P384, "EC", OSSL_HPKE_KEMSTR_P384, NID_secp384r1,
      LN_sha384, 48, 97, 97, 48 },
    { OSSL_HPKE_KEM_ID_P521, "EC", OSSL_HPKE_KEMSTR_P521, NID_secp521r1,
      LN_sha512, 64, 133, 133, 66 },
    { OSSL_HPKE_KEM_ID_25519, OSSL_HPKE_KEMSTR_X25519, NULL, NID_X25519,
      LN_sha256, 32, 32, 32, 32 },
    { OSSL_HPKE_KEM_ID_448, OSSL_HPKE_KEMSTR_X448, NULL, NID_X448,
      LN_sha512, 64, 56, 56, 56 }
};

/*
 * @brief info about a KDF
 */
typedef struct {
    uint16_t       kdf_id; /**< code point for KDF */
    const char     *mdname; /**< hash alg name for the HKDF */
    size_t         Nh; /**< length of hash/extract output */
} hpke_kdf_info_t;

/*
 * @brief table of KDFs
 */
static hpke_kdf_info_t hpke_kdf_tab[] = {
    { 0, NULL, 0 }, /* keep indexing correct */
    { OSSL_HPKE_KDF_ID_HKDF_SHA256, LN_sha256, 32 },
    { OSSL_HPKE_KDF_ID_HKDF_SHA384, LN_sha384, 48 },
    { OSSL_HPKE_KDF_ID_HKDF_SHA512, LN_sha512, 64 }
};

/*
 * @brief map from IANA codepoint to AEAD table index
 *
 * @param codepoint should be an IANA code point
 * @return index in AEAD table or 0 if error
 */
static uint16_t aead_iana2index(uint16_t codepoint)
{
    uint16_t naeads = OSSL_NELEM(hpke_aead_tab);
    uint16_t i = 0;

    for (i = 0; i != naeads; i++) {
        if (hpke_aead_tab[i].aead_id == codepoint) {
            return (i);
        }
    }
    return (0);
}

/*
 * @brief map from IANA codepoint to KEM table index
 *
 * @param codepoint should be an IANA code point
 * @return index in KEM table or 0 if error
 */
static uint16_t kem_iana2index(uint16_t codepoint)
{
    uint16_t nkems = OSSL_NELEM(hpke_kem_tab);
    uint16_t i = 0;

    for (i = 0; i != nkems; i++) {
        if (hpke_kem_tab[i].kem_id == codepoint) {
            return (i);
        }
    }
    return (0);
}

/*
 * @brief map from IANA codepoint to AEAD table index
 *
 * @param codepoint should be an IANA code point
 * @return index in AEAD table or 0 if error
 */
static uint16_t kdf_iana2index(uint16_t codepoint)
{
    uint16_t nkdfs = OSSL_NELEM(hpke_kdf_tab);
    uint16_t i = 0;

    for (i = 0; i != nkdfs; i++) {
        if (hpke_kdf_tab[i].kdf_id == codepoint) {
            return (i);
        }
    }
    return (0);
}

/*
 * @brief Check if kem_id is ok/known to us
 * @param kem_id is the externally supplied kem_id
 * @return 1 for good, not 1 for error
 */
static int hpke_kem_id_check(uint16_t kem_id)
{
    switch (kem_id) {
    case OSSL_HPKE_KEM_ID_P256:
    case OSSL_HPKE_KEM_ID_P384:
    case OSSL_HPKE_KEM_ID_P521:
    case OSSL_HPKE_KEM_ID_25519:
    case OSSL_HPKE_KEM_ID_448:
        break;
    default:
        return (- __LINE__);
    }
    return (1);
}

/*
 * @brief check if KEM uses NIST curve or not
 * @param kem_id is the externally supplied kem_id
 * @return 1 for NIST, 0 for good-but-non-NIST, other otherwise
 */
static int hpke_kem_id_nist_curve(uint16_t kem_id)
{
    if (hpke_kem_id_check(kem_id) != 1)
        return (- __LINE__);
    if (kem_id >= 0x10 && kem_id < 0x20)
        return (1);
    return (0);
}

/*
 * @brief hpke wrapper to import NIST curve public key as easily as x25519/x448
 *
 * @param libctx is the context to use (normally NULL)
 * @param curve is the curve NID
 * @param gname is the curve groupname
 * @param buf is the binary buffer with the (uncompressed) public value
 * @param buflen is the length of the private key buffer
 * @return a working EVP_PKEY * or NULL
 */
static EVP_PKEY * hpke_EVP_PKEY_new_raw_nist_public_key(OSSL_LIB_CTX *libctx,
                                                        int curve,
                                                        const char *gname,
                                                        unsigned char *buf,
                                                        size_t buflen)
{
    int erv = 1;
    EVP_PKEY *ret = NULL;
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);

    if (cctx == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_PKEY_paramgen_init(cctx) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(cctx, curve) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_PKEY_paramgen(cctx, &ret) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_PKEY_set1_encoded_public_key(ret, buf, buflen) != 1) {
        EVP_PKEY_free(ret);
        ret = NULL;
        OSSL_HPKE_err;
        goto err;
    }

err:
    EVP_PKEY_CTX_free(cctx);
    if (erv == 1)
        return (ret);
    else
        return NULL;
}

/*
 * There's an odd accidental coding style feature here:
 * For all the externally visible functions in hpke.h, when
 * passing in a buffer, the length parameter precedes the
 * associated buffer pointer. It turns out that, entirely by
 * accident, I did the exact opposite for all the static
 * functions defined inside here. But since I was consistent
 * in both cases, I'll declare that a feature and move on:-)
 *
 * For example, just below you'll see:
 *          unsigned char *iv, size_t ivlen,
 * ...whereas in hpke.h, you see:
 *          size_t publen, unsigned char *pub,
 */

/*
 * @brief do the AEAD decryption
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param key is the secret
 * @param keylen is the length of the secret
 * @param iv is the initialisation vector
 * @param ivlen is the length of the iv
 * @param aad is the additional authenticated data
 * @param aadlen is the length of the aad
 * @param cipher is obvious
 * @param cipherlen is the ciphertext length
 * @param plain is an output
 * @param plainlen input/output, better be big enough on input, exact on output
 * @return 1 for good otherwise bad
 */
static int hpke_aead_dec(OSSL_LIB_CTX *libctx,
                         ossl_hpke_suite_st  suite,
                         unsigned char *key, size_t keylen,
                         unsigned char *iv, size_t ivlen,
                         unsigned char *aad, size_t aadlen,
                         unsigned char *cipher, size_t cipherlen,
                         unsigned char *plain, size_t *plainlen)
{
    int erv = 1;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    size_t plaintextlen = 0;
    unsigned char *plaintext = NULL;
    size_t taglen;
    uint16_t aead_ind = 0;
    EVP_CIPHER *enc = NULL;

    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    taglen = hpke_aead_tab[aead_ind].taglen;
    plaintext = OPENSSL_malloc(cipherlen);
    if (plaintext == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Create and initialise the context */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Initialise the encryption operation */
    enc = EVP_CIPHER_fetch(libctx, hpke_aead_tab[aead_ind].name, NULL);
    if (enc == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    EVP_CIPHER_free(enc);
    enc = NULL;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Initialise key and IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Provide AAD. Can be called zero or more times as required */
    if (aadlen != 0 && aad != NULL) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            OSSL_HPKE_err;
            goto err;
        }
    }
    /*
     * Provide the message to be decrypted, and obtain cleartext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (EVP_DecryptUpdate(ctx, plaintext, &len, cipher,
                          cipherlen - taglen) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    plaintextlen = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             taglen, cipher + cipherlen - taglen)) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Finalise decryption.  */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (plaintextlen > *plainlen) {
        OSSL_HPKE_err;
        goto err;
    }
    *plainlen = plaintextlen;
    memcpy(plain, plaintext, plaintextlen);

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(enc);
    OPENSSL_free(plaintext);
    return erv;
}

/*
 * @brief do AEAD encryption as per the RFC
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param key is the secret
 * @param keylen is the length of the secret
 * @param iv is the initialisation vector
 * @param ivlen is the length of the iv
 * @param aad is the additional authenticated data
 * @param aadlen is the length of the aad
 * @param plain is an output
 * @param plainlen is the length of plain
 * @param cipher is an output
 * @param cipherlen input/output, better be big enough on input, exact on output
 * @return 1 for good otherwise bad
 */
static int hpke_aead_enc(OSSL_LIB_CTX *libctx,
                         ossl_hpke_suite_st  suite,
                         unsigned char *key, size_t keylen,
                         unsigned char *iv, size_t ivlen,
                         unsigned char *aad, size_t aadlen,
                         unsigned char *plain, size_t plainlen,
                         unsigned char *cipher, size_t *cipherlen)
{
    int erv = 1;
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    size_t ciphertextlen;
    unsigned char *ciphertext = NULL;
    size_t taglen = 0;
    uint16_t aead_ind = 0;
    EVP_CIPHER *enc = NULL;
    unsigned char tag[16];

    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    taglen = hpke_aead_tab[aead_ind].taglen;
    if (taglen != 16) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((taglen + plainlen) > *cipherlen) {
        OSSL_HPKE_err;
        goto err;
    }
    /*
     * Allocate this much extra for ciphertext and check the AEAD
     * doesn't require more - If it does, we'll fail.
     */
    ciphertext = OPENSSL_malloc(plainlen + taglen);
    if (ciphertext == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Initialise the encryption operation. */
    enc = EVP_CIPHER_fetch(libctx, hpke_aead_tab[aead_ind].name, NULL);
    if (enc == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    EVP_CIPHER_free(enc);
    enc = NULL;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Initialise key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aadlen != 0 && aad != NULL) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            OSSL_HPKE_err;
            goto err;
        }
    }
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plainlen) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    ciphertextlen = len;
    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    ciphertextlen += len;
    /*
     * Get the tag This isn't a duplicate so needs to be added to the ciphertext
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    memcpy(ciphertext + ciphertextlen, tag, taglen);
    ciphertextlen += taglen;
    if (ciphertextlen > *cipherlen) {
        OSSL_HPKE_err;
        goto err;
    }
    *cipherlen = ciphertextlen;
    memcpy(cipher, ciphertext, ciphertextlen);

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(enc);
    OPENSSL_free(ciphertext);
    return erv;
}

/*
 * @brief RFC5869 HKDF-Extract
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param mode5869 - controls labelling specifics
 * @param salt - surprisingly this is the salt;-)
 * @param saltlen - length of above
 * @param label - label for separation
 * @param labellen - length of above
 * @param zz - the initial key material (IKM)
 * @param zzlen - length of above
 * @param secret - the result of extraction (allocated inside)
 * @param secretlen - bufsize on input, used size on output
 * @return 1 for good otherwise bad
 *
 * Mode can be:
 * - OSSL_HPKE_5869_MODE_PURE meaning to ignore all the
 *   HPKE-specific labelling and produce an output that's
 *   RFC5869 compliant (useful for testing and maybe
 *   more)
 * - OSSL_HPKE_5869_MODE_KEM meaning to follow section 4.1
 *   where the suite_id is used as:
 *   concat("KEM", I2OSP(kem_id, 2))
 * - OSSL_HPKE_5869_MODE_FULL meaning to follow section 5.1
 *   where the suite_id is used as:
 *     concat("HPKE", I2OSP(kem_id, 2),
 *          I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
 *
 * Isn't that a bit of a mess!
 */
static int hpke_extract(OSSL_LIB_CTX *libctx,
                        const ossl_hpke_suite_st suite, const int mode5869,
                        const unsigned char *salt, const size_t saltlen,
                        const char *label, const size_t labellen,
                        const unsigned char *ikm, const size_t ikmlen,
                        unsigned char *secret, size_t *secretlen)
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;
    int mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;
    const char *mdname = NULL;
    unsigned char labeled_ikmbuf[INT_MAXSIZE];
    unsigned char *labeled_ikm = labeled_ikmbuf;
    size_t labeled_ikmlen = 0;
    int erv = 1;
    size_t concat_offset = 0;
    size_t lsecretlen = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    /* Handle oddities of HPKE labels (or not) */
    switch (mode5869) {

    case OSSL_HPKE_5869_MODE_PURE:
        labeled_ikmlen = ikmlen;
        labeled_ikm = (unsigned char *)ikm;

        break;

    case OSSL_HPKE_5869_MODE_KEM:
        concat_offset = 0;
        memcpy(labeled_ikm, OSSL_HPKE_VERLABEL, strlen(OSSL_HPKE_VERLABEL));
        concat_offset += strlen(OSSL_HPKE_VERLABEL);
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(labeled_ikm + concat_offset,
               OSSL_HPKE_SEC41LABEL, strlen(OSSL_HPKE_SEC41LABEL));
        concat_offset += strlen(OSSL_HPKE_SEC41LABEL);
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikm[concat_offset] = (suite.kem_id / 256) % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikm[concat_offset] = suite.kem_id % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(labeled_ikm + concat_offset, label, labellen);
        concat_offset += labellen;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(labeled_ikm + concat_offset, ikm, ikmlen);
        concat_offset += ikmlen;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikmlen = concat_offset;
        break;

    case OSSL_HPKE_5869_MODE_FULL:
        concat_offset = 0;
        memcpy(labeled_ikm, OSSL_HPKE_VERLABEL, strlen(OSSL_HPKE_VERLABEL));
        concat_offset += strlen(OSSL_HPKE_VERLABEL);
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(labeled_ikm + concat_offset,
               OSSL_HPKE_SEC51LABEL, strlen(OSSL_HPKE_SEC51LABEL));
        concat_offset += strlen(OSSL_HPKE_SEC51LABEL);
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikm[concat_offset] = (suite.kem_id / 256) % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikm[concat_offset] = suite.kem_id % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikm[concat_offset] = (suite.kdf_id / 256) % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikm[concat_offset] = suite.kdf_id % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikm[concat_offset] = (suite.aead_id / 256) % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikm[concat_offset] = suite.aead_id % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(labeled_ikm + concat_offset, label, labellen);
        concat_offset += labellen;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        if (ikmlen > 0) /* added 'cause asan test */
            memcpy(labeled_ikm + concat_offset, ikm, ikmlen);
        concat_offset += ikmlen;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        labeled_ikmlen = concat_offset;
        break;
    default:
        OSSL_HPKE_err;
        goto err;
    }

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(libctx, "hkdf", NULL)) == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); /* The kctx keeps a reference so this is safe */
    kdf = NULL;
    if (kctx == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Build up the parameters for the derivation */
    if (mode5869 == OSSL_HPKE_5869_MODE_KEM) {
        kem_ind = kem_iana2index(suite.kem_id);
        if (kem_ind == 0) {
            OSSL_HPKE_err;
            goto err;
        }
        mdname = hpke_kem_tab[kem_ind].mdname;
    } else {
        kdf_ind = kdf_iana2index(suite.kdf_id);
        if (kdf_ind == 0) {
            OSSL_HPKE_err;
            goto err;
        }
        mdname = hpke_kdf_tab[kdf_ind].mdname;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)mdname, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (unsigned char *)labeled_ikm,
                                             labeled_ikmlen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             (unsigned char *)salt, saltlen);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    lsecretlen = EVP_KDF_CTX_get_kdf_size(kctx);
    if (lsecretlen > *secretlen) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Do the derivation */
    if (EVP_KDF_derive(kctx, secret, lsecretlen, params) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    *secretlen = lsecretlen;

err:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    memset(labeled_ikmbuf, 0, OSSL_HPKE_MAXSIZE);
    return erv;
}

/*
 * @brief RFC5869 HKDF-Expand
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param mode5869 - controls labelling specifics
 * @param prk - the initial pseudo-random key material
 * @param prk - length of above
 * @param label - label to prepend to info
 * @param labellen - label to prepend to info
 * @param context - the info
 * @param contextlen - length of above
 * @param L - the length of the output desired
 * @param out - the result of expansion (allocated by caller)
 * @param outlen - buf size on input
 * @return 1 for good otherwise bad
 */
static int hpke_expand(OSSL_LIB_CTX *libctx,
                       const ossl_hpke_suite_st suite, const int mode5869,
                       const unsigned char *prk, const size_t prklen,
                       const char *label, const size_t labellen,
                       const unsigned char *info, const size_t infolen,
                       const uint32_t L,
                       unsigned char *out, size_t *outlen)
{
    int erv = 1;
    unsigned char libuf[INT_MAXSIZE];
    unsigned char *lip = libuf;
    size_t concat_offset = 0;
    size_t loutlen = L;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;
    int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
    const char *mdname = NULL;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    if (L > *outlen) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Handle oddities of HPKE labels (or not) */
    switch (mode5869) {
    case OSSL_HPKE_5869_MODE_PURE:
        if ((labellen + infolen) >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(lip, label, labellen);
        memcpy(lip + labellen, info, infolen);
        concat_offset = labellen + infolen;
        break;

    case OSSL_HPKE_5869_MODE_KEM:
        lip[0] = (L / 256) % 256;
        lip[1] = L % 256;
        concat_offset = 2;
        memcpy(lip + concat_offset, OSSL_HPKE_VERLABEL,
               strlen(OSSL_HPKE_VERLABEL));
        concat_offset += strlen(OSSL_HPKE_VERLABEL);
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(lip + concat_offset, OSSL_HPKE_SEC41LABEL,
               strlen(OSSL_HPKE_SEC41LABEL));
        concat_offset += strlen(OSSL_HPKE_SEC41LABEL);
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        lip[concat_offset] = (suite.kem_id / 256) % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        lip[concat_offset] = suite.kem_id % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(lip + concat_offset, label, labellen);
        concat_offset += labellen;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(lip + concat_offset, info, infolen);
        concat_offset += infolen;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        break;

    case OSSL_HPKE_5869_MODE_FULL:
        lip[0] = (L / 256) % 256;
        lip[1] = L % 256;
        concat_offset = 2;
        memcpy(lip + concat_offset, OSSL_HPKE_VERLABEL,
               strlen(OSSL_HPKE_VERLABEL));
        concat_offset += strlen(OSSL_HPKE_VERLABEL);
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(lip + concat_offset, OSSL_HPKE_SEC51LABEL,
               strlen(OSSL_HPKE_SEC51LABEL));
        concat_offset += strlen(OSSL_HPKE_SEC51LABEL);
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        lip[concat_offset] = (suite.kem_id / 256) % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        lip[concat_offset] = suite.kem_id % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        lip[concat_offset] = (suite.kdf_id / 256) % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        lip[concat_offset] = suite.kdf_id % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        lip[concat_offset] = (suite.aead_id / 256) % 256;
        concat_offset += 1;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        lip[concat_offset] = suite.aead_id % 256;
        concat_offset += 1;
        memcpy(lip + concat_offset, label, labellen);
        concat_offset += labellen;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(lip + concat_offset, info, infolen);
        concat_offset += infolen;
        if (concat_offset >= INT_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        break;

    default:
        OSSL_HPKE_err;
        goto err;
    }

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(libctx, "hkdf", NULL)) == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); /* The kctx keeps a reference so this is safe */
    kdf = NULL;
    if (kctx == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Build up the parameters for the derivation */
    if (mode5869 == OSSL_HPKE_5869_MODE_KEM) {
        kem_ind = kem_iana2index(suite.kem_id);
        if (kem_ind == 0) {
            OSSL_HPKE_err;
            goto err;
        }
        mdname = hpke_kem_tab[kem_ind].mdname;
    } else {
        kdf_ind = kdf_iana2index(suite.kdf_id);
        if (kdf_ind == 0) {
            OSSL_HPKE_err;
            goto err;
        }
        mdname = hpke_kdf_tab[kdf_ind].mdname;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)mdname, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             (unsigned char *) prk, prklen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                             libuf, concat_offset);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    /* Do the derivation */
    if (EVP_KDF_derive(kctx, out, loutlen, params) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    *outlen = loutlen;

err:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    memset(libuf, 0, OSSL_HPKE_MAXSIZE);
    return erv;
}

/*
 * @brief ExtractAndExpand
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the ciphersuite
 * @param mode5869 - controls labelling specifics
 * @param shared_secret - the initial DH shared secret
 * @param shared_secretlen - length of above
 * @param context - the info
 * @param contextlen - length of above
 * @param secret - the result of extract&expand
 * @param secretlen - buf size on input
 * @return 1 for good otherwise bad
 */
static int hpke_extract_and_expand(OSSL_LIB_CTX *libctx,
                                   ossl_hpke_suite_st suite, int mode5869,
                                   unsigned char *shared_secret,
                                   size_t shared_secretlen,
                                   unsigned char *context, size_t contextlen,
                                   unsigned char *secret, size_t *secretlen)
{
    int erv = 1;
    unsigned char eae_prkbuf[OSSL_HPKE_MAXSIZE];
    size_t eae_prklen = OSSL_HPKE_MAXSIZE;
    size_t lsecretlen = 0;
    uint16_t kem_ind = 0;

    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    lsecretlen = hpke_kem_tab[kem_ind].Nsecret;
    erv = hpke_extract(libctx, suite, mode5869,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_EAE_PRK_LABEL, strlen(OSSL_HPKE_EAE_PRK_LABEL),
                       shared_secret, shared_secretlen,
                       eae_prkbuf, &eae_prklen);
    if (erv != 1) { goto err; }
    erv = hpke_expand(libctx, suite, mode5869,
                      eae_prkbuf, eae_prklen,
                      OSSL_HPKE_SS_LABEL, strlen(OSSL_HPKE_SS_LABEL),
                      context, contextlen,
                      lsecretlen, secret, &lsecretlen);
    if (erv != 1) { goto err; }
    *secretlen = lsecretlen;
err:
    memset(eae_prkbuf, 0, OSSL_HPKE_MAXSIZE);
    return (erv);
}

/*
 * @brief run the KEM with two keys as required
 *
 * @param libctx is the context to use (normally NULL)
 * @param encrypting is 1 if we're encrypting, 0 for decrypting
 * @param suite is the ciphersuite
 * @param key1 is the first key, for which we have the private value
 * @param key1enclen is the length of the encoded form of key1
 * @param key1en is the encoded form of key1
 * @param key2 is the peer's key
 * @param key2enclen is the length of the encoded form of key1
 * @param key2en is the encoded form of key1
 * @param akey is the authentication private key
 * @param apublen is the length of the encoded the authentication public key
 * @param apub is the encoded form of the authentication public key
 * @param ss is (a pointer to) the buffer for the shared secret result
 * @param sslen is the size of the buffer (octets-used on exit)
 * @return 1 for good, not 1 for not good
 */
static int hpke_do_kem(OSSL_LIB_CTX *libctx,
                       int encrypting, ossl_hpke_suite_st suite,
                       EVP_PKEY *key1,
                       size_t key1enclen, unsigned char *key1enc,
                       EVP_PKEY *key2,
                       size_t key2enclen, unsigned char *key2enc,
                       EVP_PKEY *akey,
                       size_t apublen, unsigned char *apub,
                       unsigned char **ss, size_t *sslen)
{
    int erv = 1;
    EVP_PKEY_CTX *pctx = NULL;
    size_t zzlen = 2 * OSSL_HPKE_MAXSIZE;
    unsigned char zz[2 * OSSL_HPKE_MAXSIZE];
    size_t kem_contextlen = OSSL_HPKE_MAXSIZE;
    unsigned char kem_context[OSSL_HPKE_MAXSIZE];
    size_t lsslen = OSSL_HPKE_MAXSIZE;
    unsigned char lss[OSSL_HPKE_MAXSIZE];

    /* step 2 run DH KEM to get zz */
    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, NULL);
    if (pctx == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &zzlen) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (zzlen >= OSSL_HPKE_MAXSIZE) {
        OSSL_HPKE_err;
        goto err;
    }
    if (EVP_PKEY_derive(pctx, zz, &zzlen) <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    kem_contextlen = key1enclen + key2enclen;
    if (kem_contextlen >= OSSL_HPKE_MAXSIZE) {
        OSSL_HPKE_err;
        goto err;
    }
    if (encrypting) {
        memcpy(kem_context, key1enc, key1enclen);
        memcpy(kem_context + key1enclen, key2enc, key2enclen);
    } else {
        memcpy(kem_context, key2enc, key2enclen);
        memcpy(kem_context + key2enclen, key1enc, key1enclen);
    }
    if (apublen > 0) {
        /* Append the public auth key (mypub) to kem_context */
        if ((kem_contextlen + apublen) >= OSSL_HPKE_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(kem_context + kem_contextlen, apub, apublen);
        kem_contextlen += apublen;
    }

    if (akey != NULL) {
        size_t zzlen2 = 0;

        /* step 2 run to get 2nd half of zz */
        if (encrypting) {
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, akey, NULL);
        } else {
            pctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, NULL);
        }
        if (pctx == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_derive_init(pctx) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
        if (encrypting) {
            if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0) {
                OSSL_HPKE_err;
                goto err;
            }
        } else {
            if (EVP_PKEY_derive_set_peer(pctx, akey) <= 0) {
                OSSL_HPKE_err;
                goto err;
            }
        }
        if (EVP_PKEY_derive(pctx, NULL, &zzlen2) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
        if (zzlen2 >= OSSL_HPKE_MAXSIZE) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_derive(pctx, zz + zzlen, &zzlen2) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
        zzlen += zzlen2;
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;
    }
    erv = hpke_extract_and_expand(libctx, suite, OSSL_HPKE_5869_MODE_KEM,
                                  zz, zzlen, kem_context, kem_contextlen,
                                  lss, &lsslen);
    if (erv != 1) { goto err; }
    *ss = OPENSSL_malloc(lsslen);
    if (*ss == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    memcpy(*ss, lss, lsslen);
    *sslen = lsslen;

err:
    EVP_PKEY_CTX_free(pctx);
    return erv;
}

/*
 * @brief check mode is in-range and supported
 * @param mode is the caller's chosen mode
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_mode_check(unsigned int mode)
{
    switch (mode) {
    case OSSL_HPKE_MODE_BASE:
    case OSSL_HPKE_MODE_PSK:
    case OSSL_HPKE_MODE_AUTH:
    case OSSL_HPKE_MODE_PSKAUTH:
        break;
    default:
        return (- __LINE__);
    }
    return (1);
}

/*
 * @brief check psk params are as per spec
 * @param mode is the mode in use
 * @param pskid PSK identifier
 * @param psklen length of PSK
 * @param psk the psk itself
 * @return 1 for good (OpenSSL style), not 1 for error
 *
 * If a PSK mode is used both pskid and psk must be
 * non-default. Otherwise we ignore the PSK params.
 */
static int hpke_psk_check(unsigned int mode,
                          char *pskid,
                          size_t psklen,
                          const unsigned char *psk)
{
    if (mode == OSSL_HPKE_MODE_BASE || mode == OSSL_HPKE_MODE_AUTH)
        return (1);
    if (pskid == NULL)
        return (- __LINE__);
    if (psklen == 0)
        return (- __LINE__);
    if (psk == NULL)
        return (- __LINE__);
    return (1);
}

/*
 * @brief map a kem_id and a private key buffer into an EVP_PKEY
 *
 * Note that the buffer is expected to be some form of the encoded
 * private key, and could still have the PEM header or not, and might
 * or might not be base64 encoded. We'll try handle all those options.
 *
 * @param libctx is the context to use (normally NULL)
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, otherwise failure
 */
static int hpke_prbuf2evp(OSSL_LIB_CTX *libctx,
                          unsigned int kem_id,
                          unsigned char *prbuf,
                          size_t prbuf_len,
                          unsigned char *pubuf,
                          size_t pubuf_len,
                          EVP_PKEY **retpriv)
{
    int erv = 1;
    EVP_PKEY *lpriv = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *priv = NULL;
    const char *keytype = NULL;
    const char *groupname = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    uint16_t kem_ind = 0;
    int groupnid = 0;
    size_t pubsize = 0;
    BIGNUM *calc_priv = NULL;
    EC_POINT *calc_pub = NULL;
    EC_GROUP *curve = NULL;

    if (hpke_kem_id_check(kem_id) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    kem_ind = kem_iana2index(kem_id);
    if (kem_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    keytype = hpke_kem_tab[kem_ind].keytype;
    groupname = hpke_kem_tab[kem_ind].groupname;
    groupnid = hpke_kem_tab[kem_ind].groupid;
    pubsize = hpke_kem_tab[kem_ind].Npk;
    if (prbuf == NULL || prbuf_len == 0 || retpriv == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if (hpke_kem_tab[kem_ind].Npriv == prbuf_len) {
        if (keytype == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        param_bld = OSSL_PARAM_BLD_new();
        if (param_bld == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        if (groupname != NULL
            && OSSL_PARAM_BLD_push_utf8_string(param_bld, "group",
                                               groupname, 0) != 1) {
            OSSL_HPKE_err;
            goto err;
        }
        if (pubuf != NULL && pubuf_len > 0) {
            if (OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", pubuf,
                                                 pubuf_len) != 1) {
                OSSL_HPKE_err;
                goto err;
            }
        } else if (hpke_kem_id_nist_curve(kem_id) == 1) {
            /* need to calculate that public value, but we can:-) */
            unsigned char calc_pubuf[1024];
            size_t calc_pubuf_len = 1024;
            point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;

            curve = EC_GROUP_new_by_curve_name(groupnid);
            if (curve == NULL) {
                OSSL_HPKE_err;
                goto err;
            }
            calc_priv = BN_bin2bn(prbuf, prbuf_len, NULL);
            if (calc_priv == NULL) {
                OSSL_HPKE_err;
                goto err;
            }
            calc_pub = EC_POINT_new(curve);
            if (calc_pub == NULL) {
                OSSL_HPKE_err;
                goto err;
            }
            if (EC_POINT_mul(curve, calc_pub, calc_priv, NULL, NULL,
                             NULL) != 1) {
                OSSL_HPKE_err;
                goto err;
            }
            if ((calc_pubuf_len = EC_POINT_point2oct(curve, calc_pub, form,
                                                     calc_pubuf, calc_pubuf_len,
                                                     NULL)) != pubsize) {
                OSSL_HPKE_err;
                goto err;
            }
            if (OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", calc_pubuf,
                                                 calc_pubuf_len) != 1) {
                OSSL_HPKE_err;
                goto err;
            }

        }
        if (strlen(keytype) == 2 && !strcmp(keytype, "EC")) {
            priv = BN_bin2bn(prbuf, prbuf_len, NULL);
            if (priv == NULL) {
                OSSL_HPKE_err;
                goto err;
            }
            if (OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv) != 1) {
                OSSL_HPKE_err;
                goto err;
            }
        } else {
            if (OSSL_PARAM_BLD_push_octet_string(param_bld, "priv", prbuf,
                                                 prbuf_len) != 1) {
                OSSL_HPKE_err;
                goto err;
            }
        }
        params = OSSL_PARAM_BLD_to_param(param_bld);
        if (params == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        ctx = EVP_PKEY_CTX_new_from_name(libctx, keytype, NULL);
        if (ctx == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_fromdata_init(ctx) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_fromdata(ctx, &lpriv, EVP_PKEY_KEYPAIR, params) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
    }
    if (lpriv == NULL) {
        /* check PEM decode - that might work :-) */
        BIO *bfp = BIO_new(BIO_s_mem());

        if (bfp == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        BIO_write(bfp, prbuf, prbuf_len);
        if (!PEM_read_bio_PrivateKey(bfp, &lpriv, NULL, NULL)) {
            BIO_free_all(bfp);
            bfp = NULL;
            OSSL_HPKE_err;
            goto err;
        }
        if (bfp != NULL) {
            BIO_free_all(bfp);
            bfp = NULL;
        }
        if (lpriv == NULL) {
            /* if not done, prepend/append PEM header/footer and try again */
            unsigned char hf_prbuf[OSSL_HPKE_MAXSIZE];
            size_t hf_prbuf_len = 0;

            memcpy(hf_prbuf, PEM_PRIVATEHEADER, strlen(PEM_PRIVATEHEADER));
            hf_prbuf_len += strlen(PEM_PRIVATEHEADER);
            memcpy(hf_prbuf + hf_prbuf_len, prbuf, prbuf_len);
            hf_prbuf_len += prbuf_len;
            memcpy(hf_prbuf + hf_prbuf_len, PEM_PRIVATEFOOTER,
                   strlen(PEM_PRIVATEFOOTER));
            hf_prbuf_len += strlen(PEM_PRIVATEFOOTER);
            bfp = BIO_new(BIO_s_mem());
            if (bfp == NULL) {
                OSSL_HPKE_err;
                goto err;
            }
            BIO_write(bfp, hf_prbuf, hf_prbuf_len);
            if (!PEM_read_bio_PrivateKey(bfp, &lpriv, NULL, NULL)) {
                BIO_free_all(bfp);
                bfp = NULL;
                OSSL_HPKE_err;
                goto err;
            }
            BIO_free_all(bfp);
            bfp = NULL;
        }
    }
    if (lpriv == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    *retpriv = lpriv;

err:
    BN_free(calc_priv);
    EC_POINT_free(calc_pub);
    EC_GROUP_free(curve);
    BN_free(priv);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
    return (erv);
}

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not 1 otherwise
 */
static int hpke_suite_check(ossl_hpke_suite_st suite)
{
    /*
     * Check that the fields of the suite are each
     * implemented here
     */
    int kem_ok = 0;
    int kdf_ok = 0;
    int aead_ok = 0;
    int ind = 0;
    int nkems = OSSL_NELEM(hpke_kem_tab);
    int nkdfs = OSSL_NELEM(hpke_kdf_tab);
    int naeads = OSSL_NELEM(hpke_aead_tab);

    /* check KEM */
    for (ind = 0; ind != nkems; ind++) {
        if (suite.kem_id == hpke_kem_tab[ind].kem_id) {
            kem_ok = 1;
            break;
        }
    }

    /* check kdf */
    for (ind = 0; ind != nkdfs; ind++) {
        if (suite.kdf_id == hpke_kdf_tab[ind].kdf_id) {
            kdf_ok = 1;
            break;
        }
    }

    /* check aead */
    for (ind = 0; ind != naeads; ind++) {
        if (suite.aead_id == hpke_aead_tab[ind].aead_id) {
            aead_ok = 1;
            break;
        }
    }

    if (kem_ok == 1 && kdf_ok == 1 && aead_ok == 1)
        return (1);
    return (- __LINE__);
}

/*
 * @brief Internal HPKE single-shot encryption function
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the recipient public key
 * @param pub is the encoded recipient public key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv is the encoded private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the lenght of the additional data (can be zero)
 * @param aad is the encoded additional data (can be NULL)
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param extsenderpublen length of the input buffer for sender's public key
 * @param extsenderpub is the input buffer for sender public key
 * @param extsenderpriv has the handle for the sender private key
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpub is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_enc_int(OSSL_LIB_CTX *libctx,
                        unsigned int mode, ossl_hpke_suite_st suite,
                        char *pskid, size_t psklen, unsigned char *psk,
                        size_t publen, unsigned char *pub,
                        size_t authprivlen, unsigned char *authpriv,
                        EVP_PKEY *authpriv_evp,
                        size_t clearlen, unsigned char *clear,
                        size_t aadlen, unsigned char *aad,
                        size_t infolen, unsigned char *info,
                        size_t seqlen, unsigned char *seq,
                        size_t extsenderpublen, unsigned char *extsenderpub,
                        EVP_PKEY *extsenderpriv,
                        size_t rawsenderprivlen, unsigned char *rawsenderpriv,
                        size_t *senderpublen, unsigned char *senderpub,
                        size_t *cipherlen, unsigned char *cipher)

{
    int erv = 1; /* Our error return value - 1 is success */
    int evpcaller = 0;
    int rawcaller = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkR = NULL;
    EVP_PKEY *pkE = NULL;
    EVP_PKEY *skI = NULL;
    size_t shared_secretlen = 0;
    unsigned char *shared_secret = NULL;
    size_t enclen = 0;
    unsigned char *enc = NULL;
    size_t ks_contextlen = OSSL_HPKE_MAXSIZE;
    unsigned char ks_context[OSSL_HPKE_MAXSIZE];
    size_t secretlen = OSSL_HPKE_MAXSIZE;
    unsigned char secret[OSSL_HPKE_MAXSIZE];
    size_t psk_hashlen = OSSL_HPKE_MAXSIZE;
    unsigned char psk_hash[OSSL_HPKE_MAXSIZE];
    size_t noncelen = OSSL_HPKE_MAXSIZE;
    unsigned char nonce[OSSL_HPKE_MAXSIZE];
    size_t keylen = OSSL_HPKE_MAXSIZE;
    unsigned char key[OSSL_HPKE_MAXSIZE];
    size_t exporterlen = OSSL_HPKE_MAXSIZE;
    unsigned char exporter[OSSL_HPKE_MAXSIZE];
    size_t mypublen = 0;
    unsigned char *mypub = NULL;
    BIO *bfp = NULL;
    size_t halflen = 0;
    size_t pskidlen = 0;
    uint16_t aead_ind = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    if ((erv = hpke_mode_check(mode)) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((erv = hpke_psk_check(mode, pskid, psklen, psk)) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((erv = hpke_suite_check(suite)) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    /*
     * Depending on who called us, we may want to generate this key pair
     * or we may have had it handed to us via extsender inputs
     */
    if (extsenderpublen > 0 && extsenderpub != NULL && extsenderpriv != NULL) {
        evpcaller = 1;
    }
    if (extsenderpublen > 0 && extsenderpub != NULL && extsenderpriv == NULL
        && rawsenderprivlen > 0 && rawsenderpriv != NULL) {
        rawcaller = 1;
    }
    if (evpcaller == 0 && rawcaller == 0
        && (pub == NULL || clear == NULL
            || senderpublen == NULL || senderpub == NULL
            || cipherlen == NULL || cipher == NULL)) {
        OSSL_HPKE_err;
        goto err;
    }
    if (evpcaller
        && (pub == NULL || clear == NULL
            || !extsenderpublen || extsenderpub == NULL
            || extsenderpriv == NULL || !cipherlen || cipher == NULL)) {
        OSSL_HPKE_err;
        goto err;
    }
    if (rawcaller
        && (pub == NULL || clear == NULL
            || !extsenderpublen || extsenderpub == NULL
            || rawsenderpriv == NULL || !cipherlen || cipher == NULL)) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((mode == OSSL_HPKE_MODE_AUTH || mode == OSSL_HPKE_MODE_PSKAUTH)
        &&
        ((authpriv == NULL || authprivlen == 0) && (authpriv_evp == NULL))) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((mode == OSSL_HPKE_MODE_PSK || mode == OSSL_HPKE_MODE_PSKAUTH)
        && (psk == NULL || !psklen || pskid == NULL)) {
        OSSL_HPKE_err;
        goto err;
    }
    /*
     * The plan:
     * 0. Initialise peer's key from string
     * 1. generate sender's key pair
     * 2. run DH KEM to get dh
     * 3. create context buffer
     * 4. extracts and expands as needed
     * 5. call the AEAD
     */

    /* step 0. Initialise peer's key from string */
    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pkR = hpke_EVP_PKEY_new_raw_nist_public_key(libctx,
                                                    hpke_kem_tab[kem_ind].
                                                    groupid,
                                                    hpke_kem_tab[kem_ind].
                                                    groupname, pub, publen);
    } else {
        pkR = EVP_PKEY_new_raw_public_key_ex(libctx,
                                             hpke_kem_tab[kem_ind].keytype,
                                             NULL, pub, publen);
    }
    if (pkR == NULL) {
        OSSL_HPKE_err;
        goto err;
    }

    /* step 1. generate or import sender's key pair: skE, pkE */
    if (!evpcaller && !rawcaller) {
        pctx = EVP_PKEY_CTX_new(pkR, NULL);
        if (pctx == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
        EVP_PKEY_CTX_free(pctx);
        pctx = NULL;
    } else if (evpcaller) {
        pkE = extsenderpriv;
    } else if (rawcaller) {
        erv = hpke_prbuf2evp(libctx, suite.kem_id, rawsenderpriv,
                             rawsenderprivlen, NULL, 0, &pkE);
        if (erv != 1) {
            OSSL_HPKE_err;
            goto err;
        }
        if (pkE == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
    }

    /* step 2 run DH KEM to get dh */
    enclen = EVP_PKEY_get1_encoded_public_key(pkE, &enc);
    if (enc == NULL || enclen == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    /* load auth key pair if using an auth mode */
    if (mode == OSSL_HPKE_MODE_AUTH || mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (authpriv_evp != NULL) {
            skI = authpriv_evp;
        } else {
            erv = hpke_prbuf2evp(libctx, suite.kem_id, authpriv, authprivlen,
                                 pub, publen, &skI);
            if (erv != 1) {
                OSSL_HPKE_err;
                goto err;
            }
        }
        if (skI == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        mypublen = EVP_PKEY_get1_encoded_public_key(skI, &mypub);
        if (mypub == NULL || mypublen == 0) {
            OSSL_HPKE_err;
            goto err;
        }
    }
    erv = hpke_do_kem(libctx, 1, suite, pkE, enclen, enc, pkR, publen, pub,
                      skI, mypublen, mypub, &shared_secret, &shared_secretlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    OPENSSL_free(mypub);
    mypub = NULL;

    /* step 3. create context buffer starting with key_schedule_context */
    memset(ks_context, 0, OSSL_HPKE_MAXSIZE);
    ks_context[0] = (unsigned char)(mode % 256);
    ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = (psk == NULL ? 0 : strlen(pskid));
    erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_PSKIDHASH_LABEL,
                       strlen(OSSL_HPKE_PSKIDHASH_LABEL),
                       (unsigned char *)pskid, pskidlen,
                       ks_context + 1, &halflen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    ks_contextlen -= halflen;
    erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_INFOHASH_LABEL,
                       strlen(OSSL_HPKE_INFOHASH_LABEL),
                       (unsigned char *)info, infolen,
                       ks_context + 1 + halflen, &ks_contextlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    ks_contextlen += 1 + halflen;

    /* step 4. extracts and expands as needed */
    erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_PSK_HASH_LABEL,
                       strlen(OSSL_HPKE_PSK_HASH_LABEL),
                       psk, psklen, psk_hash, &psk_hashlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    kdf_ind = kdf_iana2index(suite.kdf_id);
    if (kdf_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    secretlen = hpke_kdf_tab[kdf_ind].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        OSSL_HPKE_err;
        goto err;
    }
    erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                       shared_secret, shared_secretlen,
                       OSSL_HPKE_SECRET_LABEL, strlen(OSSL_HPKE_SECRET_LABEL),
                       psk, psklen, secret, &secretlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    noncelen = hpke_aead_tab[aead_ind].Nn;
    erv = hpke_expand(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_NONCE_LABEL, strlen(OSSL_HPKE_NONCE_LABEL),
                      ks_context, ks_contextlen, noncelen, nonce, &noncelen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    if (noncelen != hpke_aead_tab[aead_ind].Nn) {
        OSSL_HPKE_err;
        goto err;
    }
    if (seq != NULL && seqlen > 0) { /* XOR sequence with nonce as needed */
        size_t sind;
        unsigned char cv;

        if (seqlen > noncelen) {
            OSSL_HPKE_err;
            goto err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            if (sind < seqlen) {
                cv = seq[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }
    keylen = hpke_aead_tab[aead_ind].Nk;
    erv = hpke_expand(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_KEY_LABEL, strlen(OSSL_HPKE_KEY_LABEL),
                      ks_context, ks_contextlen, keylen, key, &keylen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    exporterlen = hpke_kdf_tab[kdf_ind].Nh;
    erv = hpke_expand(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_EXP_LABEL, strlen(OSSL_HPKE_EXP_LABEL),
                      ks_context, ks_contextlen,
                      exporterlen, exporter, &exporterlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }

    /* step 5. call the AEAD */
    erv = hpke_aead_enc(libctx, suite, key, keylen, nonce, noncelen,
                        aad, aadlen, clear, clearlen, cipher, cipherlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    if (!evpcaller && !rawcaller) { /* finish up */
        if (enclen > *senderpublen) {
            OSSL_HPKE_err;
            goto err;
        }
        memcpy(senderpub, enc, enclen);
        *senderpublen = enclen;
    }

err:
    OPENSSL_free(mypub);
    BIO_free_all(bfp);
    EVP_PKEY_free(pkR);
    if (!evpcaller) { EVP_PKEY_free(pkE); }
    EVP_PKEY_free(skI);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(shared_secret);
    OPENSSL_free(enc);
    return erv;
}

/*
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public (authentication) key
 * @param pub is the encoded public (authentication) key
 * @param privlen is the length of the private key
 * @param priv is the encoded private key
 * @param evppriv is a pointer to an internal form of private key
 * @param enclen is the length of the peer's public value
 * @param enc is the peer's public value
 * @param cipherlen is the length of the ciphertext
 * @param cipher is the ciphertext
 * @param aadlen is the lenght of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param clearlen length of the input buffer for cleartext
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_dec_int(OSSL_LIB_CTX *libctx,
                        unsigned int mode, ossl_hpke_suite_st suite,
                        char *pskid, size_t psklen, unsigned char *psk,
                        size_t authpublen, unsigned char *authpub,
                        size_t privlen, unsigned char *priv,
                        EVP_PKEY *evppriv,
                        size_t enclen, unsigned char *enc,
                        size_t cipherlen, unsigned char *cipher,
                        size_t aadlen, unsigned char *aad,
                        size_t infolen, unsigned char *info,
                        size_t seqlen, unsigned char *seq,
                        size_t *clearlen, unsigned char *clear)
{
    int erv = 1;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    EVP_PKEY *pkE = NULL;
    EVP_PKEY *pkI = NULL;
    size_t shared_secretlen = 0;
    unsigned char *shared_secret = NULL;
    size_t ks_contextlen = OSSL_HPKE_MAXSIZE;
    unsigned char ks_context[OSSL_HPKE_MAXSIZE];
    size_t secretlen = OSSL_HPKE_MAXSIZE;
    unsigned char secret[OSSL_HPKE_MAXSIZE];
    size_t noncelen = OSSL_HPKE_MAXSIZE;
    unsigned char nonce[OSSL_HPKE_MAXSIZE];
    size_t psk_hashlen = OSSL_HPKE_MAXSIZE;
    unsigned char psk_hash[OSSL_HPKE_MAXSIZE];
    size_t keylen = OSSL_HPKE_MAXSIZE;
    unsigned char key[OSSL_HPKE_MAXSIZE];
    size_t exporterlen = OSSL_HPKE_MAXSIZE;
    unsigned char exporter[OSSL_HPKE_MAXSIZE];
    size_t mypublen = 0;
    unsigned char *mypub = NULL;
    BIO *bfp = NULL;
    size_t halflen = 0;
    size_t pskidlen = 0;
    uint16_t aead_ind = 0;
    uint16_t kem_ind = 0;
    uint16_t kdf_ind = 0;

    if ((erv = hpke_mode_check(mode)) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((erv = hpke_psk_check(mode, pskid, psklen, psk)) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((erv = hpke_suite_check(suite)) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((priv == NULL && evppriv == NULL)
        || !clearlen || clear == NULL || cipher == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((mode == OSSL_HPKE_MODE_AUTH || mode == OSSL_HPKE_MODE_PSKAUTH)
        && (!authpub || authpublen == 0)) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((mode == OSSL_HPKE_MODE_PSK || mode == OSSL_HPKE_MODE_PSKAUTH)
        && (psk == NULL || !psklen || pskid == NULL)) {
        OSSL_HPKE_err;
        goto err;
    }
    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }

    /*
     * The plan:
     * 0. Initialise peer's key from string
     * 1. load decryptors private key
     * 2. run DH KEM to get dh
     * 3. create context buffer
     * 4. extracts and expands as needed
     * 5. call the AEAD
     *
     */

    /* step 0. Initialise peer's key(s) from string(s) */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pkE = hpke_EVP_PKEY_new_raw_nist_public_key(libctx,
                                                    hpke_kem_tab[kem_ind].
                                                    groupid,
                                                    hpke_kem_tab[kem_ind].
                                                    groupname,
                                                    enc, enclen);
    } else {
        pkE = EVP_PKEY_new_raw_public_key_ex(libctx,
                                             hpke_kem_tab[kem_ind].keytype,
                                             NULL, enc, enclen);
    }
    if (pkE == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if (authpublen != 0 && authpub != NULL) {
        if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
            pkI = hpke_EVP_PKEY_new_raw_nist_public_key(libctx,
                                                        hpke_kem_tab[kem_ind].
                                                        groupid,
                                                        hpke_kem_tab[kem_ind].
                                                        groupname,
                                                        authpub, authpublen);
        } else {
            pkI = EVP_PKEY_new_raw_public_key_ex(libctx,
                                                 hpke_kem_tab[kem_ind].keytype,
                                                 NULL, authpub, authpublen);
        }
        if (pkI == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
    }

    /* step 1. load decryptors private key */
    if (evppriv == NULL) {
        erv = hpke_prbuf2evp(libctx, suite.kem_id, priv, privlen,
                             NULL, 0, &skR);
        if (erv != 1) {
            OSSL_HPKE_err;
            goto err;
        }
        if (skR == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
    } else {
        skR = evppriv;
    }

    /* step 2 run DH KEM to get dh */
    mypublen = EVP_PKEY_get1_encoded_public_key(skR, &mypub);
    if (mypub == NULL || mypublen == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    erv = hpke_do_kem(libctx, 0, suite, skR, mypublen, mypub, pkE, enclen, enc,
                      pkI, authpublen, authpub,
                      &shared_secret, &shared_secretlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }

    /* step 3. create context buffer */
    memset(ks_context, 0, OSSL_HPKE_MAXSIZE);
    ks_context[0] = (unsigned char)(mode % 256);

    ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = (psk == NULL ? 0 : strlen(pskid));
    erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_PSKIDHASH_LABEL,
                       strlen(OSSL_HPKE_PSKIDHASH_LABEL),
                       (unsigned char *)pskid, pskidlen,
                       ks_context + 1, &halflen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    ks_contextlen -= halflen;
    erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_INFOHASH_LABEL,
                       strlen(OSSL_HPKE_INFOHASH_LABEL),
                       info, infolen,
                       ks_context + 1 + halflen, &ks_contextlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    ks_contextlen += 1 + halflen;

    /* step 4. extracts and expands as needed */
    /* Extract secret and Expand variously...  */
    erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                       (const unsigned char *)"", 0,
                       OSSL_HPKE_PSK_HASH_LABEL,
                       strlen(OSSL_HPKE_PSK_HASH_LABEL),
                       psk, psklen,
                       psk_hash, &psk_hashlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    kdf_ind = kdf_iana2index(suite.kdf_id);
    if (kdf_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    secretlen = hpke_kdf_tab[kdf_ind].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        OSSL_HPKE_err;
        goto err;
    }
    erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                       shared_secret, shared_secretlen,
                       OSSL_HPKE_SECRET_LABEL, strlen(OSSL_HPKE_SECRET_LABEL),
                       psk, psklen, secret, &secretlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    noncelen = hpke_aead_tab[aead_ind].Nn;
    erv = hpke_expand(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_NONCE_LABEL, strlen(OSSL_HPKE_NONCE_LABEL),
                      ks_context, ks_contextlen,
                      noncelen, nonce, &noncelen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    if (noncelen != hpke_aead_tab[aead_ind].Nn) {
        OSSL_HPKE_err;
        goto err;
    }
    /* XOR sequence with nonce as needed */
    if (seq != NULL && seqlen > 0) {
        size_t sind;
        unsigned char cv;

        if (seqlen > noncelen) {
            OSSL_HPKE_err;
            goto err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            if (sind < seqlen) {
                cv = seq[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }
    keylen = hpke_aead_tab[aead_ind].Nk;
    erv = hpke_expand(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_KEY_LABEL, strlen(OSSL_HPKE_KEY_LABEL),
                      ks_context, ks_contextlen,
                      keylen, key, &keylen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    exporterlen = hpke_kdf_tab[kdf_ind].Nh;
    erv = hpke_expand(libctx, suite, OSSL_HPKE_5869_MODE_FULL,
                      secret, secretlen,
                      OSSL_HPKE_EXP_LABEL, strlen(OSSL_HPKE_EXP_LABEL),
                      ks_context, ks_contextlen,
                      exporterlen, exporter, &exporterlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }

    /* step 5. call the AEAD */
    erv = hpke_aead_dec(libctx, suite, key, keylen,
                        nonce, noncelen, aad, aadlen,
                        cipher, cipherlen, clear, clearlen);
    if (erv != 1) {
        OSSL_HPKE_err;
        goto err;
    }

err:
    BIO_free_all(bfp);
    if (evppriv == NULL) { EVP_PKEY_free(skR); }
    EVP_PKEY_free(pkE);
    EVP_PKEY_free(pkI);
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(shared_secret);
    OPENSSL_free(mypub);
    return erv;
}

/*
 * @brief compare a buffer vs. the group order
 *
 * @param kemid specifies the group (HPKE KEM code-points)
 * @param buflen is the size of the buffer
 * @param buf is the buffer
 * @param res is returned as 0 for equal, -1 if buf < order, +1 if buf > order
 * @return 1 for good, other otherwise
 */
static int hpke_kg_comp2order(uint32_t kemid, size_t buflen,
                              unsigned char *buf, int *res)
{
    /*
     * P-256: ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
     * P-384: ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf
     *        581a0db248b0a77aecec196accc52973
     * P-521: 01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
     *        fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
     */
    BIGNUM *bufbn = NULL;
    BIGNUM *gorder = NULL;
    int cres = 0;
    unsigned char p256ord[] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    };
    unsigned char p384ord[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
        0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
        0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73
    };
    unsigned char p521ord[] = {
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f,
        0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
        0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
        0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
        0x64, 0x09
    };

    if (res == NULL || buf == NULL || buflen == 0) {
        return - __LINE__;
    }
    switch (kemid) {
    case OSSL_HPKE_KEM_ID_P256:
        gorder = BN_bin2bn(p256ord, sizeof(p256ord), NULL);
        break;
    case OSSL_HPKE_KEM_ID_P384:
        gorder = BN_bin2bn(p384ord, sizeof(p384ord), NULL);
        break;
    case OSSL_HPKE_KEM_ID_P521:
        gorder = BN_bin2bn(p521ord, sizeof(p521ord), NULL);
        break;
    default:
        return - __LINE__;
    }
    if (gorder == NULL) {
        return - __LINE__;
    }
    bufbn = BN_bin2bn(buf, buflen, NULL);
    if (bufbn == NULL) {
        return - __LINE__;
    }
    cres = BN_cmp(bufbn, gorder);
    *res = cres;
    BN_free(bufbn);
    BN_free(gorder);
    return 1;
}

/*
 * @brief generate a key pair keeping private inside API
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key pointer
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg_evp(OSSL_LIB_CTX *libctx,
                       unsigned int mode, ossl_hpke_suite_st suite,
                       size_t ikmlen, unsigned char *ikm,
                       size_t *publen, unsigned char *pub,
                       EVP_PKEY **priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    unsigned char *lpub = NULL;
    size_t lpublen = 0;
    uint16_t kem_ind = 0;
    int cmp = 0;

    if (hpke_suite_check(suite) != 1)
        return (- __LINE__);
    if (pub == NULL || priv == NULL)
        return (- __LINE__);
    if (ikmlen > 0 && ikm == NULL)
        return (- __LINE__);
    if (ikmlen == 0 && ikm != NULL)
        return (- __LINE__);
    kem_ind = kem_iana2index(suite.kem_id);
    if (kem_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    /* setup generation of key pair */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pctx = EVP_PKEY_CTX_new_from_name(libctx,
                                          hpke_kem_tab[kem_ind].keytype,
                                          hpke_kem_tab[kem_ind].groupname);
        if (pctx == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_paramgen_init(pctx) != 1) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                                   hpke_kem_tab[kem_ind].groupid
                                                   ) != 1) {
            OSSL_HPKE_err;
            goto err;
        }
        if (ikm != NULL) {
            /* deterministic generation */
            /*
             *   def DeriveKeyPair(ikm):
             *     dkp_prk = LabeledExtract("", "dkp_prk", ikm)
             *     sk = 0
             *     counter = 0
             *     while sk == 0 or sk >= order:
             *       if counter > 255:
             *           raise DeriveKeyPairError
             *       bytes = LabeledExpand(dkp_prk, "candidate",
             *                           I2OSP(counter, 1), Nsk)
             *       bytes[0] = bytes[0] & bitmask
             *       sk = OS2IP(bytes)
             *       counter = counter + 1
             *     return (sk, pk(sk))
             */
            size_t tmplen = OSSL_HPKE_MAXSIZE;
            unsigned char tmp[OSSL_HPKE_MAXSIZE];
            size_t sklen = OSSL_HPKE_MAXSIZE;
            unsigned char sk[OSSL_HPKE_MAXSIZE];
            unsigned char counter = 0;

            erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_KEM,
                               (const unsigned char *)"", 0,
                               OSSL_HPKE_DPK_LABEL, strlen(OSSL_HPKE_DPK_LABEL),
                               ikm, ikmlen,
                               tmp, &tmplen);
            if (erv != 1) { goto err; }
            while (counter < 255) {

                erv = hpke_expand(libctx, suite, OSSL_HPKE_5869_MODE_KEM,
                                  tmp, tmplen,
                                  OSSL_HPKE_CAND_LABEL,
                                  strlen(OSSL_HPKE_CAND_LABEL),
                                  &counter, 1,
                                  hpke_kem_tab[kem_ind].Npriv,
                                  sk, &sklen);
                if (erv != 1) {
                    memset(tmp, 0, tmplen);
                    goto err;
                }
                switch (suite.kem_id) {
                case OSSL_HPKE_KEM_ID_P256:
                case OSSL_HPKE_KEM_ID_P384:
                    /* nothing to do for those really */
                    break;
                case OSSL_HPKE_KEM_ID_P521:
                    /* mask as RFC requires */
                    sk[0] &= 0x01;
                    break;
                default:
                    memset(tmp, 0, tmplen);
                    goto err;
                }
                /* check sk vs. group order */
                if (hpke_kg_comp2order(suite.kem_id, sklen, sk, &cmp) != 1) {
                    goto err;
                }
                if (cmp == -1) { /* success! */
                    break;
                }
            }
            if (counter == 255) {
                memset(tmp, 0, tmplen);
                goto err;
            }
            erv = hpke_prbuf2evp(libctx, suite.kem_id, sk, sklen,
                                 NULL, 0, &skR);
            memset(sk, 0, sklen);
            memset(tmp, 0, tmplen);
            if (erv != 1) { goto err; }
        }
    } else {
        pctx = EVP_PKEY_CTX_new_from_name(libctx,
                                          hpke_kem_tab[kem_ind].keytype, NULL);
        if (pctx == NULL) {
            OSSL_HPKE_err;
            goto err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
        if (ikm != NULL) {
            /* deterministic generation */
            /*
             * def DeriveKeyPair(ikm):
             *   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
             *   sk = LabeledExpand(dkp_prk, "sk", "", Nsk)
             *   return (sk, pk(sk))
             */
            size_t tmplen = OSSL_HPKE_MAXSIZE;
            unsigned char tmp[OSSL_HPKE_MAXSIZE];
            size_t sklen = OSSL_HPKE_MAXSIZE;
            unsigned char sk[OSSL_HPKE_MAXSIZE];

            erv = hpke_extract(libctx, suite, OSSL_HPKE_5869_MODE_KEM,
                               (const unsigned char *)"", 0,
                               OSSL_HPKE_DPK_LABEL, strlen(OSSL_HPKE_DPK_LABEL),
                               ikm, ikmlen,
                               tmp, &tmplen);
            if (erv != 1) { goto err; }
            erv = hpke_expand(libctx, suite, OSSL_HPKE_5869_MODE_KEM,
                              tmp, tmplen,
                              OSSL_HPKE_SK_LABEL, strlen(OSSL_HPKE_SK_LABEL),
                              NULL, 0,
                              hpke_kem_tab[kem_ind].Npriv,
                              sk, &sklen);
            if (erv != 1) {
                memset(tmp, 0, tmplen);
                goto err;
            }
            erv = hpke_prbuf2evp(libctx, suite.kem_id, sk, sklen,
                                 NULL, 0, &skR);
            memset(sk, 0, sklen);
            memset(tmp, 0, tmplen);
            if (erv != 1) { goto err; }

        }
    }
    /* generate sender's key pair */
    if (ikm == NULL) {
        /* randomly generate, deterministic done above */
        if (EVP_PKEY_generate(pctx, &skR) <= 0) {
            OSSL_HPKE_err;
            goto err;
        }
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    lpublen = EVP_PKEY_get1_encoded_public_key(skR, &lpub);
    if (lpub == NULL || lpublen == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (lpublen > *publen) {
        OSSL_HPKE_err;
        goto err;
    }
    *publen = lpublen;
    memcpy(pub, lpub, lpublen);
    *priv = skR;

err:
    if (erv != 1) { EVP_PKEY_free(skR); }
    EVP_PKEY_CTX_free(pctx);
    OPENSSL_free(lpub);
    return (erv);
}

/*
 * @brief generate a key pair
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg(OSSL_LIB_CTX *libctx,
                   unsigned int mode, ossl_hpke_suite_st suite,
                   size_t ikmlen, unsigned char *ikm,
                   size_t *publen, unsigned char *pub,
                   size_t *privlen, unsigned char *priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY *skR = NULL;
    BIO *bfp = NULL;
    unsigned char lpriv[OSSL_HPKE_MAXSIZE];
    size_t lprivlen = 0;

    if (hpke_suite_check(suite) != 1)
        return (- __LINE__);
    if (pub == NULL || priv == NULL)
        return (- __LINE__);
    erv = hpke_kg_evp(libctx, mode, suite, ikmlen, ikm, publen, pub, &skR);
    if (erv != 1) {
        return (erv);
    }
    bfp = BIO_new(BIO_s_mem());
    if (bfp == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if (!PEM_write_bio_PrivateKey(bfp, skR, NULL, NULL, 0, NULL, NULL)) {
        OSSL_HPKE_err;
        goto err;
    }
    lprivlen = BIO_read(bfp, lpriv, OSSL_HPKE_MAXSIZE);
    if (lprivlen <= 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if (lprivlen > *privlen) {
        OSSL_HPKE_err;
        goto err;
    }
    *privlen = lprivlen;
    memcpy(priv, lpriv, lprivlen);

err:
    EVP_PKEY_free(skR);
    BIO_free_all(bfp);
    return (erv);
}

/*
 * @brief randomly pick a suite
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the result
 * @return 1 for success, otherwise failure
 *
 * If you change the structure of the various *_tab arrays
 * then this code will also need change.
 */
static int hpke_random_suite(OSSL_LIB_CTX *libctx, ossl_hpke_suite_st *suite)
{
    unsigned char rval = 0;
    int nkdfs = OSSL_NELEM(hpke_kdf_tab)-1;
    int naeads = OSSL_NELEM(hpke_aead_tab)-1;
    int nkems = OSSL_NELEM(hpke_kem_tab)-1;

    /* random kem */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), OSSL_HPKE_RSTRENGTH) <= 0)
        return (- __LINE__);
    suite->kem_id = hpke_kem_tab[(rval % nkems + 1)].kem_id;

    /* random kdf */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), OSSL_HPKE_RSTRENGTH) <= 0)
        return (- __LINE__);
    suite->kdf_id = hpke_kdf_tab[(rval % nkdfs + 1)].kdf_id;

    /* random aead */
    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), OSSL_HPKE_RSTRENGTH) <= 0)
        return (- __LINE__);
    suite->aead_id = hpke_aead_tab[(rval % naeads + 1)].aead_id;
    return 1;
}

/*
 * @brief return a (possibly) random suite, public key, ciphertext for GREASErs
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite-in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher buffer with random value of the appropriate length
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
static int hpke_good4grease(OSSL_LIB_CTX *libctx,
                            ossl_hpke_suite_st *suite_in,
                            ossl_hpke_suite_st *suite,
                            unsigned char *pub,
                            size_t *pub_len,
                            unsigned char *cipher,
                            size_t cipher_len)
{
    ossl_hpke_suite_st chosen;
    int crv = 0;
    int erv = 0;
    size_t plen = 0;
    uint16_t kem_ind = 0;

    if (pub == NULL || !pub_len
        || cipher == NULL || !cipher_len || suite == NULL)
        return (- __LINE__);
    if (suite_in == NULL) {
        /* choose a random suite */
        crv = hpke_random_suite(libctx, &chosen);
        if (crv != 1)
            return (crv);
    } else {
        chosen = *suite_in;
    }
    kem_ind = kem_iana2index(chosen.kem_id);
    if (kem_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((crv = hpke_suite_check(chosen)) != 1)
        return (- __LINE__);
    *suite = chosen;
    /* publen */
    plen = hpke_kem_tab[kem_ind].Npk;
    if (plen > *pub_len)
        return (- __LINE__);
    if (RAND_bytes_ex(libctx, pub, plen, OSSL_HPKE_RSTRENGTH) <= 0)
        return (- __LINE__);
    *pub_len = plen;
    if (RAND_bytes_ex(libctx, cipher, cipher_len, OSSL_HPKE_RSTRENGTH) <= 0)
        return (- __LINE__);
    return 1;
err:
    return (erv);
}

/*
 * @brief string matching for suites
 */
#if defined(_WIN32)
# define HPKE_MSMATCH(inp, known) \
    (strlen(inp) == strlen(known) && !_stricmp(inp, known))
#else
# define HPKE_MSMATCH(inp, known) \
    (strlen(inp) == strlen(known) && !strcasecmp(inp, known))
#endif

/*
 * @brief map a string to a HPKE suite
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
static int hpke_str2suite(char *suitestr, ossl_hpke_suite_st *suite)
{
    uint16_t kem = 0, kdf = 0, aead = 0;
    char *st = NULL;
    char *instrcp = NULL;
    size_t inplen = 0;
    int labels = 0;

    if (suitestr == NULL || suite == NULL)
        return (- __LINE__);
    /* See if it contains a mix of our strings and numbers  */
    inplen = OPENSSL_strnlen(suitestr, OSSL_HPKE_MAX_SUITESTR);
    if (inplen >= OSSL_HPKE_MAX_SUITESTR)
        return (- __LINE__);
    instrcp = OPENSSL_strndup(suitestr, inplen);
    st = strtok(instrcp, ",");
    if (st == NULL) {
        OPENSSL_free(instrcp);
        return (- __LINE__);
    }
    while (st != NULL && ++labels <= 3) {
        /* check if string is known or number and if so handle appropriately */
        if (kem == 0) {
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_P256)) {
                kem = OSSL_HPKE_KEM_ID_P256;
            }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_P384)) {
                kem = OSSL_HPKE_KEM_ID_P384;
            }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_P521)) {
                kem = OSSL_HPKE_KEM_ID_P521;
            }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_X25519)) {
                kem = OSSL_HPKE_KEM_ID_25519;
            }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KEMSTR_X448)) {
                kem = OSSL_HPKE_KEM_ID_448;
            }
            if (HPKE_MSMATCH(st, "0x10")) { kem = OSSL_HPKE_KEM_ID_P256; }
            if (HPKE_MSMATCH(st, "16")) { kem = OSSL_HPKE_KEM_ID_P256; }
            if (HPKE_MSMATCH(st, "0x11")) { kem = OSSL_HPKE_KEM_ID_P384; }
            if (HPKE_MSMATCH(st, "17")) { kem = OSSL_HPKE_KEM_ID_P384; }
            if (HPKE_MSMATCH(st, "0x12")) { kem = OSSL_HPKE_KEM_ID_P521; }
            if (HPKE_MSMATCH(st, "18")) { kem = OSSL_HPKE_KEM_ID_P521; }
            if (HPKE_MSMATCH(st, "0x20")) { kem = OSSL_HPKE_KEM_ID_25519; }
            if (HPKE_MSMATCH(st, "32")) { kem = OSSL_HPKE_KEM_ID_25519; }
            if (HPKE_MSMATCH(st, "0x21")) { kem = OSSL_HPKE_KEM_ID_448; }
            if (HPKE_MSMATCH(st, "33")) { kem = OSSL_HPKE_KEM_ID_448; }
        } else if (kem != 0 && kdf == 0) {
            if (HPKE_MSMATCH(st, OSSL_HPKE_KDFSTR_256)) { kdf = 1; }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KDFSTR_384)) { kdf = 2; }
            if (HPKE_MSMATCH(st, OSSL_HPKE_KDFSTR_512)) { kdf = 3; }
            if (HPKE_MSMATCH(st, "0x01")) { kdf = 1; }
            if (HPKE_MSMATCH(st, "0x02")) { kdf = 2; }
            if (HPKE_MSMATCH(st, "0x03")) { kdf = 3; }
            if (HPKE_MSMATCH(st, "0x1")) { kdf = 1; }
            if (HPKE_MSMATCH(st, "0x2")) { kdf = 2; }
            if (HPKE_MSMATCH(st, "0x3")) { kdf = 3; }
            if (HPKE_MSMATCH(st, "1")) { kdf = 1; }
            if (HPKE_MSMATCH(st, "2")) { kdf = 2; }
            if (HPKE_MSMATCH(st, "3")) { kdf = 3; }
        } else if (kem != 0 && kdf != 0 && aead == 0) {
            if (HPKE_MSMATCH(st, OSSL_HPKE_AEADSTR_AES128GCM)) { aead = 1; }
            if (HPKE_MSMATCH(st, OSSL_HPKE_AEADSTR_AES256GCM)) { aead = 2; }
            if (HPKE_MSMATCH(st, OSSL_HPKE_AEADSTR_CP)) { aead = 3; }
            if (HPKE_MSMATCH(st, "0x01")) { aead = 1; }
            if (HPKE_MSMATCH(st, "0x02")) { aead = 2; }
            if (HPKE_MSMATCH(st, "0x03")) { aead = 3; }
            if (HPKE_MSMATCH(st, "0x1")) { aead = 1; }
            if (HPKE_MSMATCH(st, "0x2")) { aead = 2; }
            if (HPKE_MSMATCH(st, "0x3")) { aead = 3; }
            if (HPKE_MSMATCH(st, "1")) { aead = 1; }
            if (HPKE_MSMATCH(st, "2")) { aead = 2; }
            if (HPKE_MSMATCH(st, "3")) { aead = 3; }
        }
        st = strtok(NULL, ",");
    }
    OPENSSL_free(instrcp);
    if ((st != NULL && labels > 3) || kem == 0 || kdf == 0 || aead == 0) {
        return (- __LINE__);
    }
    suite->kem_id = kem;
    suite->kdf_id = kdf;
    suite->aead_id = aead;
    return 1;
}

/*
 * @brief tell the caller how big the cipertext will be
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who knows what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given suite.
 *
 * @param suite is the suite to be used
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
static int hpke_expansion(ossl_hpke_suite_st suite,
                          size_t clearlen,
                          size_t *cipherlen)
{
    int erv = 0;
    size_t tlen = 0;
    uint16_t aead_ind = 0;

    if (cipherlen == NULL) {
        OSSL_HPKE_err;
        goto err;
    }
    if ((erv = hpke_suite_check(suite)) != 1) {
        OSSL_HPKE_err;
        goto err;
    }
    aead_ind = aead_iana2index(suite.aead_id);
    if (aead_ind == 0) {
        OSSL_HPKE_err;
        goto err;
    }
    tlen = hpke_aead_tab[aead_ind].taglen;
    *cipherlen = tlen + clearlen;
    return 1;

err:
    return erv;
}

/*
 * @brief HPKE single-shot encryption function
 *
 * This function generates an ephemeral ECDH value internally and
 * provides the public component as an output.
 *
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public key
 * @param pub is the encoded public key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv is the encoded private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param senderpublen length of the input buffer for sender's public key
 * @param senderpub is the input buffer for sender public key
 * @param cipherlen is the length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
int OSSL_HPKE_enc(OSSL_LIB_CTX *libctx,
                  unsigned int mode, ossl_hpke_suite_st suite,
                  char *pskid, size_t psklen, unsigned char *psk,
                  size_t publen, unsigned char *pub,
                  size_t authprivlen, unsigned char *authpriv,
                  EVP_PKEY *authpriv_evp,
                  size_t clearlen, unsigned char *clear,
                  size_t aadlen, unsigned char *aad,
                  size_t infolen, unsigned char *info,
                  size_t seqlen, unsigned char *seq,
                  size_t *senderpublen, unsigned char *senderpub,
                  size_t *cipherlen, unsigned char *cipher)
{
    return hpke_enc_int(libctx, mode, suite,
                        pskid, psklen, psk,
                        publen, pub,
                        authprivlen, authpriv, authpriv_evp,
                        clearlen, clear,
                        aadlen, aad,
                        infolen, info,
                        seqlen, seq,
                        0, NULL,
                        NULL, 0, NULL,
                        senderpublen, senderpub,
                        cipherlen, cipher);
}

/*
 * @brief HPKE encryption function, with externally supplied sender key pair
 *
 * This function is provided with an ECDH key pair that is used for
 * HPKE encryption.
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public key
 * @param pub is the encoded public key
 * @param authprivlen is the length of the private (authentication) key
 * @param authpriv is the encoded private (authentication) key
 * @param authpriv_evp is the EVP_PKEY* form of private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param senderpublen length of the input buffer with the sender's public key
 * @param senderpub is the input buffer for sender public key
 * @param senderpriv has the handle for the sender private key
 * @param cipherlen length of the input buffer for ciphertext
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 *
 * Oddity: we're passing an hpke_suit_t directly, but 48 bits is actually
 * smaller than a 64 bit pointer, so that's grand, if odd:-)
 */
int OSSL_HPKE_enc_evp(OSSL_LIB_CTX *libctx,
                      unsigned int mode, ossl_hpke_suite_st suite,
                      char *pskid, size_t psklen, unsigned char *psk,
                      size_t publen, unsigned char *pub,
                      size_t authprivlen, unsigned char *authpriv,
                      EVP_PKEY *authpriv_evp,
                      size_t clearlen, unsigned char *clear,
                      size_t aadlen, unsigned char *aad,
                      size_t infolen, unsigned char *info,
                      size_t seqlen, unsigned char *seq,
                      size_t senderpublen, unsigned char *senderpub,
                      EVP_PKEY *senderpriv,
                      size_t *cipherlen, unsigned char *cipher)
{
    return hpke_enc_int(libctx, mode, suite,
                        pskid, psklen, psk,
                        publen, pub,
                        authprivlen, authpriv, authpriv_evp,
                        clearlen, clear,
                        aadlen, aad,
                        infolen, info,
                        seqlen, seq,
                        senderpublen, senderpub, senderpriv,
                        0, NULL,
                        0, NULL,
                        cipherlen, cipher);
}

/*
 * @brief HPKE single-shot decryption function
 *
 * @param libctx is the context to use (normally NULL)
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk
 * @param publen is the length of the public (authentication) key
 * @param pub is the encoded public (authentication) key
 * @param privlen is the length of the private key
 * @param priv is the encoded private key
 * @param evppriv is a pointer to an internal form of private key
 * @param enclen is the length of the peer's public value
 * @param enc is the peer's public value
 * @param cipherlen is the length of the ciphertext
 * @param cipher is the ciphertext
 * @param aadlen is the length of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the length of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param seqlen is the length of the sequence data (can be zero)
 * @param seq is the encoded sequence data (can be NULL)
 * @param clearlen length of the input buffer for cleartext
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_dec(OSSL_LIB_CTX *libctx,
                  unsigned int mode, ossl_hpke_suite_st suite,
                  char *pskid, size_t psklen, unsigned char *psk,
                  size_t publen, unsigned char *pub,
                  size_t privlen, unsigned char *priv,
                  EVP_PKEY *evppriv,
                  size_t enclen, unsigned char *enc,
                  size_t cipherlen, unsigned char *cipher,
                  size_t aadlen, unsigned char *aad,
                  size_t infolen, unsigned char *info,
                  size_t seqlen, unsigned char *seq,
                  size_t *clearlen, unsigned char *clear)
{
    return (hpke_dec_int(libctx, mode, suite,
                         pskid, psklen, psk,
                         publen, pub,
                         privlen, priv, evppriv,
                         enclen, enc,
                         cipherlen, cipher,
                         aadlen, aad,
                         infolen, info,
                         seqlen, seq,
                         clearlen, clear));
}

/*
 * @brief generate a key pair
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param ikmlen is the length of IKM, if supplied
 * @param ikm is IKM, if supplied
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_kg(OSSL_LIB_CTX *libctx,
                 unsigned int mode, ossl_hpke_suite_st suite,
                 size_t ikmlen, unsigned char *ikm,
                 size_t *publen, unsigned char *pub,
                 size_t *privlen, unsigned char *priv)
{
    return (hpke_kg(libctx, mode, suite, ikmlen, ikm,
                    publen, pub, privlen, priv));
}

/*
 * @brief generate a key pair but keep private inside API
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param ikmlen is the length of IKM, if supplied
 * @param ikm is IKM, if supplied
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key handle
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_kg_evp(OSSL_LIB_CTX *libctx,
                     unsigned int mode, ossl_hpke_suite_st suite,
                     size_t ikmlen, unsigned char *ikm,
                     size_t *publen, unsigned char *pub,
                     EVP_PKEY **priv)
{
    return (hpke_kg_evp(libctx, mode, suite, ikmlen, ikm, publen, pub, priv));
}

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not-1 otherwise
 */
int OSSL_HPKE_suite_check(ossl_hpke_suite_st suite)
{
    return (hpke_suite_check(suite));
}

/*
 * @brief: map a kem_id and a private key buffer into an EVP_PKEY
 *
 * @param libctx is the context to use (normally NULL)
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, otherwise failure
 *
 * Note that the buffer is expected to be some form of the PEM encoded
 * private key, but could still have the PEM header or not, and might
 * or might not be base64 encoded. We'll try handle all those options.
 */
int OSSL_HPKE_prbuf2evp(OSSL_LIB_CTX *libctx,
                        unsigned int kem_id,
                        unsigned char *prbuf,
                        size_t prbuf_len,
                        unsigned char *pubuf,
                        size_t pubuf_len,
                        EVP_PKEY **priv)
{
    return (hpke_prbuf2evp(libctx, kem_id, prbuf, prbuf_len, pubuf,
                           pubuf_len, priv));
}

/*
 * @brief get a (possibly) random suite, public key and ciphertext for GREASErs
 *
 * As usual buffers are caller allocated and lengths on input are buffer size.
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite_in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher is a random value of the appropriate length for a ciphertext
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_good4grease(OSSL_LIB_CTX *libctx,
                          ossl_hpke_suite_st *suite_in,
                          ossl_hpke_suite_st *suite,
                          unsigned char *pub,
                          size_t *pub_len,
                          unsigned char *cipher,
                          size_t cipher_len)
{
    return (hpke_good4grease(libctx, suite_in, suite,
                             pub, pub_len, cipher, cipher_len));
}

/*
 * @brief map a string to a HPKE suite
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_str2suite(char *str, ossl_hpke_suite_st *suite)
{
    return (hpke_str2suite(str, suite));
}

/*
 * @brief tell the caller how big the cipertext will be
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who know what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given
 * suite.
 *
 * @param suite is the suite to be used
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_expansion(ossl_hpke_suite_st suite,
                        size_t clearlen,
                        size_t *cipherlen)
{
    return (hpke_expansion(suite, clearlen, cipherlen));
}
