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
#include <openssl/hpke.h>
#include <openssl/err.h>

/* an error macro just to make things easier */
#define HPKE_err { ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR); erv = __LINE__; goto err; }


/*!
 * @brief info about an AEAD
 */
typedef struct {
    uint16_t            aead_id; /**< code point for aead alg */
    const EVP_CIPHER*   (*aead_init_func)(void); /**< the aead we're using */
    const char *name;   /* alg name */
    size_t              taglen; /**< aead tag len */
    size_t              Nk; /**< size of a key for this aead */
    size_t              Nn; /**< length of a nonce for this aead */
} hpke_aead_info_t;

/*!
 * @brief table of AEADs
 */
static hpke_aead_info_t hpke_aead_tab[] = {
    { 0, NULL, NULL, 0, 0, 0 }, /* keep indexing correct */
    { HPKE_AEAD_ID_AES_GCM_128, EVP_aes_128_gcm, "AES-128-GCM", 16, 16, 12 },
    { HPKE_AEAD_ID_AES_GCM_256, EVP_aes_256_gcm, "AES-256-GCM", 16, 32, 12 },
#ifndef OPENSSL_NO_CHACHA20
#ifndef OPENSSL_NO_POLY1305
    { HPKE_AEAD_ID_CHACHA_POLY1305, EVP_chacha20_poly1305,
        "chacha20-poly1305", 16, 32, 12 }
#endif
#endif
};


/*!
 * @brief info about a KEM
 */
typedef struct {
    uint16_t      kem_id; /**< code point for key encipherment method */
    const char    *keytype; /**< string form of algtype "EC"/"X25519"/"X448" */
    const char    *groupname; /**< string form of EC group for NIST curves  */
    int           groupid; /**< NID of KEM */
    const EVP_MD* (*hash_init_func)(void); /**< hash alg for the HKDF */
    size_t        Nsecret; /**< size of secrets */
    size_t        Nenc; /**< length of encapsulated key */
    size_t        Npk; /**< length of public key */
    size_t        Npriv; /**< length of raw private key */
} hpke_kem_info_t;

/*!
 * @brief table of KEMs
 *
 * Ok we're wasting space here, but not much and it's ok
 */
static hpke_kem_info_t hpke_kem_tab[] = {
    { 0, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 1, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 2, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 3, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 4, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 5, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 6, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 7, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 8, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { 9, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {10, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {11, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {12, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {13, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {14, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {15, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { HPKE_KEM_ID_P256,
      "EC", "P-256",
      NID_X9_62_prime256v1, EVP_sha256,
      32, 65, 65, 32 }, /* maybe "prime256v1" instead of P-256? */
    { HPKE_KEM_ID_P384,
      "EC", "P-384",
      NID_secp384r1, EVP_sha384,
      48, 97, 97, 48 },
    { HPKE_KEM_ID_P521,
      "EC", "P-521",
      NID_secp521r1, EVP_sha512,
      64, 133, 133, 66 },
    {19, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {20, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {21, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {22, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {23, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {24, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {25, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {26, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {27, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {28, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {29, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {30, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    {31, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
    { HPKE_KEM_ID_25519,
      "X25519", NULL,
      EVP_PKEY_X25519, EVP_sha256,
      32, 32, 32, 32 },
    { HPKE_KEM_ID_448,
      "X448", NULL,
      EVP_PKEY_X448, EVP_sha512,
      64, 56, 56, 56 },
    {34, NULL, NULL, 0, NULL, 0, 0, 0 }, /* keep indexing correct */
};



/*!
 * @brief info about a KDF
 */
typedef struct {
    uint16_t       kdf_id; /**< code point for KDF */
    const EVP_MD*  (*hash_init_func)(void); /**< the hash alg we're using */
    size_t         Nh; /**< length of hash/extract output */
} hpke_kdf_info_t;

/*!
 * @brief table of KDFs
 */
static hpke_kdf_info_t hpke_kdf_tab[] = {
    { 0, NULL, 0 }, /* keep indexing correct */
    { HPKE_KDF_ID_HKDF_SHA256, EVP_sha256, 32 },
    { HPKE_KDF_ID_HKDF_SHA384, EVP_sha384, 48 },
    { HPKE_KDF_ID_HKDF_SHA512, EVP_sha512, 64 }
};


static OSSL_LIB_CTX *hpke_libctx = NULL;



/*!
 * @brief Check if kem_id is ok/known to us
 * @param kem_id is the externally supplied kem_id
 * @return 1 for good, not 1 for error
 */
static int hpke_kem_id_check(uint16_t kem_id)
{
    switch (kem_id) {
        case HPKE_KEM_ID_P256:
        case HPKE_KEM_ID_P384:
        case HPKE_KEM_ID_P521:
        case HPKE_KEM_ID_25519:
        case HPKE_KEM_ID_448:
            break;
        default:
            return(__LINE__);
    }
    return(1);
}

/*!
 * @brief check if KEM uses NIST curve or not
 * @param kem_id is the externally supplied kem_id
 * @return 1 for NIST, 0 for good-but-non-NIST, other otherwise
 */
static int hpke_kem_id_nist_curve(uint16_t kem_id)
{
    if (hpke_kem_id_check(kem_id) != 1) return(__LINE__);
    if (kem_id >= 0x10 && kem_id < 0x20) return(1);
    return(0);
}

/*!
 * @brief hpke wrapper to import NIST curve public key as easily as x25519/x448
 * @param curve is the curve NID
 * @param buf is the binary buffer with the (uncompressed) public value
 * @param buflen is the length of the private key buffer
 * @return a working EVP_PKEY * or NULL
 */
static EVP_PKEY* hpke_EVP_PKEY_new_raw_nist_public_key(
        int curve,
        unsigned char *buf,
        size_t buflen)
{
    int erv = 1;
    EVP_PKEY *ret = NULL;
    /* following s3_lib.c:ssl_generate_param_group */
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (cctx == NULL) {
        HPKE_err;
    }
    if (EVP_PKEY_paramgen_init(cctx) <= 0) {
        HPKE_err;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(cctx, curve) <= 0) {
        HPKE_err;
    }
    if (EVP_PKEY_paramgen(cctx, &ret) <= 0) {
        HPKE_err;
    }
    if (EVP_PKEY_set1_encoded_public_key(ret, buf, buflen) != 1) {
        if (ret) EVP_PKEY_free(ret);
        ret = NULL;
        HPKE_err;
    }

err:
    if (cctx) EVP_PKEY_CTX_free(cctx);
    if (erv == 1) return(ret);
    else return NULL;
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

/*!
 * @brief do the AEAD decryption
 *
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
static int hpke_aead_dec(
            hpke_suite_t suite,
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
    size_t taglen = hpke_aead_tab[suite.aead_id].taglen;
    EVP_CIPHER *enc = NULL;

    plaintext = OPENSSL_malloc(cipherlen);
    if (plaintext == NULL) {
        HPKE_err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        HPKE_err;
    }
    /* Initialise the encryption operation */
    enc = EVP_CIPHER_fetch(hpke_libctx, hpke_aead_tab[suite.aead_id].name, 
            NULL);
    if (enc == NULL) {
        HPKE_err;
    }
    if(1 != EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        HPKE_err;
    }
    EVP_CIPHER_free(enc); enc = NULL;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL)) {
        HPKE_err;
    }
    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))  {
        HPKE_err;
    }
    /* 
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aadlen != 0 && aad != NULL) {
        if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen)) {
            HPKE_err;
        }
    }
    /* 
     * Provide the message to be decrypted, and obtain cleartext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher, cipherlen-taglen)) {
        HPKE_err;
    }
    plaintextlen = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx,
                EVP_CTRL_GCM_SET_TAG, taglen, cipher+cipherlen-taglen)) {
        HPKE_err;
    }
    /* Finalise decryption.  */
    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0)  {
        HPKE_err;
    }
    if (plaintextlen > *plainlen) {
        HPKE_err;
    }
    *plainlen = plaintextlen;
    memcpy(plain, plaintext, plaintextlen);

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (enc) EVP_CIPHER_free(enc);
    if (plaintext != NULL) OPENSSL_free(plaintext);
    return erv;
}

/*!
 * @brief do AEAD encryption as per the RFC
 *
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
static int hpke_aead_enc(
            hpke_suite_t   suite,
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
    size_t taglen = hpke_aead_tab[suite.aead_id].taglen;
    EVP_CIPHER *enc = NULL;
    unsigned char tag[16];

    if (taglen != 16) {
        HPKE_err;
    }
    if ((taglen + plainlen) > *cipherlen) {
        HPKE_err;
    }
    /*
     * Allocate this much extra for ciphertext and check the AEAD
     * doesn't require more - If it does, we'll fail.
     */
    ciphertext = OPENSSL_malloc(plainlen+taglen);
    if (ciphertext == NULL) {
        HPKE_err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        HPKE_err;
    }
    /* Initialise the encryption operation. */
    enc = EVP_CIPHER_fetch(hpke_libctx, hpke_aead_tab[suite.aead_id].name, NULL);
    if (enc == NULL) {
        HPKE_err;
    }
    if(1 != EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        HPKE_err;
    }
    EVP_CIPHER_free(enc); enc = NULL;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL)) {
        HPKE_err;
    }
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
        HPKE_err;
    }
    /* 
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aadlen != 0 && aad != NULL) {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen)) {
            HPKE_err;
        }
    }
    /* 
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plainlen)) {
        HPKE_err;
    }
    ciphertextlen = len;
    /* 
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  {
        HPKE_err;
    }
    ciphertextlen += len;
    /*
     * Get the tag This isn't a duplicate so needs to be added to the ciphertext
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag)) {
        HPKE_err;
    }
    memcpy(ciphertext+ciphertextlen, tag, taglen);
    ciphertextlen += taglen;
    if (ciphertextlen > *cipherlen) {
        HPKE_err;
    }
    *cipherlen = ciphertextlen;
    memcpy(cipher, ciphertext, ciphertextlen);

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (enc) EVP_CIPHER_free(enc);
    if (ciphertext != NULL) OPENSSL_free(ciphertext);
    return erv;
}

#define HPKE_VERLABEL        "HPKE-v1"  /**< version string label */
#define HPKE_SEC41LABEL      "KEM"      /**< "suite_id" label for 4.1 */
#define HPKE_SEC51LABEL      "HPKE"     /**< "suite_id" label for 5.1 */
#define HPKE_EAE_PRK_LABEL   "eae_prk"  /**< label in ExtractAndExpand */

#define HPKE_PSKIDHASH_LABEL "psk_id_hash"   /**< in key_schedule_context */
#define HPKE_INFOHASH_LABEL  "info_hash"     /**< in key_schedule_context */
#define HPKE_SS_LABEL        "shared_secret" /**< Yet another label */
#define HPKE_NONCE_LABEL     "base_nonce" /**< guess? */
#define HPKE_EXP_LABEL       "exp" /**< guess again? */
#define HPKE_KEY_LABEL       "key" /**< guess again? */
#define HPKE_PSK_HASH_LABEL  "psk_hash" /**< guess again? */
#define HPKE_SECRET_LABEL    "secret" /**< guess again? */

#define HPKE_5869_MODE_PURE   0 /**< Do "pure" RFC5869 */
#define HPKE_5869_MODE_KEM    1 /**< Abide by HPKE section 4.1 */
#define HPKE_5869_MODE_FULL   2 /**< Abide by HPKE section 5.1 */

/*!
 * @brief RFC5869 HKDF-Extract
 *
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
 * - HPKE_5869_MODE_PURE meaning to ignore all the
 *   HPKE-specific labelling and produce an output that's
 *   RFC5869 compliant (useful for testing and maybe
 *   more)
 * - HPKE_5869_MODE_KEM meaning to follow section 4.1
 *   where the suite_id is used as:
 *   concat("KEM", I2OSP(kem_id, 2))
 * - HPKE_5869_MODE_FULL meaning to follow section 5.1
 *   where the suite_id is used as:
 *     concat("HPKE", I2OSP(kem_id, 2),
 *          I2OSP(kdf_id, 2), I2OSP(aead_id, 2))
 *
 * Isn't that a bit of a mess!
 */
static int hpke_extract(
        const hpke_suite_t suite, const int mode5869,
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
    unsigned char labeled_ikmbuf[HPKE_MAXSIZE];
    unsigned char *labeled_ikm = labeled_ikmbuf;
    size_t labeled_ikmlen = 0;
    int erv = 1;
    size_t concat_offset = 0;
    size_t lsecretlen = 0;

    /* Handle oddities of HPKE labels (or not) */
    switch (mode5869) {
        case HPKE_5869_MODE_PURE:
            labeled_ikmlen = ikmlen;
            labeled_ikm = (unsigned char*)ikm;
            break;

        case HPKE_5869_MODE_KEM:
            concat_offset = 0;
            memcpy(labeled_ikm, HPKE_VERLABEL, strlen(HPKE_VERLABEL));
            concat_offset += strlen(HPKE_VERLABEL);
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset,
                    HPKE_SEC41LABEL, strlen(HPKE_SEC41LABEL));
            concat_offset += strlen(HPKE_SEC41LABEL);
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = (suite.kem_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = suite.kem_id % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset, label, labellen);
            concat_offset += labellen;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset, ikm, ikmlen);
            concat_offset += ikmlen;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikmlen = concat_offset;
            break;

        case HPKE_5869_MODE_FULL:
            concat_offset = 0;
            memcpy(labeled_ikm, HPKE_VERLABEL, strlen(HPKE_VERLABEL));
            concat_offset += strlen(HPKE_VERLABEL);
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset,
                    HPKE_SEC51LABEL, strlen(HPKE_SEC51LABEL));
            concat_offset += strlen(HPKE_SEC51LABEL);
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = (suite.kem_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = suite.kem_id%256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = (suite.kdf_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = suite.kdf_id%256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = (suite.aead_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikm[concat_offset] = suite.aead_id % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(labeled_ikm + concat_offset, label, labellen);
            concat_offset += labellen;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            if (ikmlen > 0) /* added 'cause asan test */
            memcpy(labeled_ikm + concat_offset, ikm, ikmlen);
            concat_offset += ikmlen;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            labeled_ikmlen = concat_offset;
            break;
        default:
            HPKE_err;
    }

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(hpke_libctx, "hkdf", NULL)) == NULL) {
        HPKE_err;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); /* The kctx keeps a reference so this is safe */
    kdf = NULL;
    if (kctx == NULL) {
        HPKE_err;
    }
    /* Build up the parameters for the derivation */
    if (mode5869 == HPKE_5869_MODE_KEM) {
        mdname = EVP_MD_get0_name(hpke_kem_tab[suite.kem_id].hash_init_func());
        if (!mdname) { HPKE_err; }
    } else {
        mdname = EVP_MD_get0_name(hpke_kdf_tab[suite.kdf_id].hash_init_func());
        if (!mdname) { HPKE_err; }
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)mdname, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (unsigned char*) labeled_ikm, labeled_ikmlen );
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
            (unsigned char*) salt, saltlen);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        HPKE_err;
    }
    lsecretlen = EVP_KDF_CTX_get_kdf_size(kctx);
    if (lsecretlen > *secretlen) {
        HPKE_err;
    }
    /* Do the derivation */
    if (EVP_KDF_derive(kctx, secret, lsecretlen, params) <= 0) {
        HPKE_err;
    }
    EVP_KDF_CTX_free(kctx); kctx = NULL;
    *secretlen = lsecretlen;

err:
    if (kdf != NULL) EVP_KDF_free(kdf);
    if (kctx != NULL) EVP_KDF_CTX_free(kctx);
    memset(labeled_ikmbuf, 0, HPKE_MAXSIZE);
    return erv;
}


/*!
 * @brief RFC5869 HKDF-Expand
 *
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
static int hpke_expand(const hpke_suite_t suite, const int mode5869,
                const unsigned char *prk, const size_t prklen,
                const char *label, const size_t labellen,
                const unsigned char *info, const size_t infolen,
                const uint32_t L,
                unsigned char *out, size_t *outlen)
{
    int erv = 1;
    unsigned char libuf[HPKE_MAXSIZE];
    unsigned char *lip = libuf;
    size_t concat_offset = 0;
    size_t loutlen = L;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;
    int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
    const char *mdname = NULL;

    if (L > *outlen) {
        HPKE_err;
    }
    /* Handle oddities of HPKE labels (or not) */
    switch (mode5869) {
        case HPKE_5869_MODE_PURE:
            if ((labellen+infolen) >= HPKE_MAXSIZE) { HPKE_err;}
            memcpy(lip, label, labellen);
            memcpy(lip + labellen, info, infolen);
            concat_offset = labellen + infolen;
            break;

        case HPKE_5869_MODE_KEM:
            lip[0] = (L / 256) % 256;
            lip[1] = L % 256;
            concat_offset = 2;
            memcpy(lip + concat_offset, HPKE_VERLABEL, strlen(HPKE_VERLABEL));
            concat_offset += strlen(HPKE_VERLABEL);
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, HPKE_SEC41LABEL,
                    strlen(HPKE_SEC41LABEL));
            concat_offset += strlen(HPKE_SEC41LABEL);
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = (suite.kem_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = suite.kem_id % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, label, labellen);
            concat_offset += labellen;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, info, infolen);
            concat_offset += infolen;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            break;

        case HPKE_5869_MODE_FULL:
            lip[0] = (L / 256) % 256;
            lip[1] = L % 256;
            concat_offset = 2;
            memcpy(lip + concat_offset, HPKE_VERLABEL, strlen(HPKE_VERLABEL));
            concat_offset += strlen(HPKE_VERLABEL);
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, HPKE_SEC51LABEL,
                    strlen(HPKE_SEC51LABEL));
            concat_offset += strlen(HPKE_SEC51LABEL);
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = (suite.kem_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = suite.kem_id % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = (suite.kdf_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = suite.kdf_id % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = (suite.aead_id / 256) % 256;
            concat_offset += 1;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            lip[concat_offset] = suite.aead_id % 256;
            concat_offset += 1;
            memcpy(lip + concat_offset, label, labellen);
            concat_offset += labellen;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            memcpy(lip + concat_offset, info, infolen);
            concat_offset += infolen;
            if (concat_offset >= HPKE_MAXSIZE) { HPKE_err; }
            break;

        default:
            HPKE_err;
    }

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(hpke_libctx, "hkdf", NULL)) == NULL) {
        HPKE_err;
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf); /* The kctx keeps a reference so this is safe */
    kdf = NULL;
    if (kctx == NULL) {
        HPKE_err;
    }
    /* Build up the parameters for the derivation */
    if (mode5869 == HPKE_5869_MODE_KEM) {
        mdname = EVP_MD_get0_name(hpke_kem_tab[suite.kem_id].hash_init_func());
        if (!mdname) { HPKE_err; }
    } else {
        mdname = EVP_MD_get0_name(hpke_kdf_tab[suite.kdf_id].hash_init_func());
        if (!mdname) { HPKE_err; }
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
            (char*)mdname, 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
            (unsigned char*) prk, prklen );
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
            libuf, concat_offset);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        HPKE_err;
    }
    /* Do the derivation */
    if (EVP_KDF_derive(kctx, out, loutlen, params) <= 0) {
        HPKE_err;
    }
    EVP_KDF_CTX_free(kctx); kctx = NULL;
    *outlen = loutlen;

err:
    if (kdf != NULL) EVP_KDF_free(kdf);
    if (kctx != NULL) EVP_KDF_CTX_free(kctx);
    memset(libuf, 0, HPKE_MAXSIZE);
    return erv;
}

/*!
 * @brief ExtractAndExpand
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
static int hpke_extract_and_expand(
					hpke_suite_t suite, int mode5869,
					unsigned char *shared_secret , size_t shared_secretlen,
					unsigned char *context, size_t contextlen,
					unsigned char *secret, size_t *secretlen
			)
{
	int erv = 1;
	unsigned char eae_prkbuf[HPKE_MAXSIZE];
    size_t eae_prklen = HPKE_MAXSIZE;
    size_t lsecretlen = hpke_kem_tab[suite.kem_id].Nsecret;

	erv = hpke_extract(suite, mode5869,
            (const unsigned char*)"", 0,
            HPKE_EAE_PRK_LABEL, strlen(HPKE_EAE_PRK_LABEL),
			shared_secret, shared_secretlen,
			eae_prkbuf, &eae_prklen);
	if (erv != 1) { goto err; }
    erv = hpke_expand(suite, mode5869,
            eae_prkbuf, eae_prklen,
            HPKE_SS_LABEL, strlen(HPKE_SS_LABEL),
            context, contextlen,
            lsecretlen,
            secret, &lsecretlen);
	if (erv != 1) { goto err; }
    *secretlen = lsecretlen;
err:
	memset(eae_prkbuf, 0, HPKE_MAXSIZE);
	return(erv);
}


/*!
 * @brief run the KEM with two keys as required
 *
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
static int hpke_do_kem(
        int encrypting, hpke_suite_t suite,
        EVP_PKEY *key1, size_t key1enclen, unsigned char *key1enc,
        EVP_PKEY *key2, size_t key2enclen, unsigned char *key2enc,
        EVP_PKEY *akey, size_t apublen, unsigned char *apub,
        unsigned char **ss, size_t *sslen)
{
    int erv = 1;
    EVP_PKEY_CTX *pctx = NULL;
    size_t zzlen = 2 * HPKE_MAXSIZE;
    unsigned char zz[2*HPKE_MAXSIZE];
    size_t kem_contextlen = HPKE_MAXSIZE;
    unsigned char kem_context[HPKE_MAXSIZE];
    size_t lsslen = HPKE_MAXSIZE;
    unsigned char lss[HPKE_MAXSIZE];

    /* step 2 run DH KEM to get zz */
    pctx = EVP_PKEY_CTX_new_from_pkey(hpke_libctx, key1, NULL);
    if (pctx == NULL) {
        HPKE_err;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        HPKE_err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0 ) {
        HPKE_err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &zzlen) <= 0) {
        HPKE_err;
    }
    if (zzlen >= HPKE_MAXSIZE) {
        HPKE_err;
    }
    if (EVP_PKEY_derive(pctx, zz, &zzlen) <= 0) {
        HPKE_err;
    }
    EVP_PKEY_CTX_free(pctx); pctx = NULL;

    kem_contextlen = key1enclen + key2enclen;
    if (kem_contextlen >= HPKE_MAXSIZE) {
        HPKE_err;
    }
    if (encrypting) {
        memcpy(kem_context, key1enc, key1enclen);
        memcpy(kem_context + key1enclen, key2enc, key2enclen);
    } else {
        memcpy(kem_context, key2enc, key2enclen);
        memcpy(kem_context + key2enclen, key1enc, key1enclen);
    }
    if (apublen != 0) {
        /* Append the public auth key (mypub) to kem_context */
        if ((kem_contextlen + apublen) >= HPKE_MAXSIZE) {
            HPKE_err;
        }
        memcpy(kem_context + kem_contextlen, apub, apublen);
        kem_contextlen += apublen;
    }

    if (akey != NULL) {
        size_t zzlen2 = 0;

        /* step 2 run to get 2nd half of zz */
        if (encrypting) {
            pctx = EVP_PKEY_CTX_new(akey, NULL);
        } else {
            pctx = EVP_PKEY_CTX_new(key1, NULL);
        }
        if (pctx == NULL) {
            HPKE_err;
        }
        if (EVP_PKEY_derive_init(pctx) <= 0 ) {
            HPKE_err;
        }
        if (encrypting) {
            if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0 ) {
                HPKE_err;
            }
        } else {
            if (EVP_PKEY_derive_set_peer(pctx, akey) <= 0 ) {
                HPKE_err;
            }
        }
        if (EVP_PKEY_derive(pctx, NULL, &zzlen2) <= 0) {
            HPKE_err;
        }
        if (zzlen2 >= HPKE_MAXSIZE) {
            HPKE_err;
        }
        if (EVP_PKEY_derive(pctx, zz+zzlen, &zzlen2) <= 0) {
            HPKE_err;
        }
        zzlen += zzlen2;
        EVP_PKEY_CTX_free(pctx); pctx = NULL;
    }

    erv = hpke_extract_and_expand(suite, HPKE_5869_MODE_KEM,
            zz, zzlen, kem_context, kem_contextlen, lss, &lsslen);
    if (erv != 1) { goto err; }
    *ss = OPENSSL_malloc(lsslen);
    if (*ss == NULL) {
        HPKE_err;
    }
    memcpy(*ss, lss, lsslen);
    *sslen = lsslen;

err:
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    return erv;
}


/*!
 * @brief check mode is in-range and supported
 * @param mode is the caller's chosen mode
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_mode_check(unsigned int mode)
{
    switch (mode) {
        case HPKE_MODE_BASE:
        case HPKE_MODE_PSK:
        case HPKE_MODE_AUTH:
        case HPKE_MODE_PSKAUTH:
            break;
        default:
            return(__LINE__);
    }
    return (1);
}

/*!
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
static int hpke_psk_check(
        unsigned int mode,
        char *pskid,
        size_t psklen,
        unsigned char *psk)
{
    if (mode == HPKE_MODE_BASE || mode == HPKE_MODE_AUTH) return(1);
    if (pskid == NULL) return(__LINE__);
    if (psklen == 0) return(__LINE__);
    if (psk == NULL) return(__LINE__);
    return(1);
}

/*!
 * @brief map a kem_id and a private key buffer into an EVP_PKEY
 *
 * Note that the buffer is expected to be some form of the encoded
 * private key, and could still have the PEM header or not, and might
 * or might not be base64 encoded. We'll try handle all those options.
 *
 * @param kem_id is what'd you'd expect (using the HPKE registry values)
 * @param prbuf is the private key buffer
 * @param prbuf_len is the length of that buffer
 * @param pubuf is the public key buffer (if available)
 * @param pubuf_len is the length of that buffer
 * @param priv is a pointer to an EVP_PKEY * for the result
 * @return 1 for success, otherwise failure
 */
static int hpke_prbuf2evp(
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

    keytype = hpke_kem_tab[kem_id].keytype;
    groupname = hpke_kem_tab[kem_id].groupname;
    if (prbuf == NULL || prbuf_len == 0 || retpriv == NULL) { HPKE_err; }
    if (hpke_kem_id_check(kem_id) != 1) { HPKE_err; }
    if (hpke_kem_tab[kem_id].Npriv == prbuf_len) {
        if (!keytype) { HPKE_err; }
        param_bld = OSSL_PARAM_BLD_new();
        if (!param_bld) { HPKE_err; }
        if (groupname != NULL &&
            OSSL_PARAM_BLD_push_utf8_string(param_bld,
                "group", groupname, 0) != 1) {
            HPKE_err;
        }
        if (pubuf && pubuf_len > 0) {
            if (OSSL_PARAM_BLD_push_octet_string(param_bld,
                        "pub", pubuf, pubuf_len) != 1) {
                HPKE_err;
            }
        }
        if (strlen(keytype) == 2 && !strcmp(keytype, "EC")) {
            priv = BN_bin2bn(prbuf, prbuf_len, NULL);
            if (!priv) {
                HPKE_err;
            }
            if (OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv) != 1) {
                HPKE_err;
            }
        } else {
            if (OSSL_PARAM_BLD_push_octet_string(param_bld,
                        "priv", prbuf, prbuf_len) != 1) {
                HPKE_err;
            }
        }
        params = OSSL_PARAM_BLD_to_param(param_bld);
        if (!params) {
            HPKE_err;
        }
        ctx = EVP_PKEY_CTX_new_from_name(hpke_libctx, keytype, NULL);
        if (ctx == NULL) {
            HPKE_err;
        }
        if (EVP_PKEY_fromdata_init(ctx) <= 0) {
            HPKE_err;
        }
        if (EVP_PKEY_fromdata(ctx, &lpriv, EVP_PKEY_KEYPAIR, params) <= 0) {
            HPKE_err;
        }
    }
    if (!lpriv) {
        /* check PEM decode - that might work :-) */
        BIO *bfp = BIO_new(BIO_s_mem());
        if (!bfp) { HPKE_err; }
        BIO_write(bfp, prbuf, prbuf_len);
        if (!PEM_read_bio_PrivateKey(bfp, &lpriv, NULL, NULL)) {
            BIO_free_all(bfp); bfp = NULL;
            HPKE_err;
        }
        if (bfp != NULL) {
            BIO_free_all(bfp); bfp = NULL;
        }
        if (!lpriv) {
            /* if not done, prepend/append PEM header/footer and try again */
            unsigned char hf_prbuf[HPKE_MAXSIZE];
            size_t hf_prbuf_len = 0;
#define PEM_PRIVATEHEADER "-----BEGIN PRIVATE KEY-----\n"
#define PEM_PRIVATEFOOTER "\n-----END PRIVATE KEY-----\n"
            memcpy(hf_prbuf, PEM_PRIVATEHEADER, strlen(PEM_PRIVATEHEADER));
            hf_prbuf_len += strlen(PEM_PRIVATEHEADER);
            memcpy(hf_prbuf + hf_prbuf_len, prbuf, prbuf_len);
            hf_prbuf_len += prbuf_len;
            memcpy(hf_prbuf + hf_prbuf_len, PEM_PRIVATEFOOTER,
                    strlen(PEM_PRIVATEFOOTER));
            hf_prbuf_len += strlen(PEM_PRIVATEFOOTER);
            bfp = BIO_new(BIO_s_mem());
            if (!bfp) { HPKE_err; }
            BIO_write(bfp, hf_prbuf, hf_prbuf_len);
            if (!PEM_read_bio_PrivateKey(bfp, &lpriv, NULL, NULL)) {
                BIO_free_all(bfp); bfp = NULL;
                HPKE_err;
            }
            if (bfp != NULL) {
                BIO_free_all(bfp); bfp = NULL;
            }
        }
    }
    if (!lpriv) { HPKE_err; }
    *retpriv = lpriv;
    if (priv) BN_free(priv);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (params) OSSL_PARAM_free(params);
    return(erv);

err:
    if (priv) BN_free(priv);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (param_bld) OSSL_PARAM_BLD_free(param_bld);
    if (params) OSSL_PARAM_free(params);
    return(erv);
}

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not 1 otherwise
 */
static int hpke_suite_check(hpke_suite_t suite)
{
    /*
     * Check that the fields of the suite are each
     * implemented here
     */
    int kem_ok = 0;
    int kdf_ok = 0;
    int aead_ok = 0;
    int ind = 0;
    int nkems = sizeof(hpke_kem_tab) / sizeof(hpke_kem_info_t);
    int nkdfs = sizeof(hpke_kdf_tab) / sizeof(hpke_kdf_info_t);
    int naeads = sizeof(hpke_aead_tab) / sizeof(hpke_aead_info_t);

    /* check KEM */
    for (ind = 0; ind != nkems; ind++) {
        if (suite.kem_id == hpke_kem_tab[ind].kem_id &&
            hpke_kem_tab[ind].hash_init_func != NULL) {
            kem_ok = 1;
            break;
        }
    }

    /* check kdf */
    for (ind = 0; ind != nkdfs; ind++) {
        if (suite.kdf_id == hpke_kdf_tab[ind].kdf_id &&
            hpke_kdf_tab[ind].hash_init_func != NULL) {
            kdf_ok = 1;
            break;
        }
    }

    /* check aead */
    for (ind = 0; ind != naeads; ind++) {
        if (suite.aead_id == hpke_aead_tab[ind].aead_id &&
            hpke_aead_tab[ind].aead_init_func != NULL) {
            aead_ok = 1;
            break;
        }
    }

    if (kem_ok == 1 && kdf_ok == 1 && aead_ok == 1) return(1);
    return(__LINE__);
}

/*!
 * @brief Internal HPKE single-shot encryption function
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
static int hpke_enc_int(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t authprivlen, unsigned char *authpriv, EVP_PKEY* authpriv_evp,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t seqlen, unsigned char *seq,
        size_t extsenderpublen, unsigned char *extsenderpub,
        EVP_PKEY *extsenderpriv,
        size_t rawsenderprivlen,  unsigned char *rawsenderpriv,
        size_t *senderpublen, unsigned char *senderpub,
        size_t *cipherlen, unsigned char *cipher
        )

{
    int erv = 1; /* Our error return value - 1 is success */
    int crv = 1;
    int arv = 1;
    int evpcaller = 0;
    int rawcaller = 0;
    /* declare vars - done early so goto err works ok */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkR = NULL;
    EVP_PKEY *pkE = NULL;
    EVP_PKEY *skI = NULL;
    size_t  shared_secretlen = 0;
    unsigned char *shared_secret = NULL;
    size_t  enclen = 0;
    unsigned char *enc = NULL;
    size_t  ks_contextlen = HPKE_MAXSIZE;
    unsigned char ks_context[HPKE_MAXSIZE];
    size_t  secretlen = HPKE_MAXSIZE;
    unsigned char secret[HPKE_MAXSIZE];
    size_t  psk_hashlen = HPKE_MAXSIZE;
    unsigned char psk_hash[HPKE_MAXSIZE];
    size_t  noncelen = HPKE_MAXSIZE;
    unsigned char nonce[HPKE_MAXSIZE];
    size_t  keylen = HPKE_MAXSIZE;
    unsigned char key[HPKE_MAXSIZE];
    size_t  exporterlen = HPKE_MAXSIZE;
    unsigned char exporter[HPKE_MAXSIZE];
    size_t  mypublen = 0;
    unsigned char *mypub = NULL;
    BIO *bfp = NULL;
    size_t halflen = 0;
    size_t pskidlen = 0;

    if ((crv = hpke_mode_check(mode)) != 1) return(crv);
    if ((crv = hpke_psk_check(mode, pskid, psklen, psk)) != 1) return(crv);
    if ((crv = hpke_suite_check(suite)) != 1) return(crv);
    /*
     * Depending on who called us, we may want to generate this key pair
     * or we may have had it handed to us via extsender* inputs
     */
    if (extsenderpublen > 0 && extsenderpub != NULL && extsenderpriv != NULL) {
        evpcaller = 1;
    }
    if (extsenderpublen > 0 && extsenderpub != NULL &&
            extsenderpriv == NULL && rawsenderprivlen > 0 &&
            rawsenderpriv != NULL) {
        rawcaller = 1;
    }
    if (!evpcaller && !rawcaller &&
        (!pub || !clear || !senderpublen || !senderpub ||
         !cipherlen  || !cipher)) return(__LINE__);
    if (evpcaller &&
        (!pub || !clear || !extsenderpublen || !extsenderpub ||
         !extsenderpriv || !cipherlen  || !cipher)) return(__LINE__);
    if (rawcaller &&
        (!pub || !clear || !extsenderpublen || !extsenderpub ||
         !rawsenderpriv || !cipherlen  || !cipher)) return(__LINE__);
    if ((mode == HPKE_MODE_AUTH || mode == HPKE_MODE_PSKAUTH) &&
        ((!authpriv || authprivlen == 0) && (!authpriv_evp))) return(__LINE__);
    if ((mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH) &&
        (!psk || psklen == 0 || !pskid)) return(__LINE__);

    /*
     * The plan:
     * 0. Initialise peer's key from string
     * 1. generate sender's key pair
     * 2. run DH KEM to get dh
     * 3. create context buffer
     * 4. extracts and expands as needed
     * 5. call the AEAD
     *
     * We'll follow the names used in the test vectors from the draft.
     * For now, we're replicating the setup from Appendix A.2
     */

    /* step 0. Initialise peer's key from string */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pkR = hpke_EVP_PKEY_new_raw_nist_public_key(
                hpke_kem_tab[suite.kem_id].groupid, pub, publen);
    } else {
        pkR = EVP_PKEY_new_raw_public_key_ex(hpke_libctx,
                hpke_kem_tab[suite.kem_id].keytype, NULL, pub, publen);
    }
    if (pkR == NULL) {
        HPKE_err;
    }

    /* step 1. generate or import sender's key pair: skE, pkE */
    if (!evpcaller && !rawcaller) {
        pctx = EVP_PKEY_CTX_new(pkR, NULL);
        if (pctx == NULL) {
            HPKE_err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            HPKE_err;
        }
        if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
            HPKE_err;
        }
        EVP_PKEY_CTX_free(pctx); pctx = NULL;
    } else if (evpcaller) {

        pkE = extsenderpriv;

    } else if (rawcaller) {

        if (hpke_prbuf2evp(suite.kem_id,
                    rawsenderpriv, rawsenderprivlen, NULL, 0, &pkE) != 1) {
            HPKE_err;
        }
        if (!pkE) { HPKE_err; }

    }

    /* step 2 run DH KEM to get dh */
    enclen = EVP_PKEY_get1_encoded_public_key(pkE, &enc);
    if (enc == NULL || enclen == 0) {
        HPKE_err;
    }

    /* load auth key pair if using an auth mode */
    if (mode == HPKE_MODE_AUTH || mode == HPKE_MODE_PSKAUTH) {
        if (authpriv_evp != NULL) {
            skI = authpriv_evp;
        } else {
            erv = hpke_prbuf2evp(suite.kem_id, authpriv, authprivlen,
                pub, publen, &skI);
            if (erv != 1) goto err;
        }

        if (!skI) {
            erv = __LINE__;goto err;
        }
        mypublen = EVP_PKEY_get1_encoded_public_key(skI, &mypub);
        if (mypub == NULL || mypublen == 0) {
            HPKE_err;
        }
    }

    erv = hpke_do_kem(1, suite, pkE, enclen, enc, pkR, publen, pub,
            skI, mypublen, mypub, &shared_secret, &shared_secretlen);
    if (erv != 1) goto err;
    if (mypub != NULL) { OPENSSL_free(mypub); mypub = NULL; }

    /* step 3. create context buffer */
    /* key_schedule_context */
    memset(ks_context, 0, HPKE_MAXSIZE);
    ks_context[0] = (unsigned char)(mode % 256); ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = (psk == NULL ? 0 : strlen(pskid));
    erv = hpke_extract(suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_PSKIDHASH_LABEL, strlen(HPKE_PSKIDHASH_LABEL),
                    (unsigned char*)pskid, pskidlen,
                    ks_context + 1, &halflen);
    if (erv != 1) goto err;
    ks_contextlen -= halflen;
    erv = hpke_extract(suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_INFOHASH_LABEL, strlen(HPKE_INFOHASH_LABEL),
                    (unsigned char*)info, infolen,
                    ks_context + 1 + halflen, &ks_contextlen);
    if (erv != 1) goto err;
    ks_contextlen += 1 + halflen;

    /* step 4. extracts and expands as needed */

    /* Extract secret and Expand variously...  */
    erv = hpke_extract(suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_PSK_HASH_LABEL, strlen(HPKE_PSK_HASH_LABEL),
                    psk, psklen,
                    psk_hash, &psk_hashlen);
    if (erv != 1) goto err;
    secretlen = hpke_kdf_tab[suite.kdf_id].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        HPKE_err;
    }
    if (hpke_extract(suite, HPKE_5869_MODE_FULL,
                    shared_secret, shared_secretlen,
                    HPKE_SECRET_LABEL, strlen(HPKE_SECRET_LABEL),
                    psk, psklen,
                    secret, &secretlen) != 1) {
        HPKE_err;
    }

    noncelen = hpke_aead_tab[suite.aead_id].Nn;
    if (hpke_expand(suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_NONCE_LABEL, strlen(HPKE_NONCE_LABEL),
                    ks_context, ks_contextlen,
                    noncelen, nonce, &noncelen) != 1) {
        HPKE_err;
    }
    if (noncelen != hpke_aead_tab[suite.aead_id].Nn) {
        HPKE_err;
    }

    /* XOR sequence with nonce as needed */
    if (seq != NULL && seqlen > 0) {
        size_t sind;
        if (seqlen > noncelen) {
            HPKE_err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            unsigned char cv;
            if (sind < seqlen) {
                cv = seq[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }

    keylen = hpke_aead_tab[suite.aead_id].Nk;
    if (hpke_expand(suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_KEY_LABEL, strlen(HPKE_KEY_LABEL),
                    ks_context, ks_contextlen,
                    keylen, key, &keylen) != 1) {
        HPKE_err;
    }
    exporterlen = hpke_kdf_tab[suite.kdf_id].Nh;
    if (hpke_expand(suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_EXP_LABEL, strlen(HPKE_EXP_LABEL),
                    ks_context, ks_contextlen,
                    exporterlen, exporter, &exporterlen) != 1) {
        HPKE_err;
    }

    /* step 5. call the AEAD */
    arv = hpke_aead_enc(
                suite,
                key, keylen,
                nonce, noncelen,
                aad, aadlen,
                clear, clearlen,
                cipher, cipherlen);
    if (arv != 1) {
        erv = arv; goto err;
    }
    /* finish up */
    if (!evpcaller && !rawcaller) {
        if (enclen > *senderpublen) {
            HPKE_err;
        }
        memcpy(senderpub, enc, enclen);
        *senderpublen = enclen;
    }

err:
    if (mypub != NULL) { OPENSSL_free(mypub); mypub = NULL; }
    if (bfp != NULL) BIO_free_all(bfp);
    if (pkR != NULL) EVP_PKEY_free(pkR);
    if (!evpcaller && pkE != NULL) EVP_PKEY_free(pkE);
    if (skI != NULL) EVP_PKEY_free(skI);
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    if (shared_secret != NULL) OPENSSL_free(shared_secret);
    if (enc != NULL) OPENSSL_free(enc);
    return erv;
}

/*!
 * @brief HPKE single-shot decryption function
 *
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
static int hpke_dec_int(
        unsigned int mode, hpke_suite_t suite,
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
    int crv = 1;
    int arv = 1;
    /* declare vars - done early so goto err works ok */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    EVP_PKEY *pkE = NULL;
    EVP_PKEY *pkI = NULL;
    size_t  shared_secretlen = 0;
    unsigned char *shared_secret = NULL;
    size_t  ks_contextlen = HPKE_MAXSIZE;
    unsigned char ks_context[HPKE_MAXSIZE];
    size_t  secretlen = HPKE_MAXSIZE;
    unsigned char secret[HPKE_MAXSIZE];
    size_t  noncelen = HPKE_MAXSIZE;
    unsigned char nonce[HPKE_MAXSIZE];
    size_t  psk_hashlen = HPKE_MAXSIZE;
    unsigned char psk_hash[HPKE_MAXSIZE];
    size_t  keylen = HPKE_MAXSIZE;
    unsigned char key[HPKE_MAXSIZE];
    size_t  exporterlen = HPKE_MAXSIZE;
    unsigned char exporter[HPKE_MAXSIZE];
    size_t  mypublen = 0;
    unsigned char *mypub = NULL;
    BIO *bfp = NULL;
    size_t halflen = 0;
    size_t pskidlen = 0;

    if ((crv = hpke_mode_check(mode)) != 1) return(crv);
    if ((crv = hpke_psk_check(mode, pskid, psklen, psk)) != 1) return(crv);
    if ((crv = hpke_suite_check(suite)) != 1) return(crv);
    if (!(priv || evppriv) || !clearlen || !clear || !cipher) return(__LINE__);
    if ((mode == HPKE_MODE_AUTH || mode == HPKE_MODE_PSKAUTH) &&
            (!authpub || authpublen == 0)) return(__LINE__);
    if ((mode == HPKE_MODE_PSK || mode == HPKE_MODE_PSKAUTH) &&
            (!psk || psklen == 0 || !pskid)) return(__LINE__);

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
        pkE = hpke_EVP_PKEY_new_raw_nist_public_key(
                hpke_kem_tab[suite.kem_id].groupid, enc, enclen);
    } else {
        pkE = EVP_PKEY_new_raw_public_key_ex(hpke_libctx,
                hpke_kem_tab[suite.kem_id].keytype, NULL , enc, enclen);
    }
    if (pkE == NULL) {
        HPKE_err;
    }
    if (authpublen != 0 && authpub != NULL) {
        if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
            pkI = hpke_EVP_PKEY_new_raw_nist_public_key(
                    hpke_kem_tab[suite.kem_id].groupid, authpub, authpublen);
        } else {
            pkI = EVP_PKEY_new_raw_public_key(
                    hpke_kem_tab[suite.kem_id].groupid, NULL,
                    authpub, authpublen);
        }
        if (pkI == NULL) {
            HPKE_err;
        }
    }

    /* step 1. load decryptors private key */
    if (!evppriv) {
        erv = hpke_prbuf2evp(suite.kem_id, priv, privlen, NULL, 0, &skR);
        if (erv != 1) goto err;
        if (!skR) {
            erv = __LINE__;goto err;
        }
    } else {
        skR = evppriv;
    }

    /* step 2 run DH KEM to get dh */
    mypublen = EVP_PKEY_get1_encoded_public_key(skR, &mypub);
    if (mypub == NULL || mypublen == 0) {
        HPKE_err;
    }

    erv = hpke_do_kem(0, suite, skR, mypublen, mypub, pkE, enclen, enc,
            pkI, authpublen, authpub, &shared_secret, &shared_secretlen);
    if (erv != 1) goto err;

    /* step 3. create context buffer */
    memset(ks_context, 0, HPKE_MAXSIZE);
    ks_context[0] = (unsigned char)(mode % 256); ks_contextlen--;
    halflen = ks_contextlen;
    pskidlen = (psk == NULL ? 0 : strlen(pskid));
    erv = hpke_extract(suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_PSKIDHASH_LABEL, strlen(HPKE_PSKIDHASH_LABEL),
                    (unsigned char*)pskid, pskidlen,
                    ks_context + 1, &halflen);
    if (erv != 1) goto err;
    ks_contextlen -= halflen;
    erv = hpke_extract(suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_INFOHASH_LABEL, strlen(HPKE_INFOHASH_LABEL),
                    info, infolen,
                    ks_context + 1 + halflen, &ks_contextlen);
    if (erv != 1) goto err;
    ks_contextlen += 1 + halflen;

    /* step 4. extracts and expands as needed */
    /* Extract secret and Expand variously...  */
    erv = hpke_extract(suite, HPKE_5869_MODE_FULL,
                    (const unsigned char*)"", 0,
                    HPKE_PSK_HASH_LABEL, strlen(HPKE_PSK_HASH_LABEL),
                    psk, psklen,
                    psk_hash, &psk_hashlen);
    if (erv != 1) goto err;
    secretlen = hpke_kdf_tab[suite.kdf_id].Nh;
    if (secretlen > SHA512_DIGEST_LENGTH) {
        HPKE_err;
    }
    if (hpke_extract(suite, HPKE_5869_MODE_FULL,
                    shared_secret, shared_secretlen,
                    HPKE_SECRET_LABEL, strlen(HPKE_SECRET_LABEL),
                    psk, psklen,
                    secret, &secretlen) != 1) {
        HPKE_err;
    }

    noncelen = hpke_aead_tab[suite.aead_id].Nn;
    if (hpke_expand(suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_NONCE_LABEL, strlen(HPKE_NONCE_LABEL),
                    ks_context, ks_contextlen,
                    noncelen, nonce, &noncelen) != 1) {
        HPKE_err;
    }
    if (noncelen != hpke_aead_tab[suite.aead_id].Nn) {
        HPKE_err;
    }

    /* XOR sequence with nonce as needed */
    if (seq != NULL && seqlen > 0) {
        size_t sind;
        if (seqlen > noncelen) {
            HPKE_err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != noncelen; sind++) {
            unsigned char cv;
            if (sind < seqlen) {
                cv = seq[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[noncelen - 1 - sind] ^= cv;
        }
    }

    keylen = hpke_aead_tab[suite.aead_id].Nk;
    if (hpke_expand(suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_KEY_LABEL, strlen(HPKE_KEY_LABEL),
                    ks_context, ks_contextlen,
                    keylen, key, &keylen) != 1) {
        HPKE_err;
    }
    exporterlen = hpke_kdf_tab[suite.kdf_id].Nh;
    if (hpke_expand(suite, HPKE_5869_MODE_FULL,
                    secret, secretlen,
                    HPKE_EXP_LABEL, strlen(HPKE_EXP_LABEL),
                    ks_context, ks_contextlen,
                    exporterlen, exporter, &exporterlen) != 1) {
        HPKE_err;
    }

    /* step 5. call the AEAD */
    arv = hpke_aead_dec(
                suite,
                key, keylen,
                nonce, noncelen,
                aad, aadlen,
                cipher, cipherlen,
                clear, clearlen);
    if (arv != 1) {
        erv = arv; goto err;
    }

err:
    if (bfp != NULL) BIO_free_all(bfp);
    if (skR != NULL && evppriv == NULL) EVP_PKEY_free(skR);
    if (pkE != NULL) EVP_PKEY_free(pkE);
    if (pkI != NULL) EVP_PKEY_free(pkI);
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    if (shared_secret != NULL) OPENSSL_free(shared_secret);
    if (mypub != NULL) OPENSSL_free(mypub);
    return erv;
}

/*!
 * @brief generate a key pair keeping private inside API
 *
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key pointer
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg_evp(
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        EVP_PKEY **priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    unsigned char *lpub = NULL;
    size_t lpublen = 0;

    if (hpke_suite_check(suite) != 1) return(__LINE__);
    if (!pub || !priv) return(__LINE__);
    /* step 1. generate sender's key pair */
    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (pctx == NULL) {
            HPKE_err;
        }
        if (1 != EVP_PKEY_paramgen_init(pctx)) {
            HPKE_err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            HPKE_err;
        }
        if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                    hpke_kem_tab[suite.kem_id].groupid)) {
            HPKE_err;
        }
    } else {
        pctx = EVP_PKEY_CTX_new_from_name(hpke_libctx,
                hpke_kem_tab[suite.kem_id].keytype, NULL);
        if (pctx == NULL) {
            HPKE_err;
        }
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            HPKE_err;
        }
    }
    if (EVP_PKEY_generate(pctx, &skR) <= 0) {
        HPKE_err;
    }
    EVP_PKEY_CTX_free(pctx); pctx = NULL;
    lpublen = EVP_PKEY_get1_encoded_public_key(skR, &lpub);
    if (lpub == NULL || lpublen == 0) {
        HPKE_err;
    }
    if (lpublen > *publen) {
        HPKE_err;
    }
    *publen = lpublen;
    memcpy(pub, lpub, lpublen);
    OPENSSL_free(lpub); lpub = NULL;
    *priv = skR;
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    if (lpub != NULL) OPENSSL_free(lpub);
    return(erv);

err:
    if (skR != NULL) EVP_PKEY_free(skR);
    if (pctx != NULL) EVP_PKEY_CTX_free(pctx);
    if (lpub != NULL) OPENSSL_free(lpub);
    return(erv);
}

/*!
 * @brief generate a key pair
 *
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg(
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        size_t *privlen, unsigned char *priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY *skR = NULL;
    BIO *bfp = NULL;
    unsigned char lpriv[HPKE_MAXSIZE];
    size_t lprivlen = 0;

    if (hpke_suite_check(suite) != 1) return(__LINE__);
    if (!pub || !priv) return(__LINE__);
    erv = hpke_kg_evp(mode, suite, publen, pub, &skR);
    if (erv != 1) {
        return(erv);
    }
    bfp = BIO_new(BIO_s_mem());
    if (!bfp) {
        HPKE_err;
    }
    if (!PEM_write_bio_PrivateKey(bfp, skR, NULL, NULL, 0, NULL, NULL)) {
        HPKE_err;
    }
    lprivlen = BIO_read(bfp, lpriv, HPKE_MAXSIZE);
    if (lprivlen <= 0) {
        HPKE_err;
    }
    if (lprivlen > *privlen) {
        HPKE_err;
    }
    *privlen = lprivlen;
    memcpy(priv, lpriv, lprivlen);

err:
    if (skR != NULL) EVP_PKEY_free(skR);
    if (bfp != NULL) BIO_free_all(bfp);
    return(erv);
}

/*!
 * @brief randomly pick a suite
 *
 * @param suite is the result
 * @return 1 for success, otherwise failure
 *
 * If you change the structure of the various *_tab arrays
 * then this code will also need change.
 */
static int hpke_random_suite(hpke_suite_t *suite)
{
    unsigned char rval = 0;
    int nkems = sizeof(hpke_kem_tab) / sizeof(hpke_kem_info_t);
    uint16_t nthkem = 0;
    uint16_t found = 0;
    int entry = 0;
    int nkdfs = sizeof(hpke_kdf_tab) / sizeof(hpke_kdf_info_t) - 1;
    int naeads = sizeof(hpke_aead_tab) / sizeof(hpke_aead_info_t) - 1;

    if (RAND_bytes(&rval, sizeof(rval)) <= 0) return(__LINE__);
    nthkem = (rval % 5 + 1); /* ok the "5" is magic!!! */
    while(found < nthkem && entry < nkems) {
        if (hpke_kem_tab[entry].keytype != NULL) {
            found++;
        }
        entry++;
    }
    suite->kem_id = hpke_kem_tab[entry-1].kem_id;

    /* check kdf */
    if (RAND_bytes(&rval, sizeof(rval)) <= 0) return(__LINE__);
    suite->kdf_id = hpke_kdf_tab[(rval % nkdfs + 1)].kdf_id;

    /* check aead */
    if (RAND_bytes(&rval, sizeof(rval)) <= 0) return(__LINE__);
    suite->aead_id = hpke_aead_tab[(rval % naeads + 1)].aead_id;
    return 1;
}

/*!
 * @brief return a (possibly) random suite, public key, ciphertext for GREASErs
 *
 * As usual buffers are caller allocated and lengths on input are buffer size.
 *
 * @param suite-in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher buffer with random value of the appropriate length
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
static int hpke_good4grease(
        hpke_suite_t *suite_in,
        hpke_suite_t suite,
        unsigned char *pub,
        size_t *pub_len,
        unsigned char *cipher,
        size_t cipher_len)
{
    hpke_suite_t chosen;
    int crv = 0;
    size_t plen = 0;

    if (!pub || !pub_len || !cipher || !cipher_len) return(__LINE__);
    if (suite_in == NULL) {
        /* choose a random suite */
        crv = hpke_random_suite(&chosen);
        if (crv != 1) return(crv);
    } else {
        chosen = *suite_in;
    }
    if ((crv = hpke_suite_check(chosen)) != 1) return(__LINE__);
    /* publen */
    plen = hpke_kem_tab[chosen.kem_id].Npk;
    if (plen > *pub_len) return(__LINE__);
    if (RAND_bytes(pub, plen) <= 0) return(__LINE__);
    *pub_len = plen;
    if (RAND_bytes(cipher, cipher_len) <= 0) return(__LINE__);
    return 1;
}


/*
 * @brief string matching for suites
 */
#if defined(_WIN32)
#define HPKE_MSMATCH(inp, known) \
    (strlen(inp) == strlen(known) && !_stricmp(inp, known))
#else
#define HPKE_MSMATCH(inp, known) \
    (strlen(inp) == strlen(known) && !strcasecmp(inp, known))
#endif

/*!
 * @brief map a string to a HPKE suite
 *
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
static int hpke_str2suite(char *suitestr, hpke_suite_t *suite)
{
    int erv = 0;
    uint16_t kem = 0, kdf = 0, aead = 0;
    char *st = NULL;
    if (!suite) return(__LINE__);
    /* See if it contains a mix of our strings and numbers  */
    st = strtok(suitestr, ",");
    if (!st) { erv = __LINE__; return erv; }
    while (st != NULL) {
        /* check if string is known or number and if so handle appropriately */
        if (kem == 0) {
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_P256)) kem = HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_P384)) kem = HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_P521)) kem = HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_X25519)) kem = HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st, HPKE_KEMSTR_X448)) kem = HPKE_KEM_ID_448;
            if (HPKE_MSMATCH(st, "0x10")) kem = HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st, "16")) kem = HPKE_KEM_ID_P256;
            if (HPKE_MSMATCH(st, "0x11")) kem = HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st, "17")) kem = HPKE_KEM_ID_P384;
            if (HPKE_MSMATCH(st, "0x12")) kem = HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st, "18")) kem = HPKE_KEM_ID_P521;
            if (HPKE_MSMATCH(st, "0x20")) kem = HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st, "32")) kem = HPKE_KEM_ID_25519;
            if (HPKE_MSMATCH(st, "0x21")) kem = HPKE_KEM_ID_448;
            if (HPKE_MSMATCH(st, "33")) kem = HPKE_KEM_ID_448;
        } else if (kem != 0 && kdf == 0) {
            if (HPKE_MSMATCH(st, HPKE_KDFSTR_256)) kdf = 1;
            if (HPKE_MSMATCH(st, HPKE_KDFSTR_384)) kdf = 2;
            if (HPKE_MSMATCH(st, HPKE_KDFSTR_512)) kdf = 3;
            if (HPKE_MSMATCH(st, "1")) kdf = 1;
            if (HPKE_MSMATCH(st, "2")) kdf = 2;
            if (HPKE_MSMATCH(st, "3")) kdf = 3;
        } else if (kem != 0 && kdf != 0 && aead == 0) {
            if (HPKE_MSMATCH(st, HPKE_AEADSTR_AES128GCM)) aead = 1;
            if (HPKE_MSMATCH(st, HPKE_AEADSTR_AES256GCM)) aead = 2;
            if (HPKE_MSMATCH(st, HPKE_AEADSTR_CP)) aead = 3;
            if (HPKE_MSMATCH(st, "1")) aead = 1;
            if (HPKE_MSMATCH(st, "2")) aead = 2;
            if (HPKE_MSMATCH(st, "3")) aead = 3;
        }
        st = strtok(NULL, ",");
    }
    if (kem == 0 || kdf == 0 || aead == 0) { erv = __LINE__; return erv; }
    suite->kem_id = kem;
    suite->kdf_id = kdf;
    suite->aead_id = aead;
#if 0
    /*
     * this line is only needed to avoid a complile error in a CI build
     * that sets -Werror=unused-but-set-parameter
     * TODO: See if this is still needed
     */
    if (suite->kem_id == 0 || suite->kdf_id == 0 || suite->aead_id == 0) {
        erv = __LINE__; return erv;
    }
#endif
    return 1;
}

/*!
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
static int hpke_expansion(hpke_suite_t suite,
        size_t clearlen,
        size_t *cipherlen)
{
    int crv = 0;
    size_t tlen = 0;
    if (!cipherlen) return __LINE__;
    if ((crv = hpke_suite_check(suite)) != 1) return(crv);
    tlen = hpke_aead_tab[suite.aead_id].taglen;
    *cipherlen = tlen + clearlen;
    return 1;
}

/*!
 * @brief set a non-default OSSL_LIB_CTX if needed
 * @param ctx is the context to set
 * @return 1 for success, otherwise failure
 */
static int hpke_setlibctx(OSSL_LIB_CTX *libctx)
{
    /*
     * This use to call OSSL_LIB_CTX_set0_default() but that caused some
     * *very* odd errors when this code was executed in the context of
     * the OpenSSL test harness in an undefined behaviour sanitizer build.
     * In the end, not calling the above (but without really understanding
     * the issue) is where we landed.
     */
    hpke_libctx = libctx;
    return(1);
}

/*
 * The same functions, but with "public" names that work for 
 * the OpenSSL project's naming conventions. Seems likely the
 * prototypes for these may change in discussion with project 
 * members, so initially, the implementations of these will be 
 * simple wrappers of the above. Once the prototypes seem ok, 
 * then we can zap the hpke_* variants and just go with the 
 * OSSL_HPKE_* ones.
 */

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
int OSSL_HPKE_enc(
        OSSL_LIB_CTX *libctx,
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t authprivlen, unsigned char *authpriv, EVP_PKEY *authpriv_evp,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t seqlen, unsigned char *seq,
        size_t *senderpublen, unsigned char *senderpub,
        size_t *cipherlen, unsigned char *cipher
        )
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return hpke_enc_int(mode, suite,
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
            cipherlen, cipher
           );
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
int OSSL_HPKE_enc_evp(
        OSSL_LIB_CTX *libctx,
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t authprivlen, unsigned char *authpriv, EVP_PKEY *authpriv_evp,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t seqlen, unsigned char *seq,
        size_t senderpublen, unsigned char *senderpub, EVP_PKEY *senderpriv,
        size_t *cipherlen, unsigned char *cipher
        )
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return hpke_enc_int(mode, suite,
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
            cipherlen, cipher
           );
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
int OSSL_HPKE_dec(
        OSSL_LIB_CTX *libctx,
        unsigned int mode, hpke_suite_t suite,
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
    if (libctx != NULL) hpke_setlibctx(libctx);
    return(hpke_dec_int(mode, suite,
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

/*!
 * @brief generate a key pair
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_kg(
        OSSL_LIB_CTX *libctx,
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        size_t *privlen, unsigned char *priv)
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return(hpke_kg(mode, suite, publen, pub, privlen, priv));
}

/*!
 * @brief generate a key pair but keep private inside API
 * @param libctx is the context to use (normally NULL)
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key handle
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_kg_evp(
        OSSL_LIB_CTX *libctx,
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        EVP_PKEY **priv)
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return(hpke_kg_evp(mode, suite, publen, pub, priv));
}

/**
 * @brief check if a suite is supported locally
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the suite to check
 * @return 1 for good/supported, not-1 otherwise
 */
int OSSL_HPKE_suite_check(
        OSSL_LIB_CTX *libctx,
        hpke_suite_t suite)
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return(hpke_suite_check(suite));
}

/*!
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
int OSSL_HPKE_prbuf2evp(
        OSSL_LIB_CTX *libctx,
        unsigned int kem_id,
        unsigned char *prbuf,
        size_t prbuf_len,
        unsigned char *pubuf,
        size_t pubuf_len,
        EVP_PKEY **priv)
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return(hpke_prbuf2evp(kem_id,prbuf,prbuf_len,pubuf,pubuf_len,priv));
}

/*!
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
int OSSL_HPKE_good4grease(
        OSSL_LIB_CTX *libctx,
        hpke_suite_t *suite_in,
        hpke_suite_t suite,
        unsigned char *pub,
        size_t *pub_len,
        unsigned char *cipher,
        size_t cipher_len)
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return(hpke_good4grease(suite_in, suite, pub, pub_len, cipher, cipher_len));
}

/*!
 * @brief map a string to a HPKE suite
 *
 * @param libctx is the context to use (normally NULL)
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_str2suite(
        OSSL_LIB_CTX *libctx,
        char *str, 
        hpke_suite_t *suite)
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return(hpke_str2suite(str, suite));
}

/*!
 * @brief tell the caller how big the cipertext will be
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who know what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given
 * suite.
 *
 * @param libctx is the context to use (normally NULL)
 * @param suite is the suite to be used
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_expansion(
        OSSL_LIB_CTX *libctx,
        hpke_suite_t suite,
        size_t clearlen,
        size_t *cipherlen)
{
    if (libctx != NULL) hpke_setlibctx(libctx);
    return(hpke_expansion(suite, clearlen, cipherlen));
}