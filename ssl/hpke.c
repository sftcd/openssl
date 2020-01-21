/*
 * Copyright 2019 Stephen Farrell. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file
 * An OpenSSL-based HPKE implementation following draft-irtf-cfrg-hpke
 *
 * I plan to use this for my ESNI-enabled OpenSSL build (https://github.com/sftcd/openssl)
 * when the time is right.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/params.h>

/*
 * If we're building standalone (from github.com/sftcd/happykey) then
 * include the former, if building from github.com/sftcd/openssl) then
 * the latter
 */
#ifdef HAPPYKEY
#include "hpke.h"
#else
#include <openssl/hpke.h>
#endif

#ifdef TESTVECTORS
#include "hpketv.h"
#endif

/*
 * Define this if you want loads printing of intermediate
 * cryptographic values
 */
#undef SUPERVERBOSE

#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
unsigned char *pbuf; ///< global var for debug printing
size_t pblen=1024; ///< global var for debug printing
#endif

/*
 * @brief table of mode strings
 */
const char *hpke_mode_strtab[]={
    HPKE_MODESTR_BASE,
    HPKE_MODESTR_PSK,
    HPKE_MODESTR_AUTH,
    HPKE_MODESTR_PSKAUTH};

/*!
 * @brief info about an AEAD
 */
typedef struct {
    uint16_t            aead_id; ///< code point for aead alg
    const EVP_CIPHER*   (*aead_init_func)(void); ///< the aead we're using
    size_t              taglen; ///< aead tag len
    size_t              Nk; ///< size of a key for this aead
    size_t              Nn; ///< length of a nonce for this aead
} hpke_aead_info_t;

/*!
 * @brief table of AEADs
 */
hpke_aead_info_t hpke_aead_tab[]={
    { 0, NULL, 0, 0, 0 }, // this is needed to keep indexing correct
    { HPKE_AEAD_ID_AES_GCM_128, EVP_aes_128_gcm, 16, 16, 12 }, 
    { HPKE_AEAD_ID_AES_GCM_256, EVP_aes_256_gcm, 16, 32, 12 }, 
    { HPKE_AEAD_ID_CHACHA_POLY1305, EVP_chacha20_poly1305, 16, 32, 12 } 
};

/*
 * @brief table of AEAD strings
 */
const char *hpke_aead_strtab[]={
    NULL,
    HPKE_AEADSTR_AES128GCM,
    HPKE_AEADSTR_AES256GCM,
    HPKE_AEADSTR_CP};


/*!
 * @brief info about a KEM
 */
typedef struct {
    uint16_t            kem_id; ///< code point for key encipherment method
    int                 groupid; ///< NID of KEM
    size_t              Nenc; ///< length of encapsulated key
    size_t              Npk; ///< length of public key
    size_t              Npriv; ///< length of raw private key
} hpke_kem_info_t;

/*!
 * @brief table of KEMs
 */
hpke_kem_info_t hpke_kem_tab[]={
    { 0, 0, 0, 0 }, // this is needed to keep indexing correct
    //{ HPKE_KEM_ID_P256, NID_secp256k1, 32, 32 },
    { HPKE_KEM_ID_P256, NID_X9_62_prime256v1, 65, 65, 32 },
    { HPKE_KEM_ID_25519, EVP_PKEY_X25519, 32, 32, 32 },
    { HPKE_KEM_ID_P521, NID_secp521r1, 133, 133, 66 },
    { HPKE_KEM_ID_448, EVP_PKEY_X448, 56, 56, 56 } 
};

/*
 * @brief table of KEM strings
 */
const char *hpke_kem_strtab[]={
    NULL,
    HPKE_KEMSTR_P256,
    HPKE_KEMSTR_X25519,
    HPKE_KEMSTR_P521,
    HPKE_KEMSTR_X448};

/*!
 * @brief info about a KDF
 */
typedef struct {
    uint16_t            kdf_id; ///< code point for KDF
    const EVP_MD*       (*hash_init_func)(void); ///< the hash alg we're using
    size_t              Nh; ///< length of hash/extract output
} hpke_kdf_info_t;

/*!
 * @brief table of KDFs
 */
hpke_kdf_info_t hpke_kdf_tab[]={
    { 0, NULL, 0 }, // this is needed to keep indexing correct
    { HPKE_KDF_ID_HKDF_SHA256, EVP_sha256, 32 },
    { HPKE_KDF_ID_HKDF_SHA512, EVP_sha512, 64 }
};

/*
 * @brief table of KDF strings
 */
const char *hpke_kdf_strtab[]={
    NULL,
    HPKE_KDFSTR_256,
    HPKE_KDFSTR_512};

/**
 * handy thing to have :-)
 */
static const unsigned char zero_buf[SHA512_DIGEST_LENGTH] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/*!
 * <pre>
 * Since I always have to reconstruct this again in my head...
 * Bash command line hashing starting from ascii hex example:
 *
 *    $ echo -e "4f6465206f6e2061204772656369616e2055726e" | xxd -r -p | openssl sha256
 *    (stdin)= 55c4040629c64c5efec2f7230407d612d16289d7c5d7afcf9340280abd2de1ab
 *
 * The above generates the Hash(info) used in Appendix A.2
 *
 * If you'd like to regenerate the zero_sha256 value above, feel free
 *    $ echo -n "" | openssl sha256 
 *    echo -n "" | openssl sha256
 *    (stdin)= e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 * Or if you'd like to re-caclulate the sha256 of nothing...
 *  SHA256_CTX sha256;
 *  SHA256_Init(&sha256);
 *  char* buffer = NULL;
 *  int bytesRead = 0;
 *  SHA256_Update(&sha256, buffer, bytesRead);
 *  SHA256_Final(zero_sha256, &sha256);
 * ...but I've done it for you, so no need:-)
 * static const unsigned char zero_sha256[SHA256_DIGEST_LENGTH] = {
 *     0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 
 *     0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 
 *     0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 
 *     0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
 * </pre>
 */

/*!
 * @brief decode ascii hex to a binary buffer
 *
 * @param ahlen is the ascii hex string length
 * @param ah is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return 1 for good otherwise bad
 */
int hpke_ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf)
{
    size_t lblen=0;
    unsigned char *lbuf=NULL;
    if (ahlen <=0 || ah==NULL || blen==NULL || buf==NULL) {
        return 0;
    }
    if (ahlen%1) {
        return 0;
    }
    lblen=ahlen/2;
    lbuf=OPENSSL_malloc(lblen);
    if (lbuf==NULL) {
        return 0;
    }
    int i=0;
    for (i=0;i!=lblen;i++) {
        lbuf[i]=HPKE_A2B(ah[2*i])*16+HPKE_A2B(ah[2*i+1]);
    }
    *blen=lblen;
    *buf=lbuf;
    return 1;
}

#if defined(SUPERVERBOSE) || defined(TESTVECTORS)
/*!
 * @brief for odd/occasional debugging
 *
 * @param fout is a FILE * to use
 * @param msg is prepended to print
 * @param buf is the buffer to print
 * @param blen is the length of the buffer
 * @return 1 for success 
 */
static int hpke_pbuf(FILE *fout, char *msg,unsigned char *buf,size_t blen) 
{
    if (!fout) {
        return 0;
    } 
    if (!msg) {
        fprintf(fout,"NULL msg:");
    } else {
        fprintf(fout,"%s: ",msg);
    }
    if (!buf) {
        fprintf(fout,"buf is NULL, so probably something wrong\n");
        return 1;
    }
    if (blen==HPKE_MAXSIZE) {
        fprintf(fout,"length is HPKE_MAXSIZE, so probably unused\n");
        return 1;
    } 
    if (blen==0) {
        fprintf(fout,"length is 0, so probably something wrong\n");
        return 1;
    }
    int i;
    for (i=0;i!=blen;i++) {
        fprintf(fout,"%02x",buf[i]);
    }
    fprintf(fout,"\n");
    return 1;
}
#endif

/*!
 * @brief Check if ciphersuite is ok/known to us
 * @param suite is the externally supplied cipheruite
 * @return 1 for good, not-1 for error
 */
static int hpke_suite_check(hpke_suite_t suite)
{
    if (suite.kem_id>HPKE_KEM_ID_MAX) return(__LINE__);
    if (suite.kdf_id>HPKE_KDF_ID_MAX) return(__LINE__);
    if (suite.aead_id>HPKE_AEAD_ID_MAX) return(__LINE__);
    return(1);
}

/*!
 * @brief return the length of the context for this suite
 * @param suite is the ciphersuite to use
 * @return the length (in octets) of the context 
 */
static size_t figure_contextlen(hpke_suite_t suite)
{
    /*
     * From the I-D:
     *  struct {
     *  // Mode and algorithms
     *  uint8 mode;
     *  uint16 kem_id;
     *  uint16 kdf_id;
     *  uint16 aead_id;
     *
     *  // Public inputs to this key exchange
     *  opaque enc[Nenc];
     *  opaque pkR[Npk];
     *  opaque pkI[Npk];
     *
     *  // Cryptographic hash of application-supplied pskID
     *  opaque pskID_hash[Nh];
     *
     *  // Cryptographic hash of application-supplied info
     *  opaque info_hash[Nh];
     * } HPKEContext;
     *
     * Note that the lengths in hpke_kem_tab are not the same
     * as in the I-D - the test vectors and this code use
     * uncompressed form NIST curve values, so that's 65 for
     * p256 and not 33 or 32.
     */
    size_t ans=
        7+hpke_kem_tab[suite.kem_id].Nenc+
        2*hpke_kem_tab[suite.kem_id].Npk+
        2*hpke_kdf_tab[suite.kdf_id].Nh;
    return(ans);
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
 * @param plainlen is an input/output, better be big enough on input, exact on output
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
    int erv=1;
    EVP_CIPHER_CTX *ctx=NULL;
    int len=0;
    size_t plaintextlen=0;
    unsigned char *plaintext=NULL;
    size_t taglen=hpke_aead_tab[suite.aead_id].taglen;
    plaintext=OPENSSL_malloc(cipherlen);
    if (plaintext==NULL) {
        erv=__LINE__; goto err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        erv=__LINE__; goto err;
    }
    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc = hpke_aead_tab[suite.aead_id].aead_init_func();
    if (enc == NULL) {
        erv=__LINE__; goto err;
    }
    if(1 != EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        erv=__LINE__; goto err;
    }
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL)) {
        erv=__LINE__; goto err;
    }
    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))  {
        erv=__LINE__; goto err;
    }
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aadlen!=0 && aad!=NULL) {
        if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen)) {
            erv=__LINE__; goto err;
        }
    }
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher, cipherlen-taglen)) {
        erv=__LINE__; goto err;
    }
    plaintextlen = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, taglen, cipher+cipherlen-taglen)) {
        erv=__LINE__; goto err;
    }
    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0)  {
        erv=__LINE__; goto err;
    }

    /* Clean up */
    if (plaintextlen>*plainlen) {
        erv=__LINE__; goto err;
    }
    *plainlen=plaintextlen;
    memcpy(plain,plaintext,plaintextlen);
err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (plaintext!=NULL) OPENSSL_free(plaintext);
    return erv;
    return(0);
}

/*!
 * @brief do the AEAD encryption as per the I-D
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
 * @param cipherlen is an input/output, better be big enough on input, exact on output
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
    int erv=1;
    EVP_CIPHER_CTX *ctx=NULL;
    int len;
    size_t ciphertextlen;
    unsigned char *ciphertext=NULL;
    size_t taglen=hpke_aead_tab[suite.aead_id].taglen;
    unsigned char tag[taglen];
    if (taglen+plainlen>*cipherlen) {
        erv=__LINE__; goto err;
    }
    /*
     * We'll allocate this much extra for ciphertext and check the AEAD doesn't require more
     * If it does, we'll fail.
     */
    ciphertext=OPENSSL_malloc(plainlen+taglen);
    if (ciphertext==NULL) {
        erv=__LINE__; goto err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        erv=__LINE__; goto err;
    }
    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc = hpke_aead_tab[suite.aead_id].aead_init_func();
    if (enc == NULL) {
        erv=__LINE__; goto err;
    }
    if(1 != EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        erv=__LINE__; goto err;
    }
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL)) {
        erv=__LINE__; goto err;
    }
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
        erv=__LINE__; goto err;
    }
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (aadlen!=0 && aad!=NULL) {
        if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen)) {
            erv=__LINE__; goto err;
        }
    }
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plainlen)) {
        erv=__LINE__; goto err;
    }
    ciphertextlen = len;
    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  {
        erv=__LINE__; goto err;
    }
    ciphertextlen += len;
    /*
     * Get the tag This isn't a duplicate so needs to be added to the ciphertext
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag)) {
        erv=__LINE__; goto err;
    }
    memcpy(ciphertext+ciphertextlen,tag,taglen);
    ciphertextlen += taglen;
    /* Clean up */
    if (ciphertextlen>*cipherlen) {
        erv=__LINE__; goto err;
    }
    *cipherlen=ciphertextlen;
    memcpy(cipher,ciphertext,ciphertextlen);
err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (ciphertext!=NULL) OPENSSL_free(ciphertext);
    return erv;

}


/*!
 * brief RFC5869 HKDF-Extract
 *
 * @param suite is the ciphersuite 
 * @param salt - surprisingly this is the salt;-)
 * @param saltlen - length of above
 * @param zz - the initial key material (IKM)
 * @param zzlen - length of above
 * @param secret - the result of extraction (allocated inside)
 * @param secretlen - an input only!
 * @return 1 for good otherwise bad
 */
static int hpke_extract(
        hpke_suite_t suite,
        const unsigned char *salt, const size_t saltlen,
        const unsigned char *zz, const size_t zzlen,
        unsigned char **secret, const size_t secretlen)
{
    EVP_PKEY_CTX *pctx=NULL;
    int erv=1;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_init(pctx)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, hpke_kdf_tab[suite.kdf_id].hash_init_func())!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, zz, zzlen)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen)!=1) {
        erv=__LINE__; goto err;
    }
    *secret=OPENSSL_malloc(secretlen);
    if (!secret) {
        erv=__LINE__; goto err;
    }
    size_t lsecretlen=secretlen;
    if (EVP_PKEY_derive(pctx, *secret, &lsecretlen)!=1) {
        erv=__LINE__; goto err;
    }
    if (lsecretlen!=secretlen) { /* just in case it changed */
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;
err:
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    return erv;
}

/*!
 * brief RFC5869 HKDF-Expand
 *
 * @param suite is the ciphersuite 
 * @param secret - the initial key material (IKM)
 * @param secretlen - length of above
 * @param label - label to prepend to info
 * @param context - the info
 * @param contextlen - length of above
 * @param out - the result of expansion (allocated inside)
 * @param outlen - an input only!
 * @return 1 for good otherwise bad
 */
static int hpke_expand(hpke_suite_t suite, unsigned char *secret, size_t secretlen,
                char *label, unsigned char *context, size_t contextlen,
                unsigned char **out, size_t outlen)
{
    EVP_PKEY_CTX *pctx=NULL;
    int erv=1;
    unsigned char *clbuf=NULL;
    size_t clbuflen;
    size_t lablen=0;

    if (label) lablen=strlen(label);

    clbuflen=contextlen+lablen;
    clbuf=OPENSSL_malloc(clbuflen);
    if (!clbuf) {
        erv=__LINE__; goto err;
    }
    if (label) memcpy(clbuf,label,lablen);
    memcpy(clbuf+lablen,context,contextlen);

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_init(pctx)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, hpke_kdf_tab[suite.kdf_id].hash_init_func())!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen)!=1) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, clbuf, clbuflen)!=1) {
        erv=__LINE__; goto err;
    }
    *out=OPENSSL_malloc(outlen);
    if (!out) {
        erv=__LINE__; goto err;
    }
    size_t loutlen=outlen; /* just in case it changes */
    if (EVP_PKEY_derive(pctx, *out, &loutlen)!=1) {
        erv=__LINE__; goto err;
    }
    if (loutlen!=outlen) {
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;
err:
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    if (clbuf!=NULL) OPENSSL_free(clbuf);
    return erv;
}

#ifdef TESTVECTORS
/*!
 * @brief specific test for epxand/extract
 *
 * This uses the test vectors from https://tools.ietf.org/html/rfc5869
 * I added this as my expand is not agreeing with the HPKE test vectors.
 * All being well, this should be silent.
 * 
 * @return 1 for good, otherwise bad 
 */
static int hpke_test_expand_extract(void)
{
    /*
     * RFC 5869 Test Case 1:
     * Hash = SHA-256
     * IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
     * salt = 0x000102030405060708090a0b0c (13 octets)
     * info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
     * L    = 42
     * 
     * PRK  = 0x077709362c2e32df0ddc3f0dc47bba63
     *        90b6c73bb50f9c3122ec844ad7c2b3e5 (32 octets)
     * OKM  = 0x3cb25f25faacd57a90434f64d0362f2a
     *        2d2d0a90cf1a5a4c5db02d56ecc4c5bf
     *        34007208d5b887185865 (42 octets)
     */
    unsigned char IKM[22]={0x0b,0x0b,0x0b,0x0b,
                           0x0b,0x0b,0x0b,0x0b,
                           0x0b,0x0b,0x0b,0x0b,
                           0x0b,0x0b,0x0b,0x0b,
                           0x0b,0x0b,0x0b,0x0b,
                           0x0b,0x0b}; 
    size_t IKMlen=22;
    unsigned char salt[13]={0x00,0x01,0x02,0x03,
                            0x04,0x05,0x06,0x07,
                            0x08,0x09,0x0a,0x0b,
                            0x0c}; 
    size_t saltlen=13;
    unsigned char info[10]={0xf0,0xf1,0xf2,0xf3,
                            0xf4,0xf5,0xf6,0xf7,
                            0xf8,0xf9}; 
    size_t infolen=10;
    unsigned char PRK[32]={ 0x07,0x77,0x09,0x36,
                            0x2c,0x2e,0x32,0xdf,
                            0x0d,0xdc,0x3f,0x0d,
                            0xc4,0x7b,0xba,0x63,
                            0x90,0xb6,0xc7,0x3b,
                            0xb5,0x0f,0x9c,0x31,
                            0x22,0xec,0x84,0x4a,
                            0xd7,0xc2,0xb3,0xe5};
    size_t PRKlen=32;
    unsigned char OKM[42]={ 0x3c,0xb2,0x5f,0x25,
                            0xfa,0xac,0xd5,0x7a,
                            0x90,0x43,0x4f,0x64,
                            0xd0,0x36,0x2f,0x2a,
                            0x2d,0x2d,0x0a,0x90,
                            0xcf,0x1a,0x5a,0x4c,
                            0x5d,0xb0,0x2d,0x56,
                            0xec,0xc4,0xc5,0xbf,
                            0x34,0x00,0x72,0x08,
                            0xd5,0xb8,0x87,0x18,
                            0x58,0x65 }; /* 42 octets */
    size_t OKMlen=42;
    unsigned char *calc_prk;
    unsigned char *calc_okm;
    int rv=1;
    hpke_suite_t suite=HPKE_SUITE_DEFAULT;
    rv=hpke_extract(suite,salt,saltlen,IKM,IKMlen,&calc_prk,PRKlen);
    if (rv!=1) {
        printf("rfc5869 check: hpke_extract failed: %d\n",rv);
        printf("rfc5869 check: hpke_extract failed: %d\n",rv);
        printf("rfc5869 check: hpke_extract failed: %d\n",rv);
        printf("rfc5869 check: hpke_extract failed: %d\n",rv);
        printf("rfc5869 check: hpke_extract failed: %d\n",rv);
        printf("rfc5869 check: hpke_extract failed: %d\n",rv);
    }
    if (memcmp(calc_prk,PRK,PRKlen)) {
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
        printf("rfc5869 check: hpke_extract gave wrong answer!\n");
    }
    OPENSSL_free(calc_prk);
    rv=hpke_expand(suite,PRK,PRKlen,"",info,infolen,&calc_okm,OKMlen);
    if (rv!=1) {
        printf("rfc5869 check: hpke_expand failed: %d\n",rv);
        printf("rfc5869 check: hpke_expand failed: %d\n",rv);
        printf("rfc5869 check: hpke_expand failed: %d\n",rv);
        printf("rfc5869 check: hpke_expand failed: %d\n",rv);
        printf("rfc5869 check: hpke_expand failed: %d\n",rv);
        printf("rfc5869 check: hpke_expand failed: %d\n",rv);
    }
    if (memcmp(calc_okm,OKM,OKMlen)) {
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
        printf("rfc5869 check: hpke_expand gave wrong answer!\n");
    }
    OPENSSL_free(calc_okm);


    return(rv);
}
#endif

/*!
 * @brief run the KEM with two keys 
 *
 * @param key1 is the first key, for which we have the private value
 * @param key2 is the peer's key
 * @param zz is (a pointer to) the buffer for the result
 * @param zzlen is the size of the buffer (octets-used on exit)
 * @return 1 for good, not-1 for not good
 */
static int hpke_do_kem(EVP_PKEY *key1, EVP_PKEY *key2, 
                   unsigned char **zz, size_t *zzlen)
{
    int erv=1;
    EVP_PKEY_CTX *pctx=NULL;

    /* step 2 run DH KEM to get zz */
    pctx = EVP_PKEY_CTX_new(key1,NULL);
    if (pctx == NULL) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, key2) <= 0 ) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive(pctx, NULL, zzlen) <= 0) {
        erv=__LINE__; goto err;
    }
    *zz=OPENSSL_malloc(*zzlen);
    if (*zz == NULL) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_derive(pctx, *zz, zzlen) <= 0) {
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;
err:
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    return erv;
}

/*!
 * @brief make it easier to do repetitive code
 */
#define CHECK_HPKE_CTX if ((cp-*context)>*contextlen) { erv=__LINE__; goto err; }

/*
 * @brief say if mode is authenticated or not
 */
#define ISAUTHMODE(xxmode) (xxmode==HPKE_MODE_AUTH || xxmode==HPKE_MODE_PSKAUTH)

/*
 * @brief say if mode has a PRK or not
 */
#define ISPSKMODE(xxmode) (xxmode==HPKE_MODE_PSK || xxmode==HPKE_MODE_PSKAUTH)

/*!
 * @brief Create context for input to extract/expand
 *
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param enc is the sender public key
 * @param enclen is the length of the sender public key
 * @param pub is the encoded recipient public key
 * @param publen is the length of the recipient public key
 * @param pkI_hash is the hash of the sender's authentication key (or NULL)
 * @param pkI_hashlen is the length of the pkI_hash
 * @param pskid is a PSK ID string (can be NULL)
 * @param info is buffer of info to bind
 * @param infolen is the length of the buffer of info
 * @param context is a buffer for the resulting context
 * @param contextlen is the size of the buffer and octets-used on exit
 * @return 1 for good, not 1 otherwise
 */
static int hpke_make_context(
            int mode, hpke_suite_t suite,
            const unsigned char *enc, const size_t enclen,
            const unsigned char *pub, const size_t publen,
            const unsigned char *pkI_hash, const size_t pkI_hashlen,
            const char *pskid,
            const unsigned char *info, const size_t infolen,
            unsigned char **context, size_t *contextlen) 
{
    int erv=1;
    *contextlen=figure_contextlen(suite);
    /* allocate space incl. some o/h just in case */
    *context=OPENSSL_malloc(*contextlen+1024);
    if (*context==NULL) {
        erv=__LINE__; goto err;
    }
    memset(*context,0,*contextlen);
    unsigned char *cp=*context;
    *cp++=mode; CHECK_HPKE_CTX;
    *cp++=(suite.kem_id&0xff00)>>8; *cp++=(suite.kem_id&0xff);  CHECK_HPKE_CTX;
    *cp++=(suite.kdf_id&0xff00)>>8; *cp++=(suite.kdf_id&0xff);  CHECK_HPKE_CTX;
    *cp++=(suite.aead_id&0xff00)>>8; *cp++=(suite.aead_id&0xff); 
    memcpy(cp,enc,enclen); cp+=enclen; CHECK_HPKE_CTX
    memcpy(cp,pub,publen); cp+=publen; CHECK_HPKE_CTX;

    if (!ISAUTHMODE(mode) || pkI_hash==NULL) {
        memset(cp,0,hpke_kem_tab[suite.kem_id].Npk); cp+= hpke_kem_tab[suite.kem_id].Npk; CHECK_HPKE_CTX;
    } else {
        memcpy(cp,pkI_hash,pkI_hashlen); cp+=pkI_hashlen; CHECK_HPKE_CTX;
    }
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int md_len;
    const EVP_MD *md=hpke_kdf_tab[suite.kdf_id].hash_init_func();
    EVP_DigestInit_ex(mdctx, md, NULL);
    if (!ISPSKMODE(mode) || pskid==NULL) {
        EVP_DigestUpdate(mdctx, NULL, 0);
    } else {
        EVP_DigestUpdate(mdctx, pskid, strlen(pskid));
    }
    EVP_DigestFinal_ex(mdctx, cp, &md_len);cp+=md_len; CHECK_HPKE_CTX;
    EVP_DigestInit_ex(mdctx, md, NULL);
    if (info==NULL) {
        EVP_DigestUpdate(mdctx, NULL, 0);
    } else {
        EVP_DigestUpdate(mdctx, info, infolen);
    }
    EVP_DigestFinal_ex(mdctx, cp, &md_len);cp+=md_len; CHECK_HPKE_CTX;
    EVP_MD_CTX_free(mdctx);

err:
    return erv;
}


/*!
 * @brief check mode is in-range and supported
 * @param mode is the caller's chosen mode
 * @return 1 for good (OpenSSL style), not-1 for error
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
 * @return 1 for good (OpenSSL style), not-1 for error
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
    if (mode==HPKE_MODE_BASE || mode==HPKE_MODE_AUTH) return(1);
    if (pskid==NULL) return(__LINE__);
    if (psklen==0) return(__LINE__);
    if (psk==NULL) return(__LINE__);
    return(1);
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
    int erv=1;
    EVP_PKEY *ret=NULL;
    // following s3_lib.c:ssl_generate_param_group
    EVP_PKEY_CTX *cctx=EVP_PKEY_CTX_new_id(EVP_PKEY_EC,NULL);
    if (cctx==NULL) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_paramgen_init(cctx) <= 0) {
        EVP_PKEY_CTX_free(cctx);
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(cctx, curve) <= 0) {
        EVP_PKEY_CTX_free(cctx);
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_paramgen(cctx, &ret) <= 0) {
        EVP_PKEY_CTX_free(cctx);
        erv=__LINE__; goto err;
    }
    // For some reason this returns zero for p256 but works!
    EVP_PKEY_set1_tls_encodedpoint(ret,buf,buflen);
    //if (!EVP_PKEY_set1_tls_encodedpoint(pkR,pub,publen)) {
        //erv=__LINE__; goto err;
    //}
 
err:
#ifdef SUPERVERBOSE
    pblen = EVP_PKEY_get1_tls_encodedpoint(ret,&pbuf); 
    hpke_pbuf(stdout,"EARLY public",pbuf,pblen); 
    if (pblen) OPENSSL_free(pbuf);
#endif
    if (cctx) EVP_PKEY_CTX_free(cctx);
    if (erv==1) return(ret);
    else return NULL;
}

/*!
 * @brief hpke wrapper to import NIST curve private key as easily as x25519/x448
 * @param curve is the curve NID
 * @param buf is the binary buffer with the private value
 * @param buflen is the length of the private key buffer
 * @return a working EVP_PKEY * or NULL
 *
 * Loadsa malarky required as it turns out...
 * You gotta: 1) name group 2) import private 3) then
 * manually re-calc public key before 4) make an EVP_PKEY
 */
static EVP_PKEY* hpke_EVP_PKEY_new_raw_nist_private_key(
        int curve,
        unsigned char *buf,
        size_t buflen) 
{
    int erv=1;
    EVP_PKEY *ret=NULL;
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(curve);
    if (!ec_key) { erv=__LINE__; goto err; }
    EC_POINT* pub_key = NULL;
    const EC_GROUP* generator = EC_KEY_get0_group(ec_key);
    if (!generator) { erv=__LINE__; goto err; }
    pub_key = EC_POINT_new(generator);
    if (1!=EC_KEY_oct2priv(ec_key, buf, buflen)) {
        erv=__LINE__; goto err; 
    }
    if (1!=EC_POINT_mul(generator, pub_key, EC_KEY_get0_private_key(ec_key), NULL, NULL, NULL)) {
        erv=__LINE__; goto err; 
    }
    if (1!=EC_KEY_set_public_key(ec_key, pub_key)) {
        erv=__LINE__; goto err; 
    }
    ret = EVP_PKEY_new();
    if (!ret) { erv=__LINE__; goto err; }
    if (1!=EVP_PKEY_assign_EC_KEY(ret, ec_key)) {
        erv=__LINE__; goto err; 
    }

err:
#ifdef SUPERVERBOSE
    pblen = EVP_PKEY_get1_tls_encodedpoint(ret,&pbuf); 
    hpke_pbuf(stdout,"EARLY re-calc public",pbuf,pblen); 
    if (pblen) OPENSSL_free(pbuf);
    pblen=EC_KEY_priv2buf(ec_key,&pbuf);
    hpke_pbuf(stdout,"EARLY private",pbuf,pblen); 
#endif

    if (pub_key) EC_POINT_free(pub_key);
    if (erv==1) return(ret);
    else return NULL;
}

/*!
 * @brief HPKE single-shot encryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite to use
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk 
 * @param publen is the length of the recipient public key
 * @param pub is the encoded recipient public key
 * @param privlen is the length of the private (authentication) key
 * @param priv is the encoded private (authentication) key
 * @param clearlen is the length of the cleartext
 * @param clear is the encoded cleartext
 * @param aadlen is the lenght of the additional data (can be zero)
 * @param aad is the encoded additional data (can be NULL)
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param senderpublen is the length of the input buffer for the sender's public key (length used on output)
 * @param senderpub is the input buffer for ciphertext
 * @param cipherlen is the length of the input buffer for ciphertext (length used on output)
 * @param cipher is the input buffer for ciphertext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_enc(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        size_t clearlen, unsigned char *clear,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t *senderpublen, unsigned char *senderpub,
        size_t *cipherlen, unsigned char *cipher
#ifdef TESTVECTORS
        , void *tv
#endif
        )
{
    int crv=1;
    if ((crv=hpke_mode_check(mode))!=1) return(crv);
    if ((crv=hpke_psk_check(mode,pskid,psklen,psk))!=1) return(crv);
    if ((crv=hpke_suite_check(suite))!=1) return(crv);

    if (!pub || !clear || !senderpublen || !senderpub || !cipherlen  || !cipher) return(__LINE__);
    if ((mode==HPKE_MODE_AUTH || mode==HPKE_MODE_PSKAUTH) && (!priv || privlen==0)) return(__LINE__);
    if ((mode==HPKE_MODE_PSK || mode==HPKE_MODE_PSKAUTH) && (!psk || psklen==0 || !pskid)) return(__LINE__);

    int erv=1; /* Our error return value - 1 is success */
#ifdef TESTVECTORS
    hpke_tv_t *ltv=(hpke_tv_t*)tv;
#endif

    /*
     * The plan:
     * 0. Initialise peer's key from string
     * 1. generate sender's key pair
     * 2. run DH KEM to get zz
     * 3. create context buffer
     * 4. extracts and expands as needed
     * 5. call the AEAD 
     *
     * We'll follow the names used in the test vectors from the draft.
     * For now, we're replicating the setup from Appendix A.2
     */

    /* declare vars - done early so goto err works ok */
    EVP_PKEY_CTX *pctx=NULL;
    EVP_PKEY *pkR=NULL;
    EVP_PKEY *pkE=NULL;
    EVP_PKEY *skI=NULL;
    size_t  zzlen=0;
    unsigned char *zz=NULL;
    size_t  enclen=0;
    unsigned char *enc=NULL;
    size_t  contextlen=0;
    unsigned char *context=NULL;
    size_t  secretlen=0;
    unsigned char *secret=NULL;
    size_t  keylen=0;
    unsigned char *key=NULL;
    size_t  noncelen=0;
    unsigned char *nonce=NULL;
    size_t pkI_buflen=0;
    unsigned char *pkI_buf=NULL;
    BIO *bfp=NULL;

    /* step 0. Initialise peer's key from string */
    if (suite.kem_id%2) {
        pkR = hpke_EVP_PKEY_new_raw_nist_public_key(hpke_kem_tab[suite.kem_id].groupid,pub,publen);
    } else {
        pkR = EVP_PKEY_new_raw_public_key(hpke_kem_tab[suite.kem_id].groupid,NULL,pub,publen);
    }
    if (pkR == NULL) {
        erv=__LINE__; goto err;
    }

    /* step 1. generate sender's key pair */
    pctx = EVP_PKEY_CTX_new(pkR, NULL);
    if (pctx == NULL) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        erv=__LINE__; goto err;
    }
#ifdef TESTVECTORS
    if (ltv) {
        /*
         * Read DH private from tv, then use that instead of 
         * a newly generated key pair
         */
        if (ltv->kemID>HPKE_KEM_ID_MAX) return(__LINE__);
        unsigned char *bin_skE=NULL;
        size_t bin_skElen=0;
        if (1!=hpke_ah_decode(strlen(ltv->skE),ltv->skE,&bin_skElen,&bin_skE)) { 
            erv=__LINE__; goto err; 
        }
        if (ltv->kemID%2) {
            pkE = hpke_EVP_PKEY_new_raw_nist_private_key(hpke_kem_tab[ltv->kemID].groupid,bin_skE,bin_skElen);
        } else {
            pkE = EVP_PKEY_new_raw_private_key(hpke_kem_tab[ltv->kemID].groupid,NULL,bin_skE,bin_skElen);
        }
        if (!pkE) { erv=__LINE__; goto err; }
        OPENSSL_free(bin_skE);

    } else  
#endif
    if (EVP_PKEY_keygen(pctx, &pkE) <= 0) {
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;

    /* step 2 run DH KEM to get zz */
    erv=hpke_do_kem(pkE,pkR,&zz,&zzlen);
    if (erv!=1) {
        goto err;
    }

    /* get 2nd half of zz if using an auth mode */
    if (mode==HPKE_MODE_AUTH||mode==HPKE_MODE_PSKAUTH) {
        if (hpke_kem_tab[suite.kem_id].Npriv==privlen) {
            if (suite.kem_id%2) {
                skI = hpke_EVP_PKEY_new_raw_nist_private_key(hpke_kem_tab[suite.kem_id].groupid,priv,privlen);
            } else {
                skI=EVP_PKEY_new_raw_private_key(hpke_kem_tab[suite.kem_id].groupid,NULL,priv,privlen);
            }
        }
        /* 
         * we'll fall through to this test even if the above was
         * tried and failed
         */
        if (!skI) {
            /* check PEM decode - that might work :-) */
            bfp=BIO_new(BIO_s_mem());
            if (!bfp) {
                erv=__LINE__; goto err;
            }
            BIO_write(bfp,priv,privlen);
            if (!PEM_read_bio_PrivateKey(bfp,&skI,NULL,NULL)) {
                erv=__LINE__; goto err;
            }
        }

        /* step 2.5 run DH KEM again to get 2nd half of zz */
        unsigned char *zz2=NULL;
        size_t zzlen2=0;
        erv=hpke_do_kem(skI,pkR,&zz2,&zzlen2);
        if (erv!=1) {
            goto err;
        }
        unsigned char *zzboth=OPENSSL_malloc(zzlen+zzlen2);
        if (!zzboth) {
            OPENSSL_free(zz2);
            erv=__LINE__; goto err;
        }
        memcpy(zzboth,zz,zzlen);
        memcpy(zzboth+zzlen,zz2,zzlen2);
        OPENSSL_free(zz2);
        OPENSSL_free(zz);
        zz=zzboth;
        zzlen=zzlen+zzlen2;

        /* set the public part of skI to be included in context */
        pkI_buflen=EVP_PKEY_get1_tls_encodedpoint(skI,&pkI_buf); 
    } 

    /* step 3. create context buffer */

    enclen = EVP_PKEY_get1_tls_encodedpoint(pkE,&enc);
    if (enc==NULL || enclen == 0) {
        erv=__LINE__; goto err;
    }
    erv=hpke_make_context(mode,suite,
            enc,enclen,
            pub,publen,
            pkI_buf,pkI_buflen,
            pskid,
            info,infolen,
            &context,&contextlen);

    /* step 4. extracts and expands as needed */
#ifdef TESTVECTORS
    hpke_test_expand_extract();
#endif
    /*
     * secret = Extract(psk, zz)
     * unless otherwise specified psk is 32 octets of zero
     */
    size_t IKM_len=hpke_kdf_tab[suite.kdf_id].Nh;
    if (IKM_len>SHA512_DIGEST_LENGTH) {
        erv=__LINE__; goto err;
    }
    const unsigned char *IKM=zero_buf;
    if (mode==HPKE_MODE_PSK || mode==HPKE_MODE_PSKAUTH) {
        IKM=psk;
        IKM_len=psklen;
    }
    secretlen=hpke_kdf_tab[suite.kdf_id].Nh;
    if (hpke_extract(suite,IKM,IKM_len,zz,zzlen,&secret,secretlen)!=1) {
        erv=__LINE__; goto err;
    }
    /*
     * key = Expand(secret, concat("hpke key", context), Nk)
    */
    keylen=hpke_aead_tab[suite.aead_id].Nk;
    if (hpke_expand(suite,secret,secretlen,"hpke key",context,contextlen,&key,keylen)!=1) {
        erv=__LINE__; goto err;
    }
    /*
     * nonce = Expand(secret, concat("hpke nonce", context), Nn)
    */
    noncelen=12;
    if (hpke_expand(suite,secret,secretlen,"hpke nonce",context,contextlen,&nonce,noncelen)!=1) {
        erv=__LINE__; goto err;
    }

    /* step 5. call the AEAD */
    size_t lcipherlen=HPKE_MAXSIZE;
    unsigned char lcipher[HPKE_MAXSIZE];
    int arv=hpke_aead_enc(
                suite,
                key,keylen,
                nonce,noncelen,
                aad,aadlen,
                clear,clearlen,
                lcipher,&lcipherlen);
    if (arv!=1) {
        erv=arv; goto err;
    }
    if (lcipherlen > *cipherlen) {
        erv=__LINE__; goto err;
    }
    /* 
     * finish up
     */
    memcpy(cipher,lcipher,lcipherlen);
    *cipherlen=lcipherlen;
    if (enclen>*senderpublen) {
        erv=__LINE__; goto err;
    }
    memcpy(senderpub,enc,enclen);
    *senderpublen=enclen;

#ifdef WASTESTVECTORS
    /*
     * print stuff
     */
    if (ltv) {
        printf("Runtime:\n");
        printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
                hpke_mode_strtab[mode],mode,
                hpke_kem_strtab[suite.kem_id],suite.kem_id,
                hkpe_kdf_strtab[suite.kdf_id], suite.kdf_id,
                hpke_aead_strtab[suite.aead_id], suite.aead_id);
        pblen = EVP_PKEY_get1_tls_encodedpoint(pkR,&pbuf); hpke_pbuf(stdout,"\tpkR",pbuf,pblen); if (pblen) OPENSSL_free(pbuf);
        pblen = EVP_PKEY_get1_tls_encodedpoint(pkE,&pbuf); hpke_pbuf(stdout,"\tpkE",pbuf,pblen); if (pblen) OPENSSL_free(pbuf);
        if (mode==HPKE_MODE_AUTH || mode==HPKE_MODE_PSKAUTH) {
            pblen = EVP_PKEY_get1_tls_encodedpoint(skI,&pbuf); hpke_pbuf(stdout,"\tpkI",pbuf,pblen); if (pblen) OPENSSL_free(pbuf);
        }
        hpke_pbuf(stdout,"\tzz",zz,zzlen);
        hpke_pbuf(stdout,"\tenc",enc,enclen);
        hpke_pbuf(stdout,"\tinfo",info,infolen);
        hpke_pbuf(stdout,"\tcontext",context,contextlen);
        hpke_pbuf(stdout,"\tsecret",secret,secretlen);
        hpke_pbuf(stdout,"\tnonce",nonce,noncelen);
        hpke_pbuf(stdout,"\tkey",key,keylen);
        hpke_pbuf(stdout,"\tplaintext",clear,clearlen);
        hpke_pbuf(stdout,"\taad",aad,aadlen);
        hpke_pbuf(stdout,"\tciphertext",cipher,*cipherlen);
        if (mode==HPKE_MODE_PSK || mode==HPKE_MODE_PSKAUTH) {
            fprintf(stdout,"\tpskid: %s\n",pskid);
            hpke_pbuf(stdout,"\tpsk",psk,psklen);
        }
    }
#endif

err:

#if defined(SUPERVERBOSE) || defined(TESTVECTORS)

#ifdef TESTVECTORS
    if (ltv) {
#endif
    printf("Encrypting:\n");
    printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
                hpke_mode_strtab[mode],mode,
                hpke_kem_strtab[suite.kem_id],suite.kem_id,
                hpke_kdf_strtab[suite.kdf_id], suite.kdf_id,
                hpke_aead_strtab[suite.aead_id], suite.aead_id);

    if (pkE) { 
        pblen = EVP_PKEY_get1_tls_encodedpoint(pkE,&pbuf); 
        hpke_pbuf(stdout,"\tpkE",pbuf,pblen); 
        if (pblen) OPENSSL_free(pbuf); 
    } else { 
        fprintf(stdout,"\tpkE is NULL\n"); 
    }
    if (pkR) { 
        pblen = EVP_PKEY_get1_tls_encodedpoint(pkR,&pbuf); 
        hpke_pbuf(stdout,"\tpkR",pbuf,pblen); 
        if (pblen) OPENSSL_free(pbuf); 
    } else { 
        fprintf(stdout,"\tpkR is NULL\n"); 
    }
    if (skI) { 
        pblen = EVP_PKEY_get1_tls_encodedpoint(skI,&pbuf); 
        hpke_pbuf(stdout,"\tskI",pbuf,pblen); 
        if (pblen) OPENSSL_free(pbuf); 
    } else { 
        fprintf(stdout,"\tskI is NULL\n"); 
    }
    hpke_pbuf(stdout,"\tzz",zz,zzlen);
    hpke_pbuf(stdout,"\tcontext",context,contextlen);
    hpke_pbuf(stdout,"\tsecret",secret,secretlen);
    hpke_pbuf(stdout,"\tenc",enc,enclen);
    hpke_pbuf(stdout,"\tinfo",info,infolen);
    hpke_pbuf(stdout,"\taad",aad,aadlen);
    hpke_pbuf(stdout,"\tnonce",nonce,noncelen);
    hpke_pbuf(stdout,"\tkey",key,keylen);
    hpke_pbuf(stdout,"\tcleartext",clear,clearlen);
    hpke_pbuf(stdout,"\tciphertext",cipher,*cipherlen);
    if (mode==HPKE_MODE_PSK || mode==HPKE_MODE_PSKAUTH) {
        fprintf(stdout,"\tpskid: %s\n",pskid);
        hpke_pbuf(stdout,"\tpsk",psk,psklen);
    }
#ifdef TESTVECTORS
    }
#endif
#endif

    if (bfp!=NULL) BIO_free_all(bfp);
    if (pkR!=NULL) EVP_PKEY_free(pkR);
    if (pkE!=NULL) EVP_PKEY_free(pkE);
    if (skI!=NULL) EVP_PKEY_free(skI);
    if (pkI_buf!=NULL) OPENSSL_free(pkI_buf);
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    if (zz!=NULL) OPENSSL_free(zz);
    if (enc!=NULL) OPENSSL_free(enc);
    if (context!=NULL) OPENSSL_free(context);
    if (secret!=NULL) OPENSSL_free(secret);
    if (key!=NULL) OPENSSL_free(key);
    if (nonce!=NULL) OPENSSL_free(nonce);
    return erv;
}

/*!
 * @brief HPKE single-shot decryption function
 * @param mode is the HPKE mode
 * @param suite is the ciphersuite 
 * @param pskid is the pskid string fpr a PSK mode (can be NULL)
 * @param psklen is the psk length
 * @param psk is the psk 
 * @param publen is the length of the public (authentication) key
 * @param pub is the encoded public (authentication) key
 * @param privlen is the length of the private key
 * @param priv is the encoded private key
 * @param enclen is the length of the peer's public value
 * @param enc is the peer's public value
 * @param cipherlen is the length of the ciphertext 
 * @param cipher is the ciphertext
 * @param aadlen is the lenght of the additional data
 * @param aad is the encoded additional data
 * @param infolen is the lenght of the info data (can be zero)
 * @param info is the encoded info data (can be NULL)
 * @param clearlen is the length of the input buffer for cleartext (octets used on output)
 * @param clear is the encoded cleartext
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_dec(
        unsigned int mode, hpke_suite_t suite,
        char *pskid, size_t psklen, unsigned char *psk,
        size_t publen, unsigned char *pub,
        size_t privlen, unsigned char *priv,
        size_t enclen, unsigned char *enc,
        size_t cipherlen, unsigned char *cipher,
        size_t aadlen, unsigned char *aad,
        size_t infolen, unsigned char *info,
        size_t *clearlen, unsigned char *clear)
{
    int crv=1;
    if ((crv=hpke_mode_check(mode))!=1) return(crv);
    if ((crv=hpke_psk_check(mode,pskid,psklen,psk))!=1) return(crv);
    if ((crv=hpke_suite_check(suite))!=1) return(crv);

    if (!priv || !clearlen || !clear || !cipher) return(__LINE__);
    if ((mode==HPKE_MODE_AUTH || mode==HPKE_MODE_PSKAUTH) && (!pub || publen==0)) return(__LINE__);
    if ((mode==HPKE_MODE_PSK || mode==HPKE_MODE_PSKAUTH) && (!psk || psklen==0 || !pskid)) return(__LINE__);

    int erv=1;

    /*
     * The plan:
     * 0. Initialise peer's key from string
     * 1. load decryptors private key
     * 2. run DH KEM to get zz
     * 3. create context buffer
     * 4. extracts and expands as needed
     * 5. call the AEAD 
     *
     */

    /* declare vars - done early so goto err works ok */
    EVP_PKEY_CTX *pctx=NULL;
    EVP_PKEY *skR=NULL;
    EVP_PKEY *pkE=NULL;
    EVP_PKEY *pkI=NULL;
    size_t  zzlen=0;
    unsigned char *zz=NULL;
    size_t  contextlen=0;
    unsigned char *context=NULL;
    size_t  secretlen=0;
    unsigned char *secret=NULL;
    size_t  keylen=0;
    unsigned char *key=NULL;
    size_t  noncelen=0;
    unsigned char *nonce=NULL;
    size_t  mypublen=0;
    unsigned char *mypub=NULL;
    size_t  otherpublen=0;
    unsigned char *otherpub=NULL;
    BIO *bfp=NULL;

    /* step 0. Initialise peer's key from string */
    if (suite.kem_id%2) {
        pkE = hpke_EVP_PKEY_new_raw_nist_public_key(hpke_kem_tab[suite.kem_id].groupid,enc,enclen);
    } else {
        pkE = EVP_PKEY_new_raw_public_key(hpke_kem_tab[suite.kem_id].groupid,NULL,enc,enclen);
    }
    if (pkE == NULL) {
        erv=__LINE__; goto err;
    }

    /* step 1. load decryptors private key */
    if (hpke_kem_tab[suite.kem_id].Npriv==privlen) {
        if (suite.kem_id%2) {
            skR = hpke_EVP_PKEY_new_raw_nist_private_key(hpke_kem_tab[suite.kem_id].groupid,priv,privlen);
        } else {
            skR=EVP_PKEY_new_raw_private_key(hpke_kem_tab[suite.kem_id].groupid,NULL,priv,privlen);
        }
    }
    if (!skR) {
        /* check PEM decode - that might work :-) */
        bfp=BIO_new(BIO_s_mem());
        if (!bfp) {
            erv=__LINE__; goto err;
        }
        BIO_write(bfp,priv,privlen);
        if (!PEM_read_bio_PrivateKey(bfp,&skR,NULL,NULL)) {
            erv=__LINE__; goto err;
        }
    }

    /* step 2 run DH KEM to get zz */
    erv=hpke_do_kem(skR,pkE,&zz,&zzlen);
    if (erv!=1) {
        goto err;
    }

    /* step 3. create context buffer */
    mypublen=EVP_PKEY_get1_tls_encodedpoint(skR,&mypub);
    if (mypub==NULL || mypublen == 0) {
        erv=__LINE__; goto err;
    }

    if (mode==HPKE_MODE_AUTH||mode==HPKE_MODE_PSKAUTH) {

        /* step 2.5 run DH KEM again to get 2nd half of zz */
        if (suite.kem_id%2) {
            pkI = hpke_EVP_PKEY_new_raw_nist_public_key(hpke_kem_tab[suite.kem_id].groupid,pub,publen);
        } else {
            pkI = EVP_PKEY_new_raw_public_key(hpke_kem_tab[suite.kem_id].groupid,NULL,pub,publen);
        }
        if (pkI == NULL) {
            erv=__LINE__; goto err;
        }
        unsigned char *zz2=NULL;
        size_t zzlen2=0;
        erv=hpke_do_kem(skR,pkI,&zz2,&zzlen2);
        if (erv!=1) {
            goto err;
        }
        unsigned char *zzboth=OPENSSL_malloc(zzlen+zzlen2);
        if (!zzboth) {
            OPENSSL_free(zz2);
            erv=__LINE__; goto err;
        }
        memcpy(zzboth,zz,zzlen);
        memcpy(zzboth+zzlen,zz2,zzlen2);
        OPENSSL_free(zz2);
        OPENSSL_free(zz);
        zz=zzboth;
        zzlen=zzlen+zzlen2;

        /* feed public into context */
        otherpub=pub;
        otherpublen=publen;
    }

    erv=hpke_make_context(mode,suite,
            enc,enclen,
            mypub,mypublen,
            otherpub,otherpublen,
            pskid,
            info,infolen,
            &context,&contextlen);

    /* step 4. extracts and expands as needed */
    /*
     * secret = Extract(psk, zz)
     * in my case psk is 32 octets of zero
     */
    size_t IKM_len=hpke_kdf_tab[suite.kdf_id].Nh;
    if (IKM_len>SHA512_DIGEST_LENGTH) {
        erv=__LINE__; goto err;
    }
    const unsigned char *IKM=zero_buf;
    secretlen=hpke_kdf_tab[suite.kdf_id].Nh;
    if (mode==HPKE_MODE_PSK || mode==HPKE_MODE_PSKAUTH) {
        IKM=psk;
        IKM_len=psklen;
    }
    if (hpke_extract(suite,IKM,IKM_len,zz,zzlen,&secret,secretlen)!=1) {
        erv=__LINE__; goto err;
    }
    /*
     * key = Expand(secret, concat("hpke key", context), Nk)
    */
    keylen=hpke_aead_tab[suite.aead_id].Nk;
    if (hpke_expand(suite,secret,secretlen,"hpke key",context,contextlen,&key,keylen)!=1) {
        erv=__LINE__; goto err;
    }
    /*
     * nonce = Expand(secret, concat("hpke nonce", context), Nn)
    */
    noncelen=12;
    if (hpke_expand(suite,secret,secretlen,"hpke nonce",context,contextlen,&nonce,noncelen)!=1) {
        erv=__LINE__; goto err;
    }

    /* step 5. call the AEAD */
    size_t lclearlen=HPKE_MAXSIZE;
    unsigned char lclear[HPKE_MAXSIZE];
    int arv=hpke_aead_dec(
                suite,
                key,keylen,
                nonce,noncelen,
                aad,aadlen,
                cipher,cipherlen,
                lclear,&lclearlen);
    if (arv!=1) {
        erv=arv; goto err;
    }
    if (lclearlen > *clearlen) {
        erv=__LINE__; goto err;
    }
    /* 
     * finish up
     */
    memcpy(clear,lclear,lclearlen);
    *clearlen=lclearlen;

err:

#ifdef SUPERVERBOSE
    printf("Decrypting:\n");
    printf("\tmode: %s (%d), kem: %s (%d), kdf: %s (%d), aead: %s (%d)\n",
                hpke_mode_strtab[mode],mode,
                hpke_kem_strtab[suite.kem_id],suite.kem_id,
                hkpe_kdf_strtab[suite.kdf_id], suite.kdf_id,
                hpke_aead_strtab[suite.aead_id], suite.aead_id);

    if (pkE) { 
        pblen = EVP_PKEY_get1_tls_encodedpoint(pkE,&pbuf); 
        hpke_pbuf(stdout,"\tpkE",pbuf,pblen); 
        if (pblen) OPENSSL_free(pbuf); 
    } else { 
        fprintf(stdout,"\tpkE is NULL\n"); 
    }
    if (skR) { 
        pblen = EVP_PKEY_get1_tls_encodedpoint(skR,&pbuf); 
        hpke_pbuf(stdout,"\tpkR",pbuf,pblen); 
        if (pblen) OPENSSL_free(pbuf); 
    } else { 
        fprintf(stdout,"\tpkR is NULL\n"); 
    }
    if (pkI) { 
        pblen = EVP_PKEY_get1_tls_encodedpoint(pkI,&pbuf); 
        hpke_pbuf(stdout,"\tpkI",pbuf,pblen); 
        if (pblen) OPENSSL_free(pbuf); 
    } else { 
        fprintf(stdout,"\tskI is NULL\n"); 
    }
 
    hpke_pbuf(stdout,"\tzz",zz,zzlen);
    hpke_pbuf(stdout,"\tcontext",context,contextlen);
    hpke_pbuf(stdout,"\tsecret",secret,secretlen);
    hpke_pbuf(stdout,"\tenc",enc,enclen);
    hpke_pbuf(stdout,"\tinfo",info,infolen);
    hpke_pbuf(stdout,"\taad",aad,aadlen);
    hpke_pbuf(stdout,"\tnonce",nonce,noncelen);
    hpke_pbuf(stdout,"\tkey",key,keylen);
    hpke_pbuf(stdout,"\tciphertext",cipher,cipherlen);
    if (mode==HPKE_MODE_PSK || mode==HPKE_MODE_PSKAUTH) {
        fprintf(stdout,"\tpskid: %s\n",pskid);
        hpke_pbuf(stdout,"\tpsk",psk,psklen);
    }
    if (*clearlen!=HPKE_MAXSIZE) hpke_pbuf(stdout,"\tplaintext",clear,*clearlen);
    else printf("clearlen is HPKE_MAXSIZE, so decryption probably failed\n");
#endif

    if (bfp!=NULL) BIO_free_all(bfp);
    if (skR!=NULL) EVP_PKEY_free(skR);
    if (pkE!=NULL) EVP_PKEY_free(pkE);
    if (pkI!=NULL) EVP_PKEY_free(pkI);
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    if (zz!=NULL) OPENSSL_free(zz);
    if (context!=NULL) OPENSSL_free(context);
    if (secret!=NULL) OPENSSL_free(secret);
    if (key!=NULL) OPENSSL_free(key);
    if (mypub!=NULL) OPENSSL_free(mypub);
    if (nonce!=NULL) OPENSSL_free(nonce);
    return erv;
}

/*!
 * @brief generate a key pair
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite (currently unused)
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param privlen is the size of the private key buffer (exact length on output)
 * @param priv is the private key
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int hpke_kg(
        unsigned int mode, hpke_suite_t suite,
        size_t *publen, unsigned char *pub,
        size_t *privlen, unsigned char *priv) 
{
    if (hpke_suite_check(suite)!=1) return(__LINE__);
    if (!pub || !priv) return(__LINE__);
    int erv=1; /* Our error return value - 1 is success */

    EVP_PKEY_CTX *pctx=NULL;
    EVP_PKEY *skR=NULL;
    unsigned char *lpub=NULL;
    BIO *bfp=NULL;

    /* step 1. generate sender's key pair */
    if (suite.kem_id%2) {
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (pctx == NULL) {
            erv=__LINE__; goto err;
        }
        if (1 != EVP_PKEY_paramgen_init(pctx)) {
            erv=__LINE__; goto err;
        }
        if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, hpke_kem_tab[suite.kem_id].groupid)) {
            erv=__LINE__; goto err;
        }
    } else {
        pctx = EVP_PKEY_CTX_new_id(hpke_kem_tab[suite.kem_id].groupid, NULL);
        if (pctx == NULL) {
            erv=__LINE__; goto err;
        }
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        erv=__LINE__; goto err;
    }
    if (EVP_PKEY_keygen(pctx, &skR) <= 0) {
        erv=__LINE__; goto err;
    }
    EVP_PKEY_CTX_free(pctx); pctx=NULL;

    size_t lpublen = EVP_PKEY_get1_tls_encodedpoint(skR,&lpub);
    if (lpub==NULL || lpublen == 0) {
        erv=__LINE__; goto err;
    }
    if (lpublen>*publen) {
        erv=__LINE__; goto err;
    }
    *publen=lpublen;
    memcpy(pub,lpub,lpublen);
    OPENSSL_free(lpub);lpub=NULL;

    bfp=BIO_new(BIO_s_mem());
    if (!bfp) {
        erv=__LINE__; goto err;
    }
    if (!PEM_write_bio_PrivateKey(bfp,skR,NULL,NULL,0,NULL,NULL)) {
        erv=__LINE__; goto err;
    }
    unsigned char lpriv[HPKE_MAXSIZE];
    size_t lprivlen = BIO_read(bfp, lpriv, HPKE_MAXSIZE);
    if (lprivlen <=0) {
        erv=__LINE__; goto err;
    }
    if (lprivlen > *privlen) {
        erv=__LINE__; goto err;
    }
    *privlen=lprivlen;
    memcpy(priv,lpriv,lprivlen);

err:

    if (skR!=NULL) EVP_PKEY_free(skR);
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    if (lpub!=NULL) OPENSSL_free(lpub);
    if (bfp!=NULL) BIO_free_all(bfp);
    return(erv);
}
