/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_NO_ESNI

#ifndef HEADER_ESNI_H
# define HEADER_ESNI_H

# include <openssl/ssl.h>


/*
 * define'd constants to go in various places
 */ 

/* destination: unknown */
#define SSL_F_TLS_CONSTRUCT_CTOS_ENCRYPTED_SERVER_NAME 401

/* 
 * From the -02 I-D, what we find in DNS:
 *     struct {
 *         uint16 version;
 *         uint8 checksum[4];
 *         KeyShareEntry keys<4..2^16-1>;
 *         CipherSuite cipher_suites<2..2^16-2>;
 *         uint16 padded_length;
 *         uint64 not_before;
 *         uint64 not_after;
 *         Extension extensions<0..2^16-1>;
 *     } ESNIKeys;
 * 
 * Note that I don't like the above, but it's what we have to
 * work with at the moment.
 */
typedef struct esni_record_st {
    unsigned int version;
    unsigned char checksum[4];
    unsigned int nkeys;
    unsigned int *group_ids;
    EVP_PKEY **keys;
    STACK_OF(SSL_CIPHER) *ciphersuites;
    unsigned int padded_length;
    uint64_t not_before;
    uint64_t not_after;
    unsigned int nexts;
    unsigned int *exttypes;
    void **exts;
    /*
     * The Encoded (binary, after b64-decode) form of the RR
     */
    size_t encoded_len;
    unsigned char *encoded;
} ESNI_RECORD;

/*
 * The plaintext form of SNI that we encrypt
 *
 *    struct {
 *        ServerNameList sni;
 *        opaque zeros[ESNIKeys.padded_length - length(sni)];
 *    } PaddedServerNameList;
 *
 *    struct {
 *        uint8 nonce[16];
 *        PaddedServerNameList realSNI;
 *    } ClientESNIInner;
 */
typedef struct client_esni_inner_st {
    size_t nonce_len;
    unsigned char *nonce;
    size_t realSNI_len;
    unsigned char *realSNI;
} CLIENT_ESNI_INNER; 

/* 
 * a struct used in key derivation
 * from the I-D:
 *    struct {
 *        opaque record_digest<0..2^16-1>;
 *        KeyShareEntry esni_key_share;
 *        Random client_hello_random;
 *     } ESNIContents;
 *
 */
typedef struct esni_contents_st {
    size_t rd_len;
    unsigned char *rd;
    size_t kse_len;
    unsigned char *kse;
    size_t cr_len;
    unsigned char *cr;
} ESNIContents;

/*
 * Place to keep crypto vars for when we try interop.
 * This should probably (mostly) disappear when/if we end up with
 * a final working version that maps to an RFC.
 *
 * Fields below:
 * keyshare: is the client's ephemeral public value
 * shared: is the D-H shared secret
 * hi: encoded ESNIContents hash input 
 * hash: hash output from above
 * Zx: derived from D-H shared secret
 * key: derived from Zx as per I-D
 * iv: derived from Zx as per I-D
 * aad: the AAD for the AEAD
 * plain: encoded plaintext
 * cipher: ciphertext
 * tag: AEAD tag (exposed by OpenSSL api?)
 */
typedef struct esni_crypto_vars_st {
    EVP_PKEY *keyshare;
    size_t shared_len;
    unsigned char *shared; /* shared secret */
    size_t hi_len;
    unsigned char *hi;
    size_t hash_len;
    unsigned char *hash;
    size_t Zx_len;
    unsigned char *Zx;
    size_t key_len;
    unsigned char *key;
    size_t iv_len;
    unsigned char *iv;
    size_t aad_len;
    unsigned char *aad;
    size_t plain_len;
    unsigned char *plain;
    size_t cipher_len;
    unsigned char *cipher;
    size_t tag_len;
    unsigned char *tag;
} ESNI_CRYPTO_VARS;

/*
 * What we send in the esni CH extension:
 *
 *    struct {
 *        CipherSuite suite;
 *        KeyShareEntry key_share;
 *        opaque record_digest<0..2^16-1>;
 *        opaque encrypted_sni<0..2^16-1>;
 *    } ClientEncryptedSNI;
 *
 * We include some related non-transmitted 
 * e.g. key structures too
 *
 */
typedef struct client_esni_st {
    /*
     * Fields encoded in extension
     */
    const SSL_CIPHER *ciphersuite;
    size_t encoded_keyshare_len; /* my encoded key share */
    unsigned char *encoded_keyshare;
    size_t record_digest_len;
    unsigned char record_digest[SSL_MAX_SSL_RECORD_DIGEST_LENGTH];
    size_t encrypted_sni_len;
    unsigned char encrypted_sni[SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH];
    /*
     * Various intermediate/crypto vars
     */
    ESNIContents econt;
    CLIENT_ESNI_INNER inner;
    ESNI_CRYPTO_VARS cvars;
} CLIENT_ESNI;

/*
 * Per connection ESNI state (inspired by include/internal/dane.h) 
 * Has DNS RR values and some more
 */
typedef struct ssl_esni_st {
    int nerecs; /* number of DNS RRs in RRset */
    ESNI_RECORD *erecs; /* array of these */
    ESNI_RECORD *mesni;      /* Matching esni record */
    CLIENT_ESNI *client;
    const char *encservername;
    const char *frontname;
    uint64_t ttl;
    uint64_t lastread;
} SSL_ESNI;

/*
 * Prototypes
 */

__owur int esni_checknames(const char *encservername, const char *frontname);
void CLIENT_ESNI_free(CLIENT_ESNI *c);
void SSL_ESNI_free(SSL_ESNI *esnikeys);
SSL_ESNI* SSL_ESNI_new_from_base64(const char *esnikeys);
int SSL_ESNI_print(BIO* out, SSL_ESNI *esni);
int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
                char *protectedserver, 
                char *frontname, 
                size_t  cr_len,
                unsigned char *client_random,
                CLIENT_ESNI **the_esni);
int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni);

#endif
#endif
