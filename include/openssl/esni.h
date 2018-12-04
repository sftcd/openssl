/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file 
 * This has the data structures and prototypes (both internal and external)
 * for the ESNI proof-of-concept
 */

#ifndef OPENSSL_NO_ESNI

#ifndef HEADER_ESNI_H
# define HEADER_ESNI_H

# include <openssl/ssl.h>


//#undef ESNI_CRYPT_INTEROP
#define ESNI_CRYPT_INTEROP

#ifdef ESNI_CRYPT_INTEROP
/**
 * If defined, this provides enough API, internals and tracing so we can 
 * ensure/check we're generating keys the same way as other code, in 
 * partocular the existing NSS code
 *
 * TODO: use this to protect the cryptovars are only needed for tracing
 */

/**
* map an (ascii hex) value to a nibble
*/
#define AH2B(x) ((x>='a' && x<='f') ? (10+x-'a'): (x-'0') )

#endif

/** 
 * @brief Representation of what goes in DNS
 *
 * This is from the -02 I-D, in TLS presentation language:
 *
 * <pre>
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
 * </pre>
 * 
 * Note that I don't like the above, but it's what we have to
 * work with at the moment.
 *
 * This structure is purely used when decoding the RR value
 * and is then discarded (selected values mapped into the
 * SSL_ESNI structure).
 */
typedef struct esni_record_st {
    unsigned int version;
    unsigned char checksum[4];
    unsigned int nkeys;
    uint16_t *group_ids;
    EVP_PKEY **keys;
    size_t *encoded_lens;
    unsigned char **encoded_keys;
    STACK_OF(SSL_CIPHER) *ciphersuites;
    unsigned int padded_length;
    uint64_t not_before;
    uint64_t not_after;
    unsigned int nexts;
    unsigned int *exttypes;
    void **exts;
} ESNI_RECORD;

/**
 * What we send in the esni CH extension:
 *
 * The TLS presentation language version is:
 *
 * <pre>
 *     struct {
 *         CipherSuite suite;
 *         KeyShareEntry key_share;
 *         opaque record_digest<0..2^16-1>;
 *         opaque encrypted_sni<0..2^16-1>;
 *     } ClientEncryptedSNI;
 * </pre>
 *
 * Fields encoded in extension, these are copies, (not malloc'd)
 * of pointers elsewhere in SSL_ESNI. One of these is returned
 * from SSL_ESNI_enc, and is also pointed to from the SSL_ESNI
 * structure.
 *
 */
typedef struct client_esni_st {
    const SSL_CIPHER *ciphersuite;
    size_t encoded_keyshare_len; 
    unsigned char *encoded_keyshare;
    size_t record_digest_len;
    unsigned char *record_digest;
    size_t encrypted_sni_len;
    unsigned char *encrypted_sni;
} CLIENT_ESNI;

/**
 * @brief The ESNI data structure that's part of the SSL structure 
 *
 * (Client-only for now really. Server is TBD.)
 */
typedef struct ssl_esni_st {
    char *encservername; ///< hidden server name
    char *covername; ///< cleartext SNI (can be NULL)
    int require_hidden_match; ///< If 1 then SSL_esni_get_status will barf if hidden name doesn't match TLS server cert. If 0, don't care.
    size_t encoded_rr_len;
    unsigned char *encoded_rr; ///< Binary (base64 decoded) RR value
    size_t rd_len;
    unsigned char *rd; ///< Hash of the above (record_digest), using the relevant hash from the ciphersuite
    const SSL_CIPHER *ciphersuite;  ///< from ESNIKeys after selection of local preference
    /*
     * TODO: figure out how to free one SSL_CIPHER, for now copy full set and free that
     */
    STACK_OF(SSL_CIPHER) *ciphersuites;  ///< needed for graceful memory management (free) for now

    uint16_t group_id;  ///< our chosen group e.g. X25519
    size_t esni_server_keyshare_len;  
    unsigned char *esni_server_keyshare; ///< the encoded server public
    EVP_PKEY *esni_server_pkey; ///< the server public as a key
    size_t padded_length; ///< from ESNIKeys
    uint64_t not_before; ///< from ESNIKeys (not currently used)
    uint64_t not_after; ///< from ESNIKeys (not currently used)
    int nexts; ///< number of extensions (not yet supported so >0 => fail)
    void **exts; ///< extensions
    size_t nonce_len; 
    unsigned char *nonce; ///< Nonce we challenge server to respond with
    size_t hs_cr_len; 
    unsigned char *hs_cr; ///< Client random from TLS h/s
    size_t hs_kse_len;
    unsigned char *hs_kse;///< Client key share from TLS h/s
    /* 
     * Crypto Vars - not all are really needed in the struct
     * (though tickets/resumption need a quick thought)
     * But all are handy for interop testing
     */
    EVP_PKEY *keyshare; ///< my own private keyshare to use with  server's ESNI share 
    size_t encoded_keyshare_len; 
    unsigned char *encoded_keyshare; ///< my own public key share
    size_t hi_len; 
    unsigned char *hi; ///< ESNIContent encoded (hash input)
    size_t hash_len;
    unsigned char *hash;  ///< hash of hi (encoded ESNIContent)
    size_t realSNI_len; 
    unsigned char *realSNI; ///< padded ESNI
    /* 
     * Derived crypto vars
     */
    size_t Z_len;
    unsigned char *Z; ///< ECDH shared secret 
    size_t Zx_len;
    unsigned char *Zx; ///< derived from Z as per I-D
    size_t key_len;
    unsigned char *key; ///< derived key
    size_t iv_len;
    unsigned char *iv; ///< derived iv
    size_t aad_len; 
    unsigned char *aad; ///< derived aad
    size_t plain_len;
    unsigned char *plain; ///< plaintext value for ESNI
    size_t cipher_len;
    unsigned char *cipher; ///< ciphetext value of ESNI
    size_t tag_len;
    unsigned char *tag; ///< GCM tag (already also in ciphertext)
#ifdef ESNI_CRYPT_INTEROP
    char *private_str; ///< for debug purposes, requires special build
#endif
    CLIENT_ESNI *the_esni; ///< the final outputs for the caller (note: not separately alloc'd)
} SSL_ESNI;

/*
 * Prototypes
 */

/**
 * Make a basic check of names from CLI or API
 *
 * Note: This may disappear as all the checks currently done would
 * result in errors anyway. However, that could change, so we'll
 * keep it for now.
 *
 * @param encservername the hidden servie
 * @param convername the cleartext SNI to send (can be NULL if we don't want any)
 * @return 1 for success, other otherwise
 */
int SSL_esni_checknames(const char *encservername, const char *covername);

/**
 * Decode and check the value retieved from DNS (currently base64 encoded)
 *
 * @param esnikeys is the base64 encoded value from DNS
 * @return is an SSL_ESNI structure
 */
SSL_ESNI* SSL_ESNI_new_from_base64(const char *esnikeys);

/**
 * Turn on SNI encryption for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidde is the hidden service name
 * @param cover is the cleartext SNI name to use
 * @param esni is the SSL_ESNI structure
 * @param require_hidden_match say whether to require (==1) the TLS server cert matches the hidden name
 * @return 1 for success, other otherwise
 * 
 */
int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni, int require_hidden_match);

/**
 * Turn on SNI Encryption, server-side
 *
 * When this works, the server will decrypt any ESNI seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 *
 * @todo: TODO: consider what to do if this is called more than once. We may
 * want a server to support that if there is >1 hidden service.
 *
 * @param s is the SSL server context
 * @param esnikeyfile has the relevant (X25519) private key in PEM format
 * @param esnipubfile has the relevant (binary encoded, not base64) ESNIKeys structure
 * @return 1 for success, other otherwise
 */
int SSL_esni_server_enable(SSL_CTX *s, const char *esnikeyfile, const char *esnipubfile);

/**
 * Do the client-side SNI encryption during a TLS handshake
 *
 * This is an internal API called as part of the state machine
 * dealing with this extension.
 *
 * @param esnikeys is the SSL_ESNI structure
 * @param client_random_len is the number of bytes of
 * @client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 */
int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
                size_t  client_random_len,
                unsigned char *client_random,
                uint16_t curve_id,
                size_t  client_keyshare_len,
                unsigned char *client_keyshare,
                CLIENT_ESNI **the_esni);

/**
 * Memory management - free an SSL_ESNI
 *
 * Free everything within an SSL_ESNI. Note that the
 * caller has to free the top level SSL_ESNI, IOW the
 * pattern here is: 
 *      SSL_ESNI_free(esnikeys);
 *      OPENSSL_free(esnikeys);
 *
 * @param esnikeys is an SSL_ESNI structure
 */
void SSL_ESNI_free(SSL_ESNI *esnikeys);

/**
 * Memory management - free a CLIENT_ESNI
 *
 * This is called from within SSL_ESNI_free so isn't
 * really needed externally at all.
 *
 * @param c is a CLIENT_ESNI structure
 */
void CLIENT_ESNI_free(CLIENT_ESNI *c);

/**
 * Debugging - print an SSL_ESNI structure note - can include sensitive values!
 *
 * @param out is a BIO for printing
 * @param esni is an SSL_ESNI structure
 * @return 1 for success, anything else for failure
 */
int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni);

/** 
 * Print the content of an SSL_ESNI
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @esni is an SSL_ESNI strucutre
 * @return 1 for success, anything else for failure
 */
int SSL_ESNI_print(BIO* out, SSL_ESNI *esni);

/**
 * Get access to the ESNI data from an SSL context (if that's
 * the right term:-)
 *
 * @param s the SSL context
 * @param esni the (ptr to) output SSL_ESNI structure
 * @return 1 for success, anything else for failure
 */
int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni);

/* 
 * Possible return codes from SSL_ESNI_get_status
 */

#define SSL_ESNI_STATUS_SUCCESS                 1 ///< Success
#define SSL_ESNI_STATUS_FAILED                  0 ///< Some internal error
#define SSL_ESNI_STATUS_BAD_CALL             -100 ///< Required in/out arguments were NULL
#define SSL_ESNI_STATUS_NOT_TRIED            -101 ///< ESNI wasn't attempted 
#define SSL_ESNI_STATUS_BAD_NAME             -102 ///< ESNI succeeded but the TLS server cert used didn't match the hidden service name

/**
 * @brief API to allow calling code know ESNI outcome, post-handshake
 *
 * This is intended to be called by applications after the TLS handshake
 * is complete.
 *
 * @param s The SSL context (if that's the right term)
 * @param hidden will be set to the address of the hidden service
 * @param cover will be set to the address of the hidden service
 * @return 1 for success, other otherwise
 */
int SSL_get_esni_status(SSL *s, char **hidden, char **cover);

/*
 * Crypto detailed debugging functions to allow comparison of intermediate
 * values with other code bases (in particular NSS) - these allow one to
 * set values that were generated in another code base's TLS handshake and
 * see if the same derived values are calculated.
 */

/**
 * Allows caller to set the ECDH private value for ESNI. 
 *
 * This is intended to only be used for interop testing - what was
 * useful was to grab the value from the NSS implemtation, force
 * it into mine and see which of the derived values end up the same.
 *
 * @param esni is the SSL_ESNI struture
 * @param private_str is an ASCII-hex encoded X25519 point (essentially
 * a random 32 octet value:-) 
 * @return 1 for success, other otherwise
 *
 */
int SSL_ESNI_set_private(SSL_ESNI *esni, char *private_str);

/**
 * @brief Allows caller to set the nonce value for ESNI. 
 *
 * This is intended to only be used for interop testing - what was
 * useful was to grab the value from the NSS implemtation, force
 * it into mine and see which of the derived values end up the same.
 *
 * @param esni is the SSL_ESNI struture
 * @param nonce points to a buffer with the network byte order value
 * @oaram nlen is the size of the nonce buffer
 * @return 1 for success, other otherwise
 *
 */
int SSL_ESNI_set_nonce(SSL_ESNI *esni, unsigned char *nonce, size_t nlen);

#endif
#endif
