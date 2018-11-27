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
 * If defined, this provides enough API, internals and tracing so we can 
 * ensure/check we're generating keys the same way as other code, in 
 * partocular the existing NSS code
 * TODO: use this to protect the cryptovars are only needed for tracing
 */
#undef ESNI_CRYPT_INTEROP

#ifdef ESNI_CRYPT_INTEROP
/*
* map an (ascii hex) value to a nibble
*/
#define AH2B(x) ((x>='a' && x<='f') ? (10+x-'a'): (x-'0') )
#endif

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
     * Fields encoded in extension, these are copies, (not malloc'd)
	 * of pointers elsewhere in SSL_ESNI
     */
    const SSL_CIPHER *ciphersuite;
    size_t encoded_keyshare_len; /* my encoded key share */
    unsigned char *encoded_keyshare;
    size_t record_digest_len;
    unsigned char *record_digest;
    size_t encrypted_sni_len;
    unsigned char *encrypted_sni;
} CLIENT_ESNI;

/*
 * Per connection ESNI state (inspired by include/internal/dane.h) 
 * Has DNS RR values and some more
 */
typedef struct old_ssl_esni_st {
    int nerecs; /* number of DNS RRs in RRset */
    ESNI_RECORD *erecs; /* array of these */
    ESNI_RECORD *mesni;      /* Matching esni record */
    CLIENT_ESNI *client;
    const char *encservername;
    const char *frontname;
    uint64_t ttl;
    uint64_t lastread;
#ifdef ESNI_CRYPT_INTEROP
	char *private_str; /* for debug purposes, requires special build */
#endif
} oldSSL_ESNI;

/*
 * New, 20181126, flat structure
 * The ESNI data structure that's part of the SSL structure 
 * (Client-only for now really. Server is TBD.)
 */
typedef struct ssl_esni_st {
	/* 
	 * Fields from API
	 */
    char *encservername;
    char *frontname;
	/*
	 * Binary (base64 decoded) RR value
	 */
	size_t encoded_rr_len;
	unsigned char *encoded_rr;
	/*
	 * Hash of the above (record_digest), using the relevant hash from the ciphersuite
	 */
    size_t rd_len;
    unsigned char *rd;
	/*
	 * Fields direct from ESNIKeys, after matching vs. local preference
	 */
    const SSL_CIPHER *ciphersuite; 
	/*
	 * TODO: figure out how to free one SSL_CIPHER, for now copy full set and free that
	 */
    STACK_OF(SSL_CIPHER) *ciphersuites; 

	uint16_t group_id; 
    size_t esni_server_keyshare_len; 
    unsigned char *esni_server_keyshare;
	EVP_PKEY *esni_server_pkey;
    size_t padded_length;
    uint64_t not_before;
    uint64_t not_after;
	int nexts; // not yet supported >0 => fail
	void **exts;
	/*
	 * Nonce we challenge server to respond with
	 */
    size_t nonce_len;
    unsigned char *nonce;
	/*
	 * Client random and key share from TLS h/s
	 */
	size_t hs_cr_len; 
	unsigned char *hs_cr;
    size_t hs_kse_len;
    unsigned char *hs_kse;
    /* 
	 * Crypto Vars - not all are really needed in the struct
	 * (though tickets/resumption need a quick thought)
	 * But all are handy for interop testing
	 */
    EVP_PKEY *keyshare; /* my own private keyshare to use with  server's ESNI share */
	size_t encoded_keyshare_len;
	unsigned char *encoded_keyshare;
	/*
	 * ESNIContent encoded and hash thereof
	 */
    size_t hi_len; 
    unsigned char *hi;
    size_t hash_len;
    unsigned char *hash; 
	/* 
	 * Derived crypto vars
	 */
    size_t Z_len;
    unsigned char *Z; /* shared secret */
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
    size_t realSNI_len; /* padded SNI */
    unsigned char *realSNI;
#ifdef ESNI_CRYPT_INTEROP
	char *private_str; /* for debug purposes, requires special build */
#endif
	CLIENT_ESNI *the_esni; /* the final outputs for the caller */
} SSL_ESNI;

/*
 * Prototypes
 */

/*
 * Make a basic check of names from CLI or API
 */
int esni_checknames(const char *encservername, const char *frontname);

/*
 * Decode and check the value retieved from DNS (currently base64 encoded)
 */
SSL_ESNI* SSL_ESNI_new_from_base64(const char *esnikeys);

/*
 * Turn on SNI encryption for this TLS (upcoming) session
 */
int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni);

/*
 * Do the client-side SNI encryption during a TLS handshake
 */
int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
                char *protectedserver, 
                char *frontname, 
                size_t  client_random_len,
                unsigned char *client_random,
				uint16_t curve_id,
				size_t  client_keyshare_len,
				unsigned char *client_keyshare,
                CLIENT_ESNI **the_esni);

/*
 * Memory management
 */
void SSL_ESNI_free(SSL_ESNI *esnikeys);
void CLIENT_ESNI_free(CLIENT_ESNI *c);

/*
 * Debugging - note - can include sensitive values!
 * (Depends on compile time options)
 */
int SSL_ESNI_print(BIO* out, SSL_ESNI *esni);

/*
 * SSL_ESNI_print calls a callback function that uses this
 * to get the SSL_ESNI structure from the external view of
 * the TLS session.
 */
int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni);

#ifdef ESNI_CRYPT_INTEROP
/*
 * Crypto detailed debugging functions to allow comparison of intermediate
 * values with other code bases (in particular NSS) - these allow one to
 * set values that were generated in another code base's TLS handshake and
 * see if the same derived values are calculated.
 */
int SSL_ESNI_set_private(SSL_ESNI *esni, char *private_str);
int SSL_ESNI_set_nonce(SSL_ESNI *esni, unsigned char *nonce, size_t nlen);
#endif

#endif
#endif
