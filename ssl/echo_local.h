/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file 
 * This has the data structures and prototypes (both internal and external)
 * for internal handling of Encrypted ClientHEllo (ECHO)
 */

#ifndef OPENSSL_NO_ECHO

#ifndef HEADER_ECHO_LOCAL_H
# define HEADER_ECHO_LOCAL_H

# include <openssl/ssl.h>
# include <openssl/echo.h>
# include <crypto/hpke.h>

#define ECHO_RRTYPE 65439 ///< experimental (as per draft-03, and draft-04) ECHO RRTYPE

#define ECHO_MIN_ECHOCONFIG_LEN 32 ///< just for a sanity check

/** 
 * @brief Representation of what goes in DNS
 * <pre>
 *       opaque HpkePublicKey<1..2^16-1>;
 *       uint16 HkpeKemId; // Defined in I-D.irtf-cfrg-hpke
 *
 *       struct {
 *           opaque public_name<1..2^16-1>;
 *           HpkePublicKey public_key;
 *           HkpeKemId kem_id;
 *           CipherSuite cipher_suites<2..2^16-2>;
 *           uint16 maximum_name_length;
 *           Extension extensions<0..2^16-1>;
 *       } ECHOConfigContents;
 *
 *       struct {
 *           uint16 version;
 *           uint16 length;
 *           select (ECHOConfig.version) {
 *             case 0xff03: ECHOConfigContents;
 *           }
 *       } ECHOConfig;
 *
 *       ECHOConfig ECHOConfigs<1..2^16-1>;
 * </pre>
 *
 */
typedef struct echo_config_st {
    unsigned int version; ///< 0xff03 for draft-06
    unsigned int public_name_len; ///< public_name
    unsigned char *public_name; ///< public_name
    unsigned int kem_id; ///< HPKE KEM ID to use
    unsigned int pub_len; ///< HPKE public
    unsigned char *pub;
	unsigned int nsuites;
	unsigned int *ciphersuites;
    unsigned int maximum_name_length;
    unsigned int nexts;
    unsigned int *exttypes;
    unsigned int *extlens;
    unsigned char **exts;
} ECHOConfig;

typedef struct echo_configs_st {
    unsigned int encoded_len; ///< length of overall encoded content
    unsigned char *encoded; ///< overall encoded content
    int nrecs; ///< Number of records 
    ECHOConfig *recs; ///< array of individual records
} ECHOConfigs;

/**
 * What we send in the echo CH extension:
 *
 * The TLS presentation language version is:
 *
 * <pre>
 * struct {
 *          CipherSuite suite;
 *          opaque record_digest<0..2^16-1>;
 *          opaque enc<1..2^16-1>;
 *          opaque encrypted_ch<1..2^16-1>;
 *      } ClientEncryptedCH;
 * </pre>
 *
 * Fields encoded in extension, these are copies, (not malloc'd)
 * of pointers elsewhere in SSL_ECHO. One of these is returned
 * from SSL_ECHO_enc, and is also pointed to from the SSL_ECHO
 * structure.
 *
 */
typedef struct echo_encch_st {
	unsigned int ciphersuite; ///< ciphersuite - TODO: make this a HPKE suite
    size_t record_digest_len; ///< identifies DNS RR used
    unsigned char *record_digest; ///< identifies DNS RR used
    size_t enc_len; ///< public share
    unsigned char *enc; ///< public share
    size_t encch_len; ///< ciphertext 
    unsigned char *encch; ///< ciphertext 
} ECHO_ENCCH;

/**
 * @brief The ECHO data structure that's part of the SSL structure 
 *
 * On the client-side, one of these is part of the SSL structure.
 * On the server-side, an array of these is part of the SSL_CTX
 * structure, and we match one of 'em to be part of the SSL 
 * structure when a handshake is in porgress. (Well, hopefully:-)
 *
 * Note that SSL_ECHO_dup copies all these fields (when values are
 * set), so if you add, change or remove a field here, you'll also
 * need to modify that (in ssl/echo.c)
 */
typedef struct ssl_echo_st {
    ECHOConfigs *cfg; ///< merge of underlying ECHOConfigs
    size_t rd_len;
    unsigned char *rd; ///< Hash of the encoded_rr record_digest, using the relevant hash from the ciphersuite

    /*
     * SSL/SSL_CTX instantiated things
     */
	unsigned int ciphersuite; ///< chosen from ECHOConfig after selection of local preference
    unsigned int kem_id;  ///< our chosen group e.g. X25519
    size_t echo_peer_keyshare_len;  
    unsigned char *echo_peer_keyshare; ///< the encoded peer's public value
    EVP_PKEY *echo_peer_pkey; ///< the peer public as a key
    size_t maximum_name_length; ///< from ECHOConfig
    int nexts; ///< number of extensions 
    unsigned int *exttypes; ///< array of extension types
    size_t *extlens; ///< lengths of encoded extension octets
    unsigned char **exts; ///< encoded extension octets
    /*
     * Session specific stuff
     */
    int crypto_started; ///< set to one if someone tried to use this for real
    int hrr_swap; ///< 0 if not a HRR, 1 if it is (and we use different IV for draft-04 on)
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
    EVP_PKEY *keyshare; ///< my own private keyshare to use with  server's ECHO share 
    size_t encoded_keyshare_len; 
    unsigned char *encoded_keyshare; ///< my own public key share
    size_t plain_len;
    unsigned char *plain; ///< plaintext value for ECHO
    size_t cipher_len;
    unsigned char *cipher; ///< ciphetext value of ECHO
    size_t tag_len;
    unsigned char *tag; ///< GCM tag (already also in ciphertext)
    ECHO_ENCCH *the_echo; ///< the final outputs for the caller (note: not separately alloc'd)
    /* 
     * File load information servers - if identical filenames not modified since
     * loadtime are added via SSL_echo_serve_enable then we'll ignore the new
     * data. If identical file names that are more recently modified are loaded
     * to a server we'll overwrite this entry.
     */
    char *privfname; ///< name of private key file from which this was loaded
    char *pubfname;  ///< name of private key file from which this was loaded
    time_t loadtime; ///< time public and private key were loaded from file
} SSL_ECHO;

/**
 * @brief Do the client-side SNI encryption during a TLS handshake
 *
 * This is an internal API called as part of the state machine
 * dealing with this extension.
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param echokeys is the SSL_ECHO structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return 1 for success, other otherwise
 */
int SSL_ECHO_enc(SSL_CTX *ctx,
                SSL *con,
                SSL_ECHO *echokeys, 
                size_t  client_random_len,
                unsigned char *client_random,
                unsigned int curve_id,
                size_t  client_keyshare_len,
                unsigned char *client_keyshare,
                ECHO_ENCCH **the_echo);

/**
 * @brief Server-side decryption during a TLS handshake
 *
 * This is the internal API called as part of the state machine
 * dealing with this extension.
 * Note that the decrypted server name is just a set of octets - there
 * is no guarantee it's a DNS name or printable etc. (Same as with
 * SNI generally.)
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param echo is the SSL_ECHO structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return NULL for error, or the decrypted servername when it works
 */
unsigned char *SSL_ECHO_dec(SSL_CTX *ctx,
                SSL *con,
                SSL_ECHO *echo,
				size_t	client_random_len,
				unsigned char *client_random,
				unsigned int curve_id,
				size_t	client_keyshare_len,
				unsigned char *client_keyshare,
				size_t *encservername_len);

/**
 * Memory management - free an SSL_ECHO
 *
 * Free everything within an SSL_ECHO. Note that the
 * caller has to free the top level SSL_ECHO, IOW the
 * pattern here is: 
 *      SSL_ECHO_free(echokeys);
 *      OPENSSL_free(echokeys);
 *
 * @param echokeys is an SSL_ECHO structure
 */
void SSL_ECHO_free(SSL_ECHO *tbf);

/**
 *
 * Free stuff
 * @param tbf is the thing to be free'd
 */
void ECHOConfigs_free(ECHOConfigs *tbf);

/**
 * @brief Duplicate the configuration related fields of an SSL_ECHO
 *
 * This is needed to handle the SSL_CTX->SSL factory model in the
 * server. Clients don't need this.  There aren't too many fields 
 * populated when this is called - essentially just the ECHOKeys and
 * the server private value. For the moment, we actually only
 * deep-copy those.
 *
 * @param orig is the input array of SSL_ECHO to be partly deep-copied
 * @param necho is the number of elements in the array
 * @param selector allows for picking all (ECHO_SELECT_ALL==-1) or just one of the RR values in orig
 * @return a partial deep-copy array or NULL if errors occur
 */
SSL_ECHO* SSL_ECHO_dup(SSL_ECHO* orig, size_t necho, int selector);

/**
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ECHOKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECHO_RRFMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection 
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param echokeys is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echos says how many SSL_ECHO structures are in the returned array
 * @return is an SSL_ECHO structure
 */
SSL_ECHO* SSL_ECHO_new_from_buffer(SSL_CTX *ctx, SSL *con, const short ekfmt, const size_t eklen, const char *echokeys, int *num_echos);

#endif
#endif
