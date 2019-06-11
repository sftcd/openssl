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

#define ESNI_MAX_RRVALUE_LEN 2000 ///< Max size of a collection of ESNI RR values

#define ESNI_SELECT_ALL -1 ///< used to duplicate all RRs in SSL_ESNI_dup

#define ESNI_PBUF_SIZE 8*1024 ///<  8K buffer used for print string sent to application via esni_print_cb


/*
 * ESNIKeys Extensions we know about...
 */
#define ESNI_ADDRESS_SET_EXT 0x1001 ///< AddressSet as per draft-03

/* TODO: find another implemenation of this, there's gotta be one */
#define A2B(__c__) (__c__>='0'&&__c__<='9'?(__c__-'0'):\
                        (__c__>='A'&&__c__<='F'?(__c__-'A'+10):\
                            (__c__>='a'&&__c__<='f'?(__c__-'a'+10):0)))


/*
 * Known text input formats for ESNIKeys RR values
 * - can be TXT containing base64 encoded value (draft-02)
 * - can be TYPE65439 containing ascii-hex string(s)
 * - can be TYPE65439 formatted as output from dig +short (multi-line)
 */
#define ESNI_RRFMT_GUESS     0  ///< try guess which it is
#define ESNI_RRFMT_BIN       1  ///< binary encoded
#define ESNI_RRFMT_ASCIIHEX  2  ///< draft-03 ascii hex value(s catenated)
#define ESNI_RRFMT_B64TXT    3  ///< draft-02 (legacy) base64 encoded TXT

/**
 * If defined, this provides enough API, internals and tracing so we can 
 * ensure/check we're generating keys the same way as other code, in 
 * partocular the existing NSS code
 */
#define ESNI_CRYPT_INTEROP
//#undef ESNI_CRYPT_INTEROP
#ifdef ESNI_CRYPT_INTEROP

#define ESNI_DRAFT_02_VERSION 0xff01 ///< ESNIKeys version from draft-02
#define ESNI_DRAFT_03_VERSION 0xff02 ///< ESNIKeys version from draft-03

#define ESNI_RRTYPE 65439 ///< experimental (as per draft-03) ESNI RRTYPE

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
 *
 * draft-03 changed this some ...
 * <pre>
 *  struct {
 *         uint16 version;
 *         uint8 checksum[4];
 *         opaque public_name<1..2^16-1>;
 *         KeyShareEntry keys<4..2^16-1>;
 *         CipherSuite cipher_suites<2..2^16-2>;
 *         uint16 padded_length;
 *         uint64 not_before;
 *         uint64 not_after;
 *         Extension extensions<0..2^16-1>;
 *     } ESNIKeys;
 * </pre>
 */
typedef struct esni_record_st {
    unsigned int version;
    unsigned char checksum[4];
    int public_name_len;
    unsigned char *public_name;
    unsigned int nkeys;
    uint16_t *group_ids;
    EVP_PKEY **keys;
    size_t *encoded_lens;
    unsigned char **encoded_keys;
	size_t nsuites;
	uint16_t *ciphersuites;
    unsigned int padded_length;
    uint64_t not_before;
    uint64_t not_after;
    unsigned int nexts;
    unsigned int *exttypes;
    size_t *extlens;
    unsigned char **exts;
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
	uint16_t ciphersuite;
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
 * On the client-side, one of these is part of the SSL structure.
 * On the server-side, an array of these is part of the SSL_CTX
 * structure, and we match one of 'em to be part of the SSL 
 * structure when a handshake is in porgress. (Well, hopefully:-)
 *
 * Note that SSL_ESNI_dup copies all these fields (when values are
 * set), so if you add, change or remove a field here, you'll also
 * need to modify that (in ssl/esni.c)
 */
typedef struct ssl_esni_st {
    unsigned int version; ///< version from underlying ESNI_RECORD/ESNIKeys
    char *encservername; ///< hidden server name
    char *covername; ///< cleartext SNI (can be NULL)
    char *public_name;  ///< public_name from ESNIKeys
    int require_hidden_match; ///< If 1 then SSL_get_esni_status will barf if hidden name doesn't match TLS server cert. If 0, don't care.
    int num_esni_rrs; ///< the number of ESNIKeys structures in this array
    size_t encoded_rr_len;
    unsigned char *encoded_rr; ///< Binary (base64 decoded) RR value
    size_t rd_len;
    unsigned char *rd; ///< Hash of the above (record_digest), using the relevant hash from the ciphersuite
	uint16_t ciphersuite; ///< from ESNIKeys after selection of local preference
    uint16_t group_id;  ///< our chosen group e.g. X25519
    size_t esni_peer_keyshare_len;  
    unsigned char *esni_peer_keyshare; ///< the encoded peer's public value
    EVP_PKEY *esni_peer_pkey; ///< the peer public as a key
    size_t padded_length; ///< from ESNIKeys
    uint64_t not_before; ///< from ESNIKeys (not currently used)
    uint64_t not_after; ///< from ESNIKeys (not currently used)
    int nexts; ///< number of extensions (not yet supported so >0 => fail)
    unsigned int *exttypes; ///< array of extension types
    size_t *extlens; ///< lengths of encoded extension octets
    unsigned char **exts; ///< encoded extension octets
    int naddrs; ///< decoded AddressSet cardinality
    BIO_ADDR *addrs; ///< decoded AddressSet values (v4 or v6)
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

/**
 * Exterally visible form of an ESNIKeys RR value
 */
typedef struct ssl_esni_ext_st {
    int index; ///< externally re-usable reference to this RR value
    char *public_name; ///< public_name from ESNIKeys
    char *prefixes;  ///< comman seperated list of IP address prefixes, in CIDR form
    uint64_t not_before; ///< from ESNIKeys (not currently used)
    uint64_t not_after; ///< from ESNIKeys (not currently used)
} SSL_ESNI_ext; 

/*
 * Non-external Prototypes
 */

/**
 * @brief wrap a "raw" key share in the relevant TLS presentation layer encoding
 *
 * Put the outer length and curve ID around a key share.
 * This just exists because we do it a few times: for the ESNI
 * client keyshare and for handshake client keyshare.
 * The input keyshare is the e.g. 32 octets of a point
 * on curve 25519 as used in X25519.
 *
 * @param keyshare is the input keyshare which'd be 32 octets for x25519
 * @param keyshare_len is the length of the above (0x20 for x25519)
 * @param curve_id is the IANA registered value for the curve e.g. 0x1d for X25519
 * @param outlen is the length of the encoded version of the above
 * @return is NULL (on error) or a pointer to the encoded version buffer
 */
unsigned char *SSL_ESNI_wrap_keyshare(
                const unsigned char *keyshare,
                const size_t keyshare_len,
                const uint16_t curve_id,
                size_t *outlen);

/**
 * @brief Do the client-side SNI encryption during a TLS handshake
 *
 * This is an internal API called as part of the state machine
 * dealing with this extension.
 *
 * @param esnikeys is the SSL_ESNI structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return 1 for success, other otherwise
 */
int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
                size_t  client_random_len,
                unsigned char *client_random,
                uint16_t curve_id,
                size_t  client_keyshare_len,
                unsigned char *client_keyshare,
                CLIENT_ESNI **the_esni);

/**
 * @brief Server-side decryption during a TLS handshake
 *
 * This is the internal API called as part of the state machine
 * dealing with this extension.
 * Note that the decrypted server name is just a set of octets - there
 * is no guarantee it's a DNS name or printable etc. (Same as with
 * SNI generally.)
 *
 * @param esni is the SSL_ESNI structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return NULL for error, or the decrypted servername when it works
 */
unsigned char *SSL_ESNI_dec(SSL_ESNI *esni,
				size_t	client_random_len,
				unsigned char *client_random,
				uint16_t curve_id,
				size_t	client_keyshare_len,
				unsigned char *client_keyshare,
				size_t *encservername_len);

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
 * @brief Duplicate the configuration related fields of an SSL_ESNI
 *
 * This is needed to handle the SSL_CTX->SSL factory model in the
 * server. Clients don't need this.  There aren't too many fields 
 * populated when this is called - essentially just the ESNIKeys and
 * the server private value. For the moment, we actually only
 * deep-copy those.
 *
 * @param orig is the input array of SSL_ESNI to be partly deep-copied
 * @param nesni is the number of elements in the array
 * @param selector allows for picking all (ESNI_SELECT_ALL==-1) or just one of the RR values in orig
 * @return a partial deep-copy array or NULL if errors occur
 */
SSL_ESNI* SSL_ESNI_dup(SSL_ESNI* orig, size_t nesni, int selector);

/*
 * Externally visible Prototypes
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
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ESNIKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ESNI_RRFMT_ASCII_HEX
 *
 * @param ekfmt specifies the format of the input text string
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param esnikeys is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_esnis says how many SSL_ESNI structures are in the returned array
 * @return is an SSL_ESNI structure
 */
SSL_ESNI* SSL_ESNI_new_from_buffer(const short ekfmt, const size_t eklen, const char *esnikeys, int *num_esnis);

/**
 * @brief Turn on SNI encryption for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidde is the hidden service name
 * @param cover is the cleartext SNI name to use
 * @param esni is an array of SSL_ESNI structures
 * @param nesnis says how many structures are in the esni array
 * @param require_hidden_match say whether to require (==1) the TLS server cert matches the hidden name
 * @return 1 for success, error otherwise
 * 
 */
int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni, int nesnis, int require_hidden_match);

/**
 * @brief query the content of an SSL_ESNI structure
 *
 * This function allows the application to examine some internals
 * of an SSL_ESNI structure so that it can then down-select some
 * options. In particular, the caller can see the public_name and
 * IP address related information associated with each ESNIKeys
 * RR value (after decoding and initial checking within the
 * library), and can then choose which of the RR value options
 * the application would prefer to use.
 *
 * @param in is the internal form of SSL_ESNI structure
 * @param out is the returned externally visible detailed form of the SSL_ESNI structure
 * @param nindices is an output saying how many indices are in the SSL_ESNI_ext structure 
 * @return 1 for success, error otherwise
 */
int SSL_esni_query(SSL_ESNI *in, SSL_ESNI_ext **out,int *nindices);

/** 
 * @brief free up memory for an SSL_ESNI_ext
 *
 * @param in is the structure to free up
 * @param size says how many indices are in in
 */
void SSL_ESNI_ext_free(SSL_ESNI_ext *in,int size);

/**
 * @brief utility fnc for application that wants to print an SSL_ESNI_ext
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param se is a pointer to an SSL_ESNI_ext struture
 * @param count is the number of elements in se
 * @return 1 for success, error othewise
 */
int SSL_ESNI_ext_print(BIO* out, SSL_ESNI_ext *se,int count);

/**
 * @brief down-select to use of one option with an SSL_ESNI
 *
 * This allows the caller to select one of the RR values 
 * within an SSL_ESNI for later use.
 *
 * @param in is an SSL_ESNI structure with possibly multiple RR values
 * @param index is the index value from an SSL_ESNI_ext produced from the 'in'
 * @param out is a returned SSL_ESNI containing only that indexed RR value 
 * @return 1 for success, error otherwise
 */
int SSL_esni_reduce(SSL_ESNI *in, int index, SSL_ESNI **out);

/**
 * Turn on SNI Encryption, server-side
 *
 * When this works, the server will decrypt any ESNI seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 *
 * @param s is the SSL server context
 * @param esnikeyfile has the relevant (X25519) private key in PEM format
 * @param esnipubfile has the relevant (binary encoded, not base64) ESNIKeys structure
 * @return 1 for success, other otherwise
 */
int SSL_esni_server_enable(SSL_CTX *s, const char *esnikeyfile, const char *esnipubfile);

/**
 * Access an SSL_ESNI structure note - can include sensitive values!
 *
 * @param s is a an SSL structure, as used on TLS client
 * @param esni is an SSL_ESNI structure
 * @return 1 for success, anything else for failure
 */
int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni);

/**
 * Access an SSL_ESNI structure note - can include sensitive values!
 *
 * @param s is a an SSL_CTX structure, as used on TLS server
 * @param esni is an SSL_ESNI structure
 * @return 0 for failure, non-zero is the number of SSL_ESNI in the array
 */
int SSL_ESNI_get_esni_ctx(SSL_CTX *s, SSL_ESNI **esni);

/** 
 * Print the content of an SSL_ESNI
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param esni is an SSL_ESNI strucutre
 * @param selector allows for picking all (ESNI_SELECT_ALL==-1) or just one of the RR values in orig
 * @return 1 for success, anything else for failure
 * 
 * The esni pointer must point at the full array, and not at
 * the element you want to select using the selector. That is,
 * the implementation here will try access esni[2] if you
 * provide selector value 2.
 */
int SSL_ESNI_print(BIO* out, SSL_ESNI *esni,int selector);

/* 
 * Possible return codes from SSL_get_esni_status
 */

#define SSL_ESNI_STATUS_SUCCESS                 1 ///< Success
#define SSL_ESNI_STATUS_FAILED                  0 ///< Some internal error
#define SSL_ESNI_STATUS_BAD_CALL             -100 ///< Required in/out arguments were NULL
#define SSL_ESNI_STATUS_NOT_TRIED            -101 ///< ESNI wasn't attempted 
#define SSL_ESNI_STATUS_BAD_NAME             -102 ///< ESNI succeeded but the TLS server cert used didn't match the hidden service name
#define SSL_ESNI_STATUS_TOOMANY              -103 ///< ESNI succeeded can't figure out which one!

/**
 * @brief API to allow calling code know ESNI outcome, post-handshake
 *
 * This is intended to be called by applications after the TLS handshake
 * is complete. This works for both client and server. The caller does
 * not have to (and shouldn't) free the hidden or cover strings.
 * TODO: Those are pointers into the SSL struct though so maybe better
 * to allocate fresh ones.
 *
 * Note that the PR we sent to curl will include a check that this
 * function exists (something like "AC_CHECK_FUNCS( SSL_get_esni_status )"
 * so don't change this name without co-ordinating with that.
 * The curl PR: https://github.com/curl/curl/pull/4011
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
