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

#define ECHO_MAX_RRVALUE_LEN 2000 ///< Max size of a collection of ECHO RR values
#define ECHO_SELECT_ALL -1 ///< used to duplicate all RRs in SSL_ECHO_dup
#define ECHO_PBUF_SIZE 8*1024 ///<  8K buffer used for print string sent to application via echo_cb

/*
 * What value to use to indicate a bogus/missing time value, that might work on 
 * all platforms? I thought about -1 but that might cause some errors if used
 * with gmtime() or similar. Zero isn't distinguishable from a calloc'd buffer
 * so didn't go for that. But a small value that's early in 1970 should be ok
 * here as ECHO was invented more than 40 years later. For now, we'll go with
 * one second into the time_t epoch, but will be happy to bikeshed on this
 * later as needed.
 */
#define ECHO_NOTATIME 1 ///< value used to indicate that a now-defunct not_before/not_after field is bogus

/*
 * ECHOKeys Extensions we know about...
 */
#define ECHO_ADDRESS_SET_EXT 0x1001 ///< AddressSet as per draft-03

/* TODO: find another implemenation of this, there's gotta be one */
#define ECHO_A2B(__c__) (__c__>='0'&&__c__<='9'?(__c__-'0'):\
                        (__c__>='A'&&__c__<='F'?(__c__-'A'+10):\
                            (__c__>='a'&&__c__<='f'?(__c__-'a'+10):0)))


/*
 * Known text input formats for ECHOKeys RR values
 * - can be TXT containing base64 encoded value (draft-02)
 * - can be TYPE65439 containing ascii-hex string(s)
 * - can be TYPE65439 formatted as output from dig +short (multi-line)
 */
#define ECHO_RRFMT_GUESS     0  ///< try guess which it is
#define ECHO_RRFMT_BIN       1  ///< binary encoded
#define ECHO_RRFMT_ASCIIHEX  2  ///< draft-03 ascii hex value(s catenated)
#define ECHO_RRFMT_B64TXT    3  ///< draft-02 (legacy) base64 encoded TXT

/**
 * If defined, this provides enough API, internals and tracing so we can 
 * ensure/check we're generating keys the same way as other code, in 
 * partocular the existing NSS code
 */
#define ECHO_CRYPT_INTEROP
//#undef ECHO_CRYPT_INTEROP
#ifdef ECHO_CRYPT_INTEROP

#define ECHO_GREASE_VERSION 0xffff ///< Fake ECHOKeys version to indicate grease
#define ECHO_DRAFT_02_VERSION 0xff01 ///< ECHOKeys version from draft-02
#define ECHO_DRAFT_03_VERSION 0xff02 ///< ECHOKeys version from draft-03
#define ECHO_DRAFT_04_VERSION 0xff03 ///< ECHOKeys version from draft-04
#define ECHO_DRAFT_05_VERSION 0xff03 ///< ECHOConfig version from draft-05 (sigh - same version!)

#define ECHO_RRTYPE 65439 ///< experimental (as per draft-03, and draft-04) ECHO RRTYPE

#endif

/** 
 * @brief Representation of what goes in DNS
 * <pre>
 * </pre>
 *
 */
typedef struct echo_record_st {
    unsigned int version;
    unsigned char checksum[4];
    size_t public_name_len;
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
    size_t dnsext_offset;
    unsigned int dnsnexts;
    unsigned int *dnsexttypes;
    size_t *dnsextlens;
    unsigned char **dnsexts;
} ECHO_RECORD;

/**
 * What we send in the echo CH extension:
 *
 * The TLS presentation language version is:
 *
 * <pre>
 * </pre>
 *
 * Fields encoded in extension, these are copies, (not malloc'd)
 * of pointers elsewhere in SSL_ECHO. One of these is returned
 * from SSL_ECHO_enc, and is also pointed to from the SSL_ECHO
 * structure.
 *
 */
typedef struct client_echo_st {
	uint16_t ciphersuite;
    size_t encoded_keyshare_len; 
    unsigned char *encoded_keyshare;
    size_t record_digest_len;
    unsigned char *record_digest;
    size_t encrypted_sni_len;
    unsigned char *encrypted_sni;
} CLIENT_ECHO;

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
    unsigned int version; ///< version from underlying ECHO_RECORD/ECHOKeys
    char *encservername; ///< hidden server name
    char *clear_sni; ///< cleartext SNI (can be NULL)
    char *public_name;  ///< public_name from ECHOKeys
    int require_hidden_match; ///< If 1 then SSL_get_echo_status will barf if hidden name doesn't match TLS server cert. If 0, don't care.
    int num_echo_rrs; ///< the number of ECHOKeys structures in this array
    size_t encoded_rr_len;
    unsigned char *encoded_rr; ///< Binary (base64 decoded) RR value
    size_t rd_len;
    unsigned char *rd; ///< Hash of the above (record_digest), using the relevant hash from the ciphersuite
	uint16_t ciphersuite; ///< from ECHOKeys after selection of local preference
    uint16_t group_id;  ///< our chosen group e.g. X25519
    size_t echo_peer_keyshare_len;  
    unsigned char *echo_peer_keyshare; ///< the encoded peer's public value
    EVP_PKEY *echo_peer_pkey; ///< the peer public as a key
    size_t padded_length; ///< from ECHOKeys
    uint64_t not_before; ///< from ECHOKeys (not currently used)
    uint64_t not_after; ///< from ECHOKeys (not currently used)
    int nexts; ///< number of extensions 
    unsigned int *exttypes; ///< array of extension types
    size_t *extlens; ///< lengths of encoded extension octets
    unsigned char **exts; ///< encoded extension octets
    int dnsnexts; ///< number of dns extensions 
    unsigned int *dnsexttypes; ///< array of dns extension types
    size_t *dnsextlens; ///< lengths of encoded dns extension octets
    unsigned char **dnsexts; ///< encoded dns extension octets
    int naddrs; ///< decoded AddressSet cardinality
    BIO_ADDR *addrs; ///< decoded AddressSet values (v4 or v6)
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
    size_t hi_len; 
    unsigned char *hi; ///< ECHOContent encoded (hash input)
    size_t hash_len;
    unsigned char *hash;  ///< hash of hi (encoded ECHOContent)
    size_t realSNI_len; 
    unsigned char *realSNI; ///< padded ECHO
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
    unsigned char *plain; ///< plaintext value for ECHO
    size_t cipher_len;
    unsigned char *cipher; ///< ciphetext value of ECHO
    size_t tag_len;
    unsigned char *tag; ///< GCM tag (already also in ciphertext)
#ifdef ECHO_CRYPT_INTEROP
    char *private_str; ///< for debug purposes, requires special build
#endif
    CLIENT_ECHO *the_echo; ///< the final outputs for the caller (note: not separately alloc'd)
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

/*
 * Non-external Prototypes
 */

/**
 * @brief wrap a "raw" key share in the relevant TLS presentation layer encoding
 *
 * Put the outer length and curve ID around a key share.
 * This just exists because we do it a few times: for the ECHO
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
unsigned char *SSL_ECHO_wrap_keyshare(
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
                uint16_t curve_id,
                size_t  client_keyshare_len,
                unsigned char *client_keyshare,
                CLIENT_ECHO **the_echo);

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
				uint16_t curve_id,
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
void SSL_ECHO_free(SSL_ECHO *echokeys);

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
int SSL_echo_checknames(const char *encservername, const char *clear_sni);

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


/**
 * Report on the number of ECHO key RRs currently loaded
 *
 * @param s is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_echo_server_key_status(SSL_CTX *s, int *numkeys);

/**
 * Zap the set of stored ECHO Keys to allow a re-load without hogging memory
 *
 * Supply a zero or negative age to delete all keys. Providing age=3600 will
 * keep keys loaded in the last hour.
 *
 * @param s is the SSL server context
 * @param age don't flush keys loaded in the last age seconds
 * @return 1 for success, other otherwise
 */
int SSL_CTX_echo_server_flush_keys(SSL_CTX *s, int age);

/**
 * Access an SSL_ECHO structure note - can include sensitive values!
 *
 * @param s is a an SSL structure, as used on TLS client
 * @param echo is an SSL_ECHO structure
 * @return 1 for success, anything else for failure
 */
int SSL_ECHO_get_echo(SSL *s, SSL_ECHO **echo);

/**
 * Access an SSL_ECHO structure note - can include sensitive values!
 *
 * @param s is a an SSL_CTX structure, as used on TLS server
 * @param echo is an SSL_ECHO structure
 * @return 0 for failure, non-zero is the number of SSL_ECHO in the array
 */
int SSL_CTX_get_echo(SSL_CTX *s, SSL_ECHO **echo);

/* 
 * Possible return codes from SSL_get_echo_status
 */

#define SSL_ECHO_STATUS_GREASE                  2 ///< ECHO GREASE happened (if you care:-)
#define SSL_ECHO_STATUS_SUCCESS                 1 ///< Success
#define SSL_ECHO_STATUS_FAILED                  0 ///< Some internal error
#define SSL_ECHO_STATUS_BAD_CALL             -100 ///< Required in/out arguments were NULL
#define SSL_ECHO_STATUS_NOT_TRIED            -101 ///< ECHO wasn't attempted 
#define SSL_ECHO_STATUS_BAD_NAME             -102 ///< ECHO succeeded but the server cert didn't match the hidden service name
#define SSL_ECHO_STATUS_TOOMANY              -103 ///< ECHO succeeded can't figure out which one!

/**
 * @brief API to allow calling code know ECHO outcome, post-handshake
 *
 * This is intended to be called by applications after the TLS handshake
 * is complete. This works for both client and server. The caller does
 * not have to (and shouldn't) free the hidden or clear_sni strings.
 * TODO: Those are pointers into the SSL struct though so maybe better
 * to allocate fresh ones.
 *
 * Note that the PR we sent to curl will include a check that this
 * function exists (something like "AC_CHECK_FUNCS( SSL_get_echo_status )"
 * so don't change this name without co-ordinating with that.
 * The curl PR: https://github.com/curl/curl/pull/4011
 *
 * @param s The SSL context (if that's the right term)
 * @param hidden will be set to the address of the hidden service
 * @param clear_sni will be set to the address of the hidden service
 * @return 1 for success, other otherwise
 */
int SSL_get_echo_status(SSL *s, char **hidden, char **clear_sni);

/*
 * Crypto detailed debugging functions to allow comparison of intermediate
 * values with other code bases (in particular NSS) - these allow one to
 * set values that were generated in another code base's TLS handshake and
 * see if the same derived values are calculated.
 */

/**
 * Allows caller to set the ECDH private value for ECHO. 
 *
 * This is intended to only be used for interop testing - what was
 * useful was to grab the value from the NSS implemtation, force
 * it into mine and see which of the derived values end up the same.
 *
 * @param echo is the SSL_ECHO struture
 * @param private_str is an ASCII-hex encoded X25519 point (essentially
 * a random 32 octet value:-) 
 * @return 1 for success, other otherwise
 *
 */
int SSL_ECHO_set_private(SSL_ECHO *echo, char *private_str);

/**
 * @brief Allows caller to set the nonce value for ECHO. 
 *
 * This is intended to only be used for interop testing - what was
 * useful was to grab the value from the NSS implemtation, force
 * it into mine and see which of the derived values end up the same.
 *
 * @param echo is the SSL_ECHO struture
 * @param nonce points to a buffer with the network byte order value
 * @oaram nlen is the size of the nonce buffer
 * @return 1 for success, other otherwise
 *
 */
int SSL_ECHO_set_nonce(SSL_ECHO *echo, unsigned char *nonce, size_t nlen);

/**
 * @brief Make up a GREASE/fake SSL_ECHO structure
 *
 * When doing GREASE (draft-ietf-tls-grease) we want to make up a
 * phony encrypted SNI. This function will do that:-)
 *
 * If s->echo isn't NULL on input then we leave it alone
 * If s->echo comes back NULL after this call, then we're not greasing
 *
 * TODO: arrange a flag that can be part of the openssl config
 * file to turn greasing on/off globally or as part of normal setup 
 * that allows greasing to be turned on/off per session. That'll
 * default to off for now.
 *
 * @param s is the SSL context
 * @param cp is a pointer to a possible greasy ECHO
 * @return 1 for success, other otherwise
 *
 */
int SSL_ECHO_grease_me(SSL *s, CLIENT_ECHO **cp);

#endif
#endif
