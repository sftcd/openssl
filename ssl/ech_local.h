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
 * for internal handling of Encrypted ClientHEllo (ECH)
 */

#ifndef OPENSSL_NO_ECH

#ifndef HEADER_ECH_LOCAL_H
# define HEADER_ECH_LOCAL_H

# include <openssl/ssl.h>
# include <openssl/ech.h>
# include <crypto/hpke.h>

#define ECH_RRTYPE 65439 ///< experimental (as per draft-03, and draft-04) ECH RRTYPE

#define ECH_MIN_ECHCONFIG_LEN 32 ///< just for a sanity check
#define ECH_MAX_ECHCONFIG_LEN 512 ///< just for a sanity check

#define ECH_SELECT_ALL -1 ///< used to duplicate all RRs in SSL_ECH_dup

#define ECH_CIPHER_LEN 4 ///< length of an ECHCipher (2 for kdf, 2 for aead)

#define ECH_OUTERS_MAX 10 ///< max number of TLS extensions that can be compressed via outer-exts


/** 
 * @brief Representation of what goes in DNS
 * <pre>
 *
 *         opaque HpkePublicKey<1..2^16-1>;
 *         uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
 *         uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
 *         uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
 *  
 *         struct {
 *             HpkeKdfId kdf_id;
 *             HpkeAeadId aead_id;
 *         } ECHCipherSuite;
 *
 *       struct {
 *           opaque public_name<1..2^16-1>;
 *           HpkePublicKey public_key;
 *           HkpeKemId kem_id;
 *           ECHCipherSuite cipher_suites<4..2^16-2>;
 *           uint16 maximum_name_length;
 *           Extension extensions<0..2^16-1>;
 *       } ECHConfigContents;
 *
 *       struct {
 *           uint16 version;
 *           uint16 length;
 *           select (ECHConfig.version) {
 *             case 0xff08: ECHConfigContents;
 *           }
 *       } ECHConfig;
 *
 *       ECHConfig ECHConfigs<1..2^16-1>;
 * </pre>
 *
 */
typedef unsigned char ech_ciphersuite_t[ECH_CIPHER_LEN];

typedef struct ech_config_st {
    unsigned int version; ///< 0xff08 for draft-08
    unsigned int public_name_len; ///< public_name
    unsigned char *public_name; ///< public_name
    unsigned int kem_id; ///< HPKE KEM ID to use
    unsigned int pub_len; ///< HPKE public
    unsigned char *pub;
	unsigned int nsuites;
	ech_ciphersuite_t *ciphersuites;
    unsigned int maximum_name_length;
    unsigned int nexts;
    unsigned int *exttypes;
    unsigned int *extlens;
    unsigned char **exts;
} ECHConfig;

typedef struct ech_configs_st {
    unsigned int encoded_len; ///< length of overall encoded content
    unsigned char *encoded; ///< overall encoded content
    int nrecs; ///< Number of records 
    ECHConfig *recs; ///< array of individual records
} ECHConfigs;

/**
 * What we send in the ech CH extension:
 *
 * The TLS presentation language version is:
 *
 * <pre>
 *     struct {
 *       ECHCipherSuite cipher_suite;
 *       opaque config_id<0..255>;
 *       opaque enc<1..2^16-1>;
 *       opaque payload<1..2^16-1>;
 *    } ClientECH;
 * </pre>
 *
 */
typedef struct ech_encch_st {
	unsigned int ciphersuite; ///< ciphersuite 
    size_t config_id_len; ///< identifies DNS RR used
    unsigned char *config_id; ///< identifies DNS RR used
    size_t enc_len; ///< public share
    unsigned char *enc; ///< public share
    size_t payload_len; ///< ciphertext 
    unsigned char *payload; ///< ciphertext 
} ECH_ENCCH;

/**
 * @brief The ECH data structure that's part of the SSL structure 
 *
 * On the client-side, one of these is part of the SSL structure.
 * On the server-side, an array of these is part of the SSL_CTX
 * structure, and we match one of 'em to be part of the SSL 
 * structure when a handshake is in porgress. (Well, hopefully:-)
 *
 * Note that SSL_ECH_dup copies all these fields (when values are
 * set), so if you add, change or remove a field here, you'll also
 * need to modify that (in ssl/ech.c)
 */
typedef struct ssl_ech_st {
    ECHConfigs *cfg; ///< merge of underlying ECHConfigs

    /*
     * SSL/SSL_CTX instantiated things
     */
	unsigned int ciphersuite; ///< chosen from ECHConfig after selection of local preference
    unsigned int kem_id;  ///< our chosen group e.g. X25519
    size_t ech_peer_keyshare_len;  
    unsigned char *ech_peer_keyshare; ///< the encoded peer's public value
    EVP_PKEY *ech_peer_pkey; ///< the peer public as a key
    size_t maximum_name_length; ///< from ECHConfig
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
    EVP_PKEY *keyshare; ///< my own private keyshare to use with  server's ECH share 
    size_t encoded_keyshare_len; 
    unsigned char *encoded_keyshare; ///< my own public key share
    ECH_ENCCH *the_ech; ///< the final outputs for the caller (note: not separately alloc'd)
    /* 
     * File load information servers - if identical filenames not modified since
     * loadtime are added via SSL_ech_serve_enable then we'll ignore the new
     * data. If identical file names that are more recently modified are loaded
     * to a server we'll overwrite this entry.
     */
    char *privfname; ///< name of private key file from which this was loaded
    char *pubfname;  ///< name of private key file from which this was loaded
    time_t loadtime; ///< time public and private key were loaded from file
    /*
     * Stuff about inner/outer diffs for extensions other than SNI
     */
    char *dns_alpns; ///< ALPN values from SVCB/HTTPS RR (as comma-sep string)
    int dns_no_def_alpn; ///< no_def_alpn if set in DNS RR

    /*
     * Inner/Outer things
     */
    unsigned char *innerch;
    size_t innerch_len;
    unsigned char *encoded_innerch;
    size_t encoded_innerch_len;
    int n_outer_only;
    uint16_t outer_only[ECH_OUTERS_MAX];
    /*
     * Placeholder for putting the extension type currently being
     * processed - this is pretty naff but will do for now
     */
    int etype;
    /*
     * API inputs
     */
    char *inner_name;
    char *outer_name;
    
} SSL_ECH;

/**
 * @brief Do the client-side SNI encryption during a TLS handshake
 *
 * This is an internal API called as part of the state machine
 * dealing with this extension.
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param echkeys is the SSL_ECH structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return 1 for success, other otherwise
 */
int SSL_ECH_enc(SSL_CTX *ctx,
                SSL *con,
                SSL_ECH *echkeys, 
                size_t  client_random_len,
                unsigned char *client_random,
                unsigned int curve_id,
                size_t  client_keyshare_len,
                unsigned char *client_keyshare,
                ECH_ENCCH **the_ech);

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
 * @param ech is the SSL_ECH structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return NULL for error, or the decrypted servername when it works
 */
unsigned char *SSL_ECH_dec(SSL_CTX *ctx,
                SSL *con,
                SSL_ECH *ech,
				size_t	client_random_len,
				unsigned char *client_random,
				unsigned int curve_id,
				size_t	client_keyshare_len,
				unsigned char *client_keyshare,
				size_t *encservername_len);

/**
 * Memory management - free an SSL_ECH
 *
 * Free everything within an SSL_ECH. Note that the
 * caller has to free the top level SSL_ECH, IOW the
 * pattern here is: 
 *      SSL_ECH_free(echkeys);
 *      OPENSSL_free(echkeys);
 *
 * @param echkeys is an SSL_ECH structure
 */
void SSL_ECH_free(SSL_ECH *tbf);

/**
 *
 * Free stuff
 * @param tbf is the thing to be free'd
 */
void ECHConfigs_free(ECHConfigs *tbf);

/**
 * @brief Duplicate the configuration related fields of an SSL_ECH
 *
 * This is needed to handle the SSL_CTX->SSL factory model in the
 * server. Clients don't need this.  There aren't too many fields 
 * populated when this is called - essentially just the ECHKeys and
 * the server private value. For the moment, we actually only
 * deep-copy those.
 *
 * @param orig is the input array of SSL_ECH to be partly deep-copied
 * @param nech is the number of elements in the array
 * @param selector allows for picking all (ECH_SELECT_ALL==-1) or just one of the RR values in orig
 * @return a partial deep-copy array or NULL if errors occur
 */
SSL_ECH* SSL_ECH_dup(SSL_ECH* orig, size_t nech, int selector);

/**
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ECHKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECH_FMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection 
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param echkeys is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is an SSL_ECH structure
 */
SSL_ECH* SSL_ECH_new_from_buffer(SSL_CTX *ctx, SSL *con, const short ekfmt, const size_t eklen, const char *echkeys, int *num_echs);

/**
 * @brief After "normal" 1st pass CH is done, fix encoding as needed
 *
 * This will make up the ClientHelloInner and EncodedClientHelloInner buffes
 *
 * @param s is the SSL session
 * @return 1 for success, error otherwise
 */
int ech_encode_inner(SSL *s);

/*
 * Return values from ech_same_ext
 */
#define ECH_SAME_EXT_ERR 0
#define ECH_SAME_EXT_DONE 1
#define ECH_SAME_EXT_CONTINUE 2

/**
 * @brief repeat extension value from inner ch in outer ch and handle outer compression
 * @param s is the SSL session
 * @param pkt is the packet containing extensions
 * @return 0: error, 1: copied existing and done, 2: ignore existing
 */
int ech_same_ext(SSL *s, WPACKET* pkt);

/**
 * @brief print a buffer nicely
 *
 * This is used in SSL_ESNI_print
 */
void ech_pbuf(char *msg,unsigned char *buf,size_t blen);

/*
 * A stab at a "special" copy of the SSL struct
 * from inner to outer, so we can play with
 * changes
 */
int ech_inner2outer_dup(SSL *in);


#endif
#endif
