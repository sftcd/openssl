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
 * This has the internal data structures and prototypes
 * for handling of Encrypted ClientHello (ECH)
 */

#ifndef OPENSSL_NO_ECH

#ifndef HEADER_ECH_LOCAL_H
# define HEADER_ECH_LOCAL_H

# include <openssl/ssl.h>
# include <openssl/ech.h>
# include <crypto/hpke.h>

#define ECH_SUPERVERBOSE  /**< to get bazillions more lines of tracing */

#define ECH_CIPHER_LEN 4 /**< length of an ECHCipher (2 for kdf, 2 for aead) */

/* values for s->ext.ech_grease */
#define ECH_GREASE_UNKNOWN -1 /**< when we're not yet sure */
#define ECH_NOT_GREASE 0 /**< when decryption worked */
#define ECH_IS_GREASE 1 /**< when decryption failed or GREASE wanted */

/* value for uninitialised GREASE ECH version */
#define TLSEXT_TYPE_ech_unknown               0xffff

/* value for not yet set ECH config_id */
#define TLSEXT_TYPE_ech_config_id_unset       -1

/*
 * Strings used in ECH crypto derivations
 */
#define ECH_CONFIG_ID_STRING (char*) "tls ech config id"
#define ECH_CONTEXT_STRING (char*) "tls ech"
#define ECH_ACCEPT_CONFIRM_STRING (char*) "ech accept confirmation"
#define ECH_HRR_CONFIRM_STRING (char*) "hrr ech accept confirmation"

/**
 * @brief Representation of what goes in DNS for draft-10
 *
 * <pre>
 *  draft-10
 *   opaque HpkePublicKey<1..2^16-1>;
 *   uint16 HpkeKemId; 
 *   uint16 HpkeKdfId; 
 *   uint16 HpkeAeadId;
 *   struct {
 *       HpkeKdfId kdf_id;
 *       HpkeAeadId aead_id;
 *   } HpkeSymmetricCipherSuite;
 *   struct {
 *       uint8 config_id;
 *       HpkeKemId kem_id;
 *       HpkePublicKey public_key;
 *       HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
 *   } HpkeKeyConfig;
 *   struct {
 *       HpkeKeyConfig key_config;
 *       uint16 maximum_name_length;
 *       opaque public_name<1..2^16-1>;
 *       Extension extensions<0..2^16-1>;
 *   } ECHConfigContents;
 *   struct {
 *       uint16 version;
 *       uint16 length;
 *       select (ECHConfig.version) {
 *         case 0xfe0a: ECHConfigContents contents;
 *       }
 *   } ECHConfig;
 * </pre>
 *
 * And for draft-13:
 * <pre>
 *     opaque HpkePublicKey<1..2^16-1>;
 *     uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
 *     uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
 *     uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
 *     struct {
 *         HpkeKdfId kdf_id;
 *         HpkeAeadId aead_id;
 *     } HpkeSymmetricCipherSuite;
 *     struct {
 *         uint8 config_id;
 *         HpkeKemId kem_id;
 *         HpkePublicKey public_key;
 *         HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
 *     } HpkeKeyConfig;
 *     struct {
 *         HpkeKeyConfig key_config;
 *         uint8 maximum_name_length;
 *         opaque public_name<1..255>;
 *         Extension extensions<0..2^16-1>;
 *     } ECHConfigContents;
 *     struct {
 *         uint16 version;
 *         uint16 length;
 *         select (ECHConfig.version) {
 *           case 0xfe0d: ECHConfigContents contents;
 *         }
 * </pre>
 *
 * The main diffs from -10 to -13 are that the
 * lengths of public_name and maximum_name_length
 * go from 2 octets (draft-10) to one.
 *
 */
typedef unsigned char ech_ciphersuite_t[ECH_CIPHER_LEN];

typedef struct ech_config_st {
    unsigned int version; /**< 0xff08 for draft-08 */
    unsigned int public_name_len; /**< public_name */
    unsigned char *public_name; /**< public_name */
    unsigned int kem_id; /**< HPKE KEM ID to use */
    unsigned int pub_len; /**< HPKE public */
    unsigned char *pub;
	unsigned int nsuites;
	ech_ciphersuite_t *ciphersuites;
    unsigned int maximum_name_length;
    unsigned int nexts;
    unsigned int *exttypes;
    unsigned int *extlens;
    unsigned char **exts;
    size_t encoding_length;
    unsigned char *encoding_start;
    uint8_t config_id;
} ECHConfig;

typedef struct ech_configs_st {
    unsigned int encoded_len; /**< length of overall encoded content */
    unsigned char *encoded; /**< overall encoded content */
    int nrecs; /**< Number of records  */
    ECHConfig *recs; /**< array of individual records */
} ECHConfigs;

/**
 * What we send in the ech CH extension:
 *
 * For draft-10, we get:
 * <pre>
 *     struct {
 *       HpkeSymmetricCipherSuite cipher_suite;
 *       uint8 config_id;
 *       opaque enc<1..2^16-1>;
 *       opaque payload<1..2^16-1>;
 *    } ClientECH;
 * </pre>
 *
 *
 * For draft-13:
 * <pre>
 *     enum { outer(0), inner(1) } ECHClientHelloType;
 *     struct {
 *        ECHClientHelloType type;
 *        select (ECHClientHello.type) {
 *            case outer:
 *                HpkeSymmetricCipherSuite cipher_suite;
 *                uint8 config_id;
 *                opaque enc<0..2^16-1>;
 *                opaque payload<1..2^16-1>;
 *            case inner:
 *                Empty;
 *        };
 *     } ECHClientHello;
 * </pre>
 *
 */
typedef struct ech_encch_st {
	uint16_t kdf_id; /**< ciphersuite  */
	uint16_t aead_id; /**< ciphersuite  */
    uint8_t config_id; /**< identifies DNS RR used */
    size_t enc_len; /**< public share */
    unsigned char *enc; /**< public share */
    size_t payload_len; /**< ciphertext  */
    unsigned char *payload; /**< ciphertext  */
} ECH_ENCCH;

#define ECH_OUTER_CH_TYPE 0 /**< outer ECHClientHello enum */
#define ECH_INNER_CH_TYPE 1 /**< inner ECHClientHello enum */

/**
 * @brief The ECH data structure that's part of the SSL structure
 *
 * On the client-side, one of these is part of the SSL structure.
 * On the server-side, an array of these is part of the SSL_CTX
 * structure, and we match one of 'em to be part of the SSL
 * structure when a handshake is in progress. (Well, hopefully:-)
 *
 * Note that SSL_ECH_dup copies all these fields (when values are
 * set), so if you add, change or remove a field here, you'll also
 * need to modify that (in ssl/ech.c)
 */
typedef struct ssl_ech_st {
    ECHConfigs *cfg; /**< merge of underlying ECHConfigs */
    /*
     * API input names, or, set on server from CH if ECH worked
     */
    char *inner_name;
    char *outer_name;
    /*
     * File load information - if identical filenames not modified since
     * loadtime are added via SSL_ech_serve_enable then we'll ignore the new
     * data. If identical file names that are more recently modified are loaded
     * to a server we'll overwrite this entry.
     */
    char *pemfname; /**< name of PEM file from which this was loaded */
    time_t loadtime; /**< time public and private key were loaded from file */
    EVP_PKEY *keyshare; /**< my own private keyshare to use as a server */
} SSL_ECH;

/**
 * @brief Free an SSL_ECH
 *
 * Free everything within an SSL_ECH. Note that the
 * caller has to also free the top level SSL_ECH, IOW the
 * pattern here is:
 *      SSL_ECH_free(echkeys);
 *      OPENSSL_free(echkeys);
 *
 * @param echkeys is an SSL_ECH structure
 */
void SSL_ECH_free(SSL_ECH *tbf);

/**
 * @brief Free an ECHConfigs
 * @param tbf is the thing to be free'd
 */
void ECHConfigs_free(ECHConfigs *tbf);

/**
 * @brief Free an ECHConfig structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfig_free(ECHConfig *tbf);

/**
 * @brief Free an ECH_ENCCH
 * @param tbf is a ptr to an SSL_ECH structure
 */
void ECH_ENCCH_free(ECH_ENCCH *ev);

/**
 * @brief Duplicate the configuration related fields of an SSL_ECH
 *
 * This is needed to handle the SSL_CTX->SSL factory model in the
 * server. Clients don't need this.  There aren't too many fields
 * populated when this is called - essentially just the ECHConfigs and
 * the server private value.
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
 * The echkeys value here may be the catenation of multiple encoded ECHKeys RR values.
 * We'll internally try decode and handle those and (later)
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
 * @brief After "normal" 1st pass client CH handling is done, fix encoding as needed
 *
 * This will make up the ClientHelloInner and EncodedClientHelloInner buffers
 *
 * @param s is the SSL session
 * @return 1 for success, error otherwise
 */
int ech_encode_inner(SSL *s);

/*
 * Return values from ech_same_ext, note that the CONTINUE
 * return value might mean something new if the extension
 * handler is ECH "aware" (other than in a trivial sense)
 */
#define ECH_SAME_EXT_ERR 0 /* bummer something wrong */
#define ECH_SAME_EXT_DONE 1 /* proceed with same value in inner/outer */
#define ECH_SAME_EXT_CONTINUE 2 /* generate a new value for outer CH */

/**
 * @brief Replicate extension value from inner ch into outer ch and setup for later outer compression
 * @param s is the SSL session
 * @param pkt is the packet containing extensions
 * @return 0: error, 1: copied existing and done, 2: ignore existing
 */
int ech_same_ext(SSL *s, WPACKET* pkt);

/**
 * @brief Calculate ECH acceptance signal.
 *
 * Handling for the ECH accept_confirmation (see
 * spec, section 7.2) - this is a magic value in
 * the ServerHello.random lower 8 octets that is
 * used to signal that the inner worked. As per
 * the draft-09 spec:
 *
 * accept_confirmation =
 *          Derive-Secret(Handshake Secret,
 *                        "ech accept confirmation",
 *                        ClientHelloInner...ServerHelloECHConf)
 *
 * @param s is the SSL inner context
 * @oaram for_hrr is 1 if this is for an HRR, otherwise for SH
 * @param ac is (preallocated) 8 octet buffer
 * @param shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * @param shlen is the length of the SH buf
 * @return: 1 for success, 0 otherwise
 */
int ech_calc_ech_confirm(SSL *s, int for_hrr, unsigned char *acbuf, 
        const unsigned char *shbuf, const size_t shlen);

/**
 * @brief Swap the inner and outer CH structures as needed..
 *
 * The only reason to make this a function is because it's
 * likely very brittle - if we need any other fields to be
 * handled specially (e.g. because of some so far untested
 * combination of extensions), then this may fail, so good
 * to keep things in one place as we find that out.
 *
 * @param s is the SSL struct
 * @return 1 for success, other value otherwise
 */
int ech_swaperoo(SSL_CONNECTION *s);

/**
 * @brief send a GREASy ECH
 *
 * We send some random stuff that we hope looks like a real ECH
 *
 * The unused parameters are just to match tls_construct_ctos_ech
 * which calls this - that's in case we need 'em later.
 *
 * @param s is the SSL session
 * @param pkt is the in-work CH packet
 * @return 1 for success, 0 otherwise
 */
int ech_send_grease(SSL *s, WPACKET *pkt);

/**
 * @brief Calculate AAD and then do ECH encryption
 *
 * 1. Make up the AAD:
 *      - the HPKE suite
 *      - my HPKE ephemeral public key
 *      - the encoded outer, minus the ECH
 * 2. Do the encryption
 * 3. Put the ECH back into the encoding
 * 4. Encode the outer (again!)
 *
 * @param s is the SSL struct
 * @param pkt is the packet to send
 * @return 1 for success, other otherwise
 */
int ech_aad_and_encrypt(SSL *s, WPACKET *pkt);

/**
 * @brief reset the handshake buffer for transcript after ECH is good
 *
 * @param s is the session
 * @param buf is the data to put into the transcript (usuallhy inner CH)
 * @param blen is the length of buf
 * @return 1 for success
 */
int ech_reset_hs_buffer(SSL *s, unsigned char *buf, size_t blen);

/**
 * @brief If an ECH is present, attempt decryption
 * @param s: SSL session stuff
 * @param pkt: the received CH that might include an ECH
 * @param newpkt: the plaintext from ECH
 */
int ech_early_decrypt(SSL *s, PACKET *pkt, PACKET *newpkt);


/**
 * @brief say if extension at index i in ext_defs is to be ECH compressed
 * @param ind is the index of this extension in ext_defs (and ech_outer_config)
 * @return 1 if this one is to be compressed, 0 if not, -1 for error
 */
int ech_2bcompressed(int ind);

/**
 * @brief Used in tracing
 */
void ech_pbuf(const char *msg,const unsigned char *buf,const size_t blen);
void ech_ptranscript(const char* msg, SSL_CONNECTION *s);

/*!
 * Given a CH find the offsets of the session id, extensions and ECH
 *
 * Offsets are set to zero if relevant thing not found.
 * Offsets are returned to the type or length field in question.
 *
 * @param: s is the SSL session
 * @param: pkt is the CH
 * @param: sessid points to offset of session_id length
 * @param: exts points to offset of extensions
 * @param: echoffset points to offset of ECH
 * @param: echtype points to the ext type of the ECH
 * @param: inner 1 if the ECH is marked as an inner, 0 for outer
 * @param: snioffset points to offset of (outer) SNI
 * @return 1 for success, other otherwise
 */
int ech_get_ch_offsets(
        SSL *s,
        PACKET *pkt,
        size_t *sessid,
        size_t *exts,
        size_t *echoffset,
        uint16_t *echtype,
        int *inner,
        size_t *snioffset);

#endif
#endif
