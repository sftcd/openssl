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

#define ECH_SUPERVERBOSE  /**< to get bazillions more lines of tracing */

#define ECH_RRTYPE 65439 /**< experimental (as per draft-03, and draft-04) ECH RRTYPE */

#define ECH_MIN_ECHCONFIG_LEN 32 /**< just for a sanity check */
#define ECH_MAX_ECHCONFIG_LEN 512 /**< just for a sanity check */

#define ECH_CIPHER_LEN 4 /**< length of an ECHCipher (2 for kdf, 2 for aead) */

#define ECH_OUTERS_MAX 10 /**< max number of TLS extensions that can be compressed via outer-exts */

#define MAX_ECH_CONFIG_ID_LEN 0x30 /**< max size of ENC-CH config id we'll decode */
#define MAX_ECH_ENC_LEN 0x100 /**< max size of ENC-CH peer key share we'll decode */
#define MAX_ECH_PAYLOAD_LEN 0x200 /**< max size of ENC-CH ciphertext we'll decode */

#define ECH_GREASE_UNKNOWN -1 /**< value for s->ext.ech_grease when we're not yet sure */
#define ECH_NOT_GREASE 0 /**< value for s->ext.ech_grease when decryption worked */
#define ECH_IS_GREASE 1 /**< value for s->ext.ech_grease when decryption failed */

/*
 * This is a special marker value. If set via a specific call
 * to our external API, then we'll override use of the 
 * ECHConfig.public_name and send no outer SNI.
 */
extern char *ech_public_name_override_null;
#define ECH_PUBLIC_NAME_OVERRIDE_NULL  ech_public_name_override_null

/** 
 * @brief Representation of what goes in DNS for draft-09 and draft-10
 *
 * <pre>
 *  draft-09:
 *         opaque HpkePublicKey<1..2^16-1>;
 *         uint16 HpkeKemId;  
 *         uint16 HpkeKdfId; 
 *         uint16 HpkeAeadId;
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
 *
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
 *
 * </pre>
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
    size_t encoding_length;         /* these fields will disappear in -10 */
    unsigned char *encoding_start; /* as they're only needed to calc config_id */
    unsigned int config_id_len;
    unsigned char *config_id;
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
 * The draft-09 TLS presentation language version is:
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
 * For draft-10, we get:
 *
 * <pre>
 *     struct {
 *       HpkeSymmetricCipherSuite cipher_suite;
 *       uint8 config_id;
 *       opaque enc<1..2^16-1>;
 *       opaque payload<1..2^16-1>;
 *    } ClientECH;
 * </pre>
 *
 * The same struct below still works, we can treat
 * changing the config id to a uint8 as a TODO: for
 * now.
 *
 */
typedef struct ech_encch_st {
	uint16_t kdf_id; /**< ciphersuite  */
	uint16_t aead_id; /**< ciphersuite  */
    size_t config_id_len; /**< identifies DNS RR used */
    unsigned char *config_id; /**< identifies DNS RR used */
    size_t enc_len; /**< public share */
    unsigned char *enc; /**< public share */
    size_t payload_len; /**< ciphertext  */
    unsigned char *payload; /**< ciphertext  */
} ECH_ENCCH;

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
     * File load information servers - if identical filenames not modified since
     * loadtime are added via SSL_ech_serve_enable then we'll ignore the new
     * data. If identical file names that are more recently modified are loaded
     * to a server we'll overwrite this entry.
     */
    char *pemfname; /**< name of PEM file from which this was loaded */
    time_t loadtime; /**< time public and private key were loaded from file */
    EVP_PKEY *keyshare; /**< my own private keyshare to use as a server */
    /*
     * Stuff about inner/outer diffs for extensions other than SNI
     * TODO: code that up:-)
     */
    char *dns_alpns; /**< ALPN values from SVCB/HTTPS RR (as comma-sep string) */
    int dns_no_def_alpn; /**< no_def_alpn if set in DNS RR */

} SSL_ECH;

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
 * @brief Free an ECHConfig structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfig_free(ECHConfig *tbf);

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
 * This is used in SSL_ECH_print
 */
void ech_pbuf(const char *msg,const unsigned char *buf,const size_t blen);

/**
 * @brief free an ECH_ENCCH
 * @param tbf is a ptr to an SSL_ECH structure
 */
void ECH_ENCCH_free(ECH_ENCCH *ev);

/*
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
 * @param ac is (preallocated) 8 octet buffer
 * @param shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * @param shlen is the length of the SH buf
 * @return: 1 for success, 0 otherwise
 */
int ech_calc_accept_confirm(SSL *s, unsigned char *acbuf, const unsigned char *shbuf, const size_t shlen);

/*
 * Swap the inner and outer.
 * The only reason to make this a function is because it's
 * likely very brittle - if we need any other fields to be
 * handled specially (e.g. because of some so far untested
 * combination of extensions), then this may fail, so good
 * to keep things in one place as we find that out.
 */
int ech_swaperoo(SSL *s);

/*
 * @brief if we had inner CH cleartext, try parse and process
 * that and then decide whether to swap it for the current 
 * SSL *s - if we decide to, the big swaperoo happens inside
 * here (for now)
 * 
 * @param s is the SSL session
 * @return 1 for success, 0 for failure
int ech_process_inner_if_present(SSL *s); 
 */

void ech_ptranscript(const char* msg,SSL *s);

/*
 * Send grease
 */
int SSL_ech_send_grease(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx);

/*
 * Calc AAD and encrypt
 */
int ech_aad_and_encrypt(SSL *s, WPACKET *pkt);

/*
 * Given CH encoding, return CH minus the ECH value (if present)
 *
 * @param s: SSL session stuff
 * @param ch_len: length of original encoded CH 
 * @param ch: buffer with original encoded CH
 * @param de_len: zero if no ECH present, otherwise length of buffer with CH after ECH taken out
 * @param de: NULL or the above buffer (caller-allocated)
 * @return 1 for success, zero otherwise
 */
int drop_ech_from_ch(SSL *s, const size_t ch_len, const unsigned char *ch,
        size_t *de_len, unsigned char *de);

int ech_make_enc_info(ECHConfig *tc,unsigned char *info,size_t *info_len);

/*
 * @brief reset the handshake buffer for transcript after ECH is good
 *
 * @param s is the session
 * @param buf is the data to put into the transcript (usuallhy inner CH)
 * @param blen is the length of buf
 * @return 1 for success
 */
int ech_reset_hs_buffer(SSL *s, unsigned char *buf, size_t blen);

/*
 * If an ECH is present, attempt decryption
 *
 * @param s: SSL session stuff
 * @param pkt: the received CH that might include an ECH
 * @param newpkt: the plaintext from ECH 
 */
int ech_early_decrypt(SSL *s, PACKET *pkt, PACKET *newpkt);

#endif
#endif
