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
 * This has the externally-visible data structures and prototypes 
 * for handling Encrypted ClientHello (ECH)
 */

#ifndef OPENSSL_NO_ECH

#ifndef HEADER_ECH_H
# define HEADER_ECH_H

/*
 * Temporary symbol for code that is/isn't used
 * when we do up-front ECH decryption on a server
 * that's not part of normal extension handling.
 * (That "up-front" approach is likely what'll be
 * needed long term.)
 * undef this to get back to previously-tested
 * state
 */
#define ECH_UPFRONT_DEC

/*
 * Default for this in hpke.h can be overridden so let's do that
 */
#define HPKE_MAXSIZE 0x280

# include <openssl/ssl.h>
/*
 * Strings used in crypto derivations
 */
#define ECH_CONFIG_ID_STRING (char*) "tls ech config id"
#define ECH_CONTEXT_STRING (char*) "tls ech"
#define ECH_ACCEPT_CONFIRM_STRING (char*) "ech accept confirmation"

#define ECH_MAX_ECHCONFIGS_BUFLEN 2000  /**< max PEM encoded ECHConfigs we'll emit */
#define ECH_MAX_RRVALUE_LEN 2000 /**< Max size of a collection of ECH RR values */
#define ECH_PBUF_SIZE 8*1024 /**<  8K buffer used for print string sent to application via ech_cb */
#define ECH_MAX_DNSNAME 255 /**< max size of a DNS name string (+1 for null and one for luck!) */

/*
 * Known text input formats for ECHKeys RR values
 * - can be TXT containing base64 encoded value (draft-02)
 * - can be TYPE65439 containing ascii-hex string(s)
 * - can be TYPE65439 formatted as output from dig +short (multi-line)
 */
#define ECH_FMT_GUESS     0  /**< try guess which it is */
#define ECH_FMT_BIN       1  /**< binary blob with one or more catenated encoded ECHConfigs */
#define ECH_FMT_B64TXT    2  /**< base64 encoded ECHConfigs (semi-colon separated if >1) */
#define ECH_FMT_ASCIIHEX  3  /**< ascii-hex encoded ECHConfigs (semi-colon separated if >1) */
#define ECH_FMT_HTTPSSVC  4  /**< presentation form of HTTPSSVC */

#define ECH_DRAFT_09_VERSION 0xfe09 /**< ECHConfig version from draft-09 */
#define ECH_DRAFT_10_VERSION 0xfe0a /**< ECHConfig version from draft-10 */

/* 
 * the wire-format code for ECH within an SVCB or HTTPS RData
 */
#define ECH_PCODE_ALPN           0x0001
#define ECH_PCODE_NO_DEF_ALPN    0x0002
#define ECH_PCODE_ECH            0x0005


/**
 * Exterally visible form of an ECHConfigs RR value
 */
typedef struct ech_diff_st {
    int index; /**< externally re-usable reference to this value */
    char *public_name; /**< public_name from ECHKeys */
    char *inner_name; /**< server-name for inner CH */
    char *outer_alpns; /**< outer ALPN string */
    char *inner_alpns; /**< inner ALPN string */
} ECH_DIFF;


/*
 * Externally visible Prototypes
 */


/**
 * @brief Decode/store SVCB/HTTPS RR value provided as (binary or ascii-hex encoded) 
 *
 * rrval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECH_FMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_svcb_add(SSL_CTX *ctx, short rrfmt, size_t rrlen, char *rrval, int *num_echs);

/**
 * @brief Decode/store SVCB/HTTPS RR value provided as (binary or ascii-hex encoded) 
 *
 * rrval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECH_FMT_ASCII_HEX
 *
 * @param con is the SSL connection 
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_svcb_add(SSL *con, int rrfmt, size_t rrlen, char *rrval, int *num_echs);


/**
 * @brief Decode/store ECHConfigs provided as (binary, base64 or ascii-hex encoded) 
 *
 * ekval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECH_FMT_ASCII_HEX
 *
 * @param con is the SSL connection 
 * @param eklen is the length of the ekval
 * @param ekval is the binary, base64 or ascii-hex encoded ECHConfigs
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_ech_add(SSL *con, int ekfmt, size_t eklen, char *echkeys, int *num_echs);

/**
 * @brief Decode/store ECHConfigs provided as (binary, base64 or ascii-hex encoded) 
 *
 * ekval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECH_FMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param eklen is the length of the ekval
 * @param ekval is the binary, base64 or ascii-hex encoded ECHConfigs
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_ech_add(SSL_CTX *ctx, short ekfmt, size_t eklen, char *echkeys, int *num_echs);

/**
 * @brief Set the inner and outer SNI
 * 
 * @param s is the SSL context
 * @param inner_name is the (to be) hidden service name
 * @param outer_name is the cleartext SNI name to use 
 * @return 1 for success, error otherwise
 *
 * Providing a NULL outer_name has a special effect - that means we won't
 * send the ECHConfig.public_name (which is the default). If you prefer 
 * the default, then don't call this. If you supply a non-NULL value and
 * do ECH then the value supplied here will override the ECHConfig.public_name
 */
int SSL_ech_server_name(SSL *s, const char *inner_name, const char *outer_name);

/**
 * @brief Set the outer SNI
 * 
 * @param s is the SSL context
 * @param outer_name is the (to be) hidden service name
 * @return 1 for success, error otherwise
 *
 * Providing a NULL or empty outer_name has a special effect - that means we 
 * won't send the ECHConfig.public_name (which is the default). If you prefer 
 * the default, then don't call this. If you supply a non-NULL value and
 * do ECH then the value supplied here will override the ECHConfig.public_name
 * 
 */
int SSL_ech_set_outer_server_name(SSL *s, const char *outer_name);

/**
 * @brief set the ALPN values for the outer ClientHello 
 *
 * @param s is the SSL_CTX
 * @param protos encodes the ALPN values 
 * @param protos_len is the length of protos
 * @return 1 for success, error otherwise
 */
int SSL_CTX_set_ech_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
                            const size_t protos_len);

/**
 * @brief set the ALPN values for the outer ClientHello 
 *
 * @param s is the SSL session
 * @param protos encodes the ALPN values 
 * @param protos_len is the length of protos
 * @return 1 for success, error otherwise
 */
int SSL_set_ech_alpn_protos(SSL *ssl, const unsigned char *protos,
                        unsigned int protos_len);

/**
 * @brief query the content of an SSL_ECH structure
 *
 * This function allows the application to examine some internals
 * of an SSL_ECH structure so that it can then down-select some
 * options. In particular, the caller can see the public_name and
 * IP address related information associated with each ECHKeys
 * RR value (after decoding and initial checking within the
 * library), and can then choose which of the RR value options
 * the application would prefer to use.
 *
 * @param in is the SSL session
 * @param out is the returned externally visible detailed form of the SSL_ECH structure
 * @param nindices is an output saying how many indices are in the ECH_DIFF structure 
 * @return 1 for success, error otherwise
 */
int SSL_ech_query(SSL *in, ECH_DIFF **out, int *nindices);

/** 
 * @brief free up memory for an ECH_DIFF
 *
 * @param in is the structure to free up
 * @param size says how many indices are in in
 */
void SSL_ECH_DIFF_free(ECH_DIFF *in, int size);

/**
 * @brief utility fnc for application that wants to print an ECH_DIFF
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param se is a pointer to an ECH_DIFF struture
 * @param count is the number of elements in se
 * @return 1 for success, error othewise
 */
int SSL_ECH_DIFF_print(BIO* out, ECH_DIFF *se, int count);

/**
 * @brief down-select to use of one option with an SSL_ECH
 *
 * This allows the caller to select one of the RR values 
 * within an SSL_ECH for later use.
 *
 * @param in is an SSL structure with possibly multiple RR values
 * @param index is the index value from an ECH_DIFF produced from the 'in'
 * @return 1 for success, error otherwise
 */
int SSL_ech_reduce(SSL *in, int index);

/**
 * Report on the number of ECH key RRs currently loaded
 *
 * @param s is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_key_status(SSL_CTX *s, int *numkeys);

/**
 * Zap the set of stored ECH Keys to allow a re-load without hogging memory
 *
 * Supply a zero or negative age to delete all keys. Providing age=3600 will
 * keep keys loaded in the last hour.
 *
 * @param s is the SSL server context
 * @param age don't flush keys loaded in the last age seconds
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_flush_keys(SSL_CTX *s, int age);

/**
 * Turn on ECH server-side
 *
 * When this works, the server will decrypt any ECH seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 *
 * @param s is the SSL server context
 * @param echcfgfile has the relevant ECHConfig(s) and private key in PEM format
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_enable(SSL_CTX *s, const char *echcfgfile);

/*!
 * @brief API to load all the keys found in a directory
 *
 * @param ctx is an SSL_CTX
 * @param echdir is the directory name
 * @oaram number_loaded returns the number of key pairs successfully loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_readpemdir(SSL_CTX *ctx, const char *echdir, int *number_loaded);

#define ECH_SELECT_ALL -1 /**< used to indicate "all" in SSL_ech_print etc. */

/** 
 * Print the content of an SSL_ECH
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param con is an SSL session strucutre
 * @param selector allows for picking all (ECH_SELECT_ALL==-1) or just one of the RR values in orig
 * @return 1 for success, anything else for failure
 * 
 */
int SSL_ech_print(BIO* out, SSL *con, int selector);

/* 
 * Possible return codes from SSL_get_ech_status
 */

#define SSL_ECH_STATUS_GREASE                  2 /**< ECH GREASE happened (if you care:-) */
#define SSL_ECH_STATUS_SUCCESS                 1 /**< Success */
#define SSL_ECH_STATUS_FAILED                  0 /**< Some internal error */
#define SSL_ECH_STATUS_BAD_CALL             -100 /**< Required in/out arguments were NULL */
#define SSL_ECH_STATUS_NOT_TRIED            -101 /**< ECH wasn't attempted  */
#define SSL_ECH_STATUS_BAD_NAME             -102 /**< ECH succeeded but the server cert didn't match the hidden service name */
#define SSL_ECH_STATUS_TOOMANY              -103 /**< ECH succeeded can't figure out which one! */
#define SSL_ECH_STATUS_NOT_CONFIGURED       -104 /**< ECH wasn't even configured */
#define SSL_ECH_STATUS_BACKEND              -105 /**< ECH backend: saw an ech_is_inner */

/**
 * @brief API to allow calling code know ECH outcome, post-handshake
 *
 * This is intended to be called by applications after the TLS handshake
 * is complete. This works for both client and server. The caller does
 * not have to (and shouldn't) free the inner_sni or outer_sni strings.
 * TODO: Those are pointers into the SSL struct though so maybe better
 * to allocate fresh ones.
 *
 * @param s The SSL context (if that's the right term)
 * @param inner_sni will be set to the SNI from the inner CH (if any)
 * @param outer_sni will be set to the SNI from the outer CH (if any)
 * @return 1 for success, other otherwise
 */
int SSL_ech_get_status(SSL *s, char **inner_sni, char **outer_sni);

/**
 * @brief API to allow clients to set a preferred HPKE suite to use when GREASEing
 *
 * @param s is the SSL context
 * @param suite is the relevant suite string
 * @return 1 for success, other otherwise
 */
int SSL_ech_set_grease_suite(SSL *s,const char* suite);

/**
 * @brief provide a way to do raw ECH decryption for split-mode frontends
 *
 * @param ctx is an SSL_CTX
 * @param outer_ch is the entire client hello (possibly incl. ECH)
 * @param outer_len is the length of the above (on input the buffer size)
 * @param inner is the resulting plaintext CH, if all went well
 * @param inner_len is the length of the above (on input the buffer size)
 * @param inner_sni is the inner SNI (if present)
 * @param outer_sni is the outer SNI (if present)
 * @param decrypted_ok is 0 on return if decryption failed, 1 if it worked
 * @return 1 for success (incl. failed decrypt) or 0 on error
 *
 * Note that the outer_ch's length is inside the TLV data
 */
int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx, 
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len, 
                            char **inner_sni, char **outer_sni,
                            int *decrypted_ok);

/**
 * @brief prototype for an ECH callback
 *
 * @param ssl is the SSL session
 * @param str is a string representation of the ECH details
 * @return 1 for success, other otherwise
 */
typedef unsigned int (*SSL_ech_cb_func)(SSL *ssl, char *str);

/**
 * @brief set an ECH callback for the SSL session
 *
 * @param s is the SSL session
 * @param f is the callback function
 *
 * This will be called once an ECH value has been processed.
 * At that point, e.g. SSL_ech_get_status() could be called
 * so the application can find out what happened.
 */ 
void SSL_set_ech_callback(SSL *s, SSL_ech_cb_func f);


/**
 * @brief set an ECH callback for the SSL session
 *
 * @param s is the SSL_CTX
 * @param f is the callback function
 *
 * This will be called once an ECH value has been processed.
 * At that point, e.g. SSL_ech_get_status() could be called
 * so the application can find out what happened.
 */ 
void SSL_CTX_set_ech_callback(SSL_CTX *s, SSL_ech_cb_func f);

#endif
#endif
