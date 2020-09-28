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

# include <openssl/ssl.h>

#define ECH_MAX_ECHCONFIGS_BUFLEN 2000  ///< max PEM encoded ESNIConfigs we'll emit

#define ECH_MAX_RRVALUE_LEN 2000 ///< Max size of a collection of ECH RR values

#define ECH_PBUF_SIZE 8*1024 ///<  8K buffer used for print string sent to application via ech_cb

#define ECH_MAX_DNSNAME 255 ///< max size of a DNS name string (+1 for null and one for luck!)

/*
 * Known text input formats for ECHKeys RR values
 * - can be TXT containing base64 encoded value (draft-02)
 * - can be TYPE65439 containing ascii-hex string(s)
 * - can be TYPE65439 formatted as output from dig +short (multi-line)
 */
#define ECH_FMT_GUESS     0  ///< try guess which it is
#define ECH_FMT_BIN       1  ///< binary blob with one or more catenated encoded ECHConfigs
#define ECH_FMT_B64TXT    2  ///< base64 encoded ECHConfigs (semi-colon separated if >1)
#define ECH_FMT_ASCIIHEX  3  ///< ascii-hex encoded ECHConfigs (semi-colon separated if >1)
#define ECH_FMT_HTTPSSVC  4  ///< presentation form of HTTPSSVC

#define ECH_GREASE_VERSION 0xffff ///< Fake ECHKeys version to indicate grease
#define ECH_DRAFT_07_VERSION 0xff07 ///< ECHConfig version from draft-07
#define ECH_DRAFT_PRE08_VERSION 0xff08 ///< ECHConfig version from pre-draft-08

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
    int index; ///< externally re-usable reference to this value
    char *public_name; ///< public_name from ECHKeys
    char *inner_name; ///< server-name for inner CH
    char *outer_alpns; ///< outer ALPN string
    char *inner_alpns; ///< inner ALPN string
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
 * @brief Turn on client hello encryption for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidden_name is the hidden service name
 * @param public_name is the cleartext SNI name to use
 * @return 1 for success, error otherwise
 * 
 */
int SSL_ech_server_name(SSL *s, const char *hidden_name, const char *public_name);

/**
 * @brief Add an ALPN for inclusion in ECH for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidden_alpns is the hidden service alpns
 * @param public_alpns is the cleartext SNI alpns to use
 * @return 1 for success, error otherwise
 * 
 */
int SSL_ech_alpns(SSL *s, const char *hidden_alpns, const char *public_alpns);

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

#define SSL_ECH_STATUS_GREASE                  2 ///< ECH GREASE happened (if you care:-)
#define SSL_ECH_STATUS_SUCCESS                 1 ///< Success
#define SSL_ECH_STATUS_FAILED                  0 ///< Some internal error
#define SSL_ECH_STATUS_BAD_CALL             -100 ///< Required in/out arguments were NULL
#define SSL_ECH_STATUS_NOT_TRIED            -101 ///< ECH wasn't attempted 
#define SSL_ECH_STATUS_BAD_NAME             -102 ///< ECH succeeded but the server cert didn't match the hidden service name
#define SSL_ECH_STATUS_TOOMANY              -103 ///< ECH succeeded can't figure out which one!

/**
 * @brief API to allow calling code know ECH outcome, post-handshake
 *
 * This is intended to be called by applications after the TLS handshake
 * is complete. This works for both client and server. The caller does
 * not have to (and shouldn't) free the hidden or clear_sni strings.
 * TODO: Those are pointers into the SSL struct though so maybe better
 * to allocate fresh ones.
 *
 * Note that the PR we sent to curl will include a check that this
 * function exists (something like "AC_CHECK_FUNCS( SSL_get_ech_status )"
 * so don't change this name without co-ordinating with that.
 * The curl PR: https://github.com/curl/curl/pull/4011
 *
 * @param s The SSL context (if that's the right term)
 * @param hidden will be set to the address of the hidden service
 * @param clear_sni will be set to the address of the hidden service
 * @return 1 for success, other otherwise
 */
int SSL_ech_get_status(SSL *s, char **hidden, char **clear_sni);

#endif
#endif
