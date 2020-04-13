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
 * This implements the externally-visible functions
 * for handling Encrypted ClientHello (ECHO)
 */

#ifndef OPENSSL_NO_ECHO

# include <openssl/ssl.h>
# include <openssl/echo.h>
# include "ssl_local.h"
# include "echo_local.h"

/*
 * Various ancilliary functions
 */


/**
 * Try figure out ECHOConfig encodng
 *
 * @param eklen is the length of rrval
 * @param rrval is encoded thing
 * @param guessedfmt is our returned guess at the format
 * @return 1 for success, 0 for error
 */
static int echo_guess_fmt(const size_t eklen, 
                    const char *rrval,
                    int *guessedfmt)
{
    if (!guessedfmt || eklen <=0 || !rrval) {
        return(0);
    }
    /* asci hex is easy:-) either case allowed*/
    const char *AH_alphabet="0123456789ABCDEFabcdef";
    /* we actually add a semi-colon here as we accept multiple semi-colon separated values */
    const char *B64_alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;";
    /*
     * Try from most constrained to least in that order
     */
    if (eklen<=strspn(rrval,AH_alphabet)) {
        *guessedfmt=ESNI_RRFMT_ASCIIHEX;
    } else if (eklen<=strspn(rrval,B64_alphabet)) {
        *guessedfmt=ESNI_RRFMT_B64TXT;
    } else {
        // fallback - try binary
        *guessedfmt=ESNI_RRFMT_BIN;
    }
    return(1);
} 

/**
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ECHOKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECHO_RRFMT_ASCII_HEX
 *
 * @param con is the SSL connection 
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param ekval is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echos says how many SSL_ECHO structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_echo_add(SSL *con, const short ekfmt, const size_t eklen, const char *ekval, int *num_echos)
{

    int usedfmt=ECHO_RRFMT_GUESS;
    int rv=0;
    if (ekfmt==ECHO_RRFMT_GUESS) {
        rv=echo_guess_fmt(eklen,ekval,&usedfmt);
        if (rv==0) return(rv);
    } else {
        usedfmt=ekfmt;
    }
    return 1;
}

/**
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ECHOKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECHO_RRFMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param echokeys is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echos says how many SSL_ECHO structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_echo_add(SSL_CTX *ctx, const short ekfmt, const size_t eklen, const char *echokeys, int *num_echos)
{
    return 1;
}

/**
 * @brief Turn on SNI encryption for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidden_name is the hidden service name
 * @param public_name is the cleartext SNI name to use
 * @return 1 for success, error otherwise
 * 
 */
int SSL_echo_server_name(SSL *s, const char *hidden_name, const char *public_name)
{
    return 1;
}

/**
 * @brief Turn on ALPN encryption for an (upcoming) TLS session
 * 
 * @param s is the SSL context
 * @param hidden_alpns is the hidden service alpns
 * @param public_alpns is the cleartext SNI alpns to use
 * @return 1 for success, error otherwise
 * 
 */
int SSL_echo_alpns(SSL *s, const char *hidden_alpns, const char *public_alpns)
{
    return 1;
}

/**
 * @brief query the content of an SSL_ECHO structure
 *
 * This function allows the application to examine some internals
 * of an SSL_ECHO structure so that it can then down-select some
 * options. In particular, the caller can see the public_name and
 * IP address related information associated with each ECHOKeys
 * RR value (after decoding and initial checking within the
 * library), and can then choose which of the RR value options
 * the application would prefer to use.
 *
 * @param in is the SSL session
 * @param out is the returned externally visible detailed form of the SSL_ECHO structure
 * @param nindices is an output saying how many indices are in the ECHO_DIFF structure 
 * @return 1 for success, error otherwise
 */
int SSL_echo_query(SSL *in, ECHO_DIFF **out, int *nindices)
{
    return 1;
}

/** 
 * @brief free up memory for an ECHO_DIFF
 *
 * @param in is the structure to free up
 * @param size says how many indices are in in
 */
void SSL_ECHO_DIFF_free(ECHO_DIFF *in, int size)
{
    return;
}

/**
 * @brief utility fnc for application that wants to print an ECHO_DIFF
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param se is a pointer to an ECHO_DIFF struture
 * @param count is the number of elements in se
 * @return 1 for success, error othewise
 */
int SSL_ECHO_DIFF_print(BIO* out, ECHO_DIFF *se, int count)
{
    return 1;
}

/**
 * @brief down-select to use of one option with an SSL_ECHO
 *
 * This allows the caller to select one of the RR values 
 * within an SSL_ECHO for later use.
 *
 * @param in is an SSL structure with possibly multiple RR values
 * @param index is the index value from an ECHO_DIFF produced from the 'in'
 * @return 1 for success, error otherwise
 */
int SSL_echo_reduce(SSL *in, int index)
{
    return 1;
}

/**
 * Report on the number of ECHO key RRs currently loaded
 *
 * @param s is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_echo_server_key_status(SSL_CTX *s, int *numkeys)
{
    return 1;
}

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
int SSL_CTX_echo_server_flush_keys(SSL_CTX *s, int age)
{
    return 1;
}

/**
 * Turn on ECHO server-side
 *
 * When this works, the server will decrypt any ECHO seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 *
 * @param s is the SSL server context
 * @param con is the SSL connection (can be NULL)
 * @param echokeyfile has the relevant (X25519) private key in PEM format, or both keys
 * @param echopubfile has the relevant (binary encoded, not base64) ECHOKeys structure, or is NULL
 * @return 1 for success, other otherwise
 */
int SSL_CTX_echo_server_enable(SSL_CTX *s, const char *echokeyfile, const char *echopubfile)
{
    return 1;
}

/** 
 * Print the content of an SSL_ECHO
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param con is an SSL session strucutre
 * @param selector allows for picking all (ECHO_SELECT_ALL==-1) or just one of the RR values in orig
 * @return 1 for success, anything else for failure
 * 
 */
int SSL_echo_print(BIO* out, SSL *con, int selector)
{
    return 1;
}

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
int SSL_echo_get_status(SSL *s, char **hidden, char **clear_sni)
{
    return 1;
}

#endif
