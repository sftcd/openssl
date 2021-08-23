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
 * for handling Encrypted ClientHello (ECH)
 */


# include <openssl/ssl.h>

#ifndef OPENSSL_NO_ECH

#include <openssl/ssl.h>
#include <openssl/ech.h>
#include "ssl_local.h"
#include "ech_local.h"
#include "statem/statem_local.h"
#include <openssl/rand.h>
#ifndef OPENSSL_NO_SSL_TRACE
#include <openssl/trace.h>
#endif
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* Needed to use stat for file status below in ech_check_filenames */
#include <sys/types.h>
#include <sys/stat.h>
#if !defined(OPENSSL_SYS_WINDOWS)
#include <unistd.h>
#endif
#include "internal/o_dir.h"

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

/* For ossl_assert */
#include "internal/cryptlib.h"

/* For HPKE APIs */
#include <crypto/hpke.h>

/*
 * When doing ECH, this array specifies which inner CH extensions (if
 * any) are to be "compressed" using the outer extensions scheme.
 *
 * Basically, we store a 0 for "don't compress" and a 1 for "do compress"
 * and the index is the same as the index of the extension itself.
 *
 * This is likely to disappear before submitting a PR to upstream as
 * it'd make more sense to make this a new field in the ext_defs table
 * in  ssl/statem/extensions.c
 *
 * For now however, we'll keep it separate as it's still possible that
 * we might develop a better way to handle this. (Or maybe upstream devs
 * will have better ideas, or maybe the standards process will come to
 * its senses and kill the compression idea:-)
 *
 * Reasons this could change include: wanting better than compile-time
 * or handling custom extensions.
 *
 * As with ext_defs in extensions.c: NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the
 * indexes ( TLSEXT_IDX_* ) defined in ssl_local.h.
 *
 * Lotsa notes, eh - that's because I'm not sure this is sane:-)
 */
static int ech_outer_config[]={
     /*TLSEXT_IDX_renegotiate, 0xff01 */ 0,
     /*TLSEXT_IDX_server_name, 0 */ 0,
     /*TLSEXT_IDX_max_fragment_length, 1 */ 1,
     /*TLSEXT_IDX_srp, 12 */ 1,
     /*TLSEXT_IDX_ec_point_formats, 11 */ 1,
     /*TLSEXT_IDX_supported_groups, 10 */ 1,
     /*TLSEXT_IDX_session_ticket, 35 */ 1,
     /*TLSEXT_IDX_status_request, 5 */ 1,
     /*TLSEXT_IDX_next_proto_neg, 13172 */ 1,
     /*TLSEXT_IDX_application_layer_protocol_negotiation, 16 */ 0,
     /*TLSEXT_IDX_use_srtp, 14 */ 1,
     /*TLSEXT_IDX_encrypt_then_mac, 22 */ 1,
     /*TLSEXT_IDX_signed_certificate_timestamp, 18 */ 0,
     /*TLSEXT_IDX_extended_master_secret, 23 */ 1,
     /*TLSEXT_IDX_signature_algorithms_cert, 50 */ 0,
     /*TLSEXT_IDX_post_handshake_auth, 49 */ 0,
     /*TLSEXT_IDX_signature_algorithms, 13 */ 1,
     /*TLSEXT_IDX_supported_versions, 43 */ 1,
     /*TLSEXT_IDX_psk_kex_modes, 45 */ 0,
     /*TLSEXT_IDX_key_share, 51 */ 0,
     /*TLSEXT_IDX_cookie, 44 */ 0,
     /*TLSEXT_IDX_cryptopro_bug, 0xfde8 */ 0,
     /*TLSEXT_IDX_early_data, 42 */ 0,
     /*TLSEXT_IDX_certificate_authorities, 47 */ 0,
     /*TLSEXT_IDX_ech, 0xfe0a */ 0,
     /*TLSEXT_IDX_ech13, 0xfe0d */ 0,
     /*TLSEXT_IDX_outer_extensions, 0xfd00 */ 0,
     /*TLSEXT_IDX_ech_is_inner, 0xda09 */ 0,
     /*TLSEXT_IDX_padding, 21 */ 0,
     /*TLSEXT_IDX_psk, 41 */ 0,
    };

/*
 * When doing ECH, this array specifies whether, when we're not
 * compressing, we want to re-use the inner value in the outer CH 
 * ("0") or whether to generate an independently new value for the
 * outer ("1"). That makes most sense perhaps for the key_share,
 * but maybe also for others, hence being generic.
 *
 * These settings will be ignored for some extensions that don't
 * use the IOSAME macro (in ssl/statem/extensions_clnt.c) - for
 * example the ECH setting below is ignored as you'd imagine.
 *
 * As above this is likely to disappear before submitting a PR to
 * upstream.
 *
 * As with ext_defs in extensions.c: NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the
 * indexes ( TLSEXT_IDX_* ) defined in ssl_local.h.
 */
static int ech_outer_indep[]={
     /*TLSEXT_IDX_renegotiate */ 0,
     /*TLSEXT_IDX_server_name */ 1,
     /*TLSEXT_IDX_max_fragment_length */ 0,
     /*TLSEXT_IDX_srp */ 0,
     /*TLSEXT_IDX_ec_point_formats */ 0,
     /*TLSEXT_IDX_supported_groups */ 0,
     /*TLSEXT_IDX_session_ticket */ 0,
     /*TLSEXT_IDX_status_request */ 0,
     /*TLSEXT_IDX_next_proto_neg */ 0,
     /*TLSEXT_IDX_application_layer_protocol_negotiation */ 1,
     /*TLSEXT_IDX_use_srtp */ 0,
     /*TLSEXT_IDX_encrypt_then_mac */ 0,
     /*TLSEXT_IDX_signed_certificate_timestamp */ 0,
     /*TLSEXT_IDX_extended_master_secret */ 0,
     /*TLSEXT_IDX_signature_algorithms_cert */ 0,
     /*TLSEXT_IDX_post_handshake_auth */ 0,
     /*TLSEXT_IDX_signature_algorithms */ 0,
     /*TLSEXT_IDX_supported_versions */ 0,
     /*TLSEXT_IDX_psk_kex_modes */ 0,
     /*TLSEXT_IDX_key_share */ 1,
     /*TLSEXT_IDX_cookie */ 0,
     /*TLSEXT_IDX_cryptopro_bug */ 0,
     /*TLSEXT_IDX_early_data */ 0,
     /*TLSEXT_IDX_certificate_authorities */ 0,
     /*TLSEXT_IDX_ech */ 0,
     /*TLSEXT_IDX_ech13 */ 0,
     /*TLSEXT_IDX_outer_extensions */ 0,
     /*TLSEXT_IDX_ech_is_inner */ 0,
     /*TLSEXT_IDX_padding */ 0,
     /*TLSEXT_IDX_psk */ 0,
};

/*
 * @brief Decode/check the value from DNS (binary, base64 or ascii-hex encoded)
 *
 * This does the real work, can be called to add to a context or a connection
 * @param eklen length of the binary, base64 or ascii-hex encoded value from DNS
 * @param ekval is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param echs is a pointer to an array of decoded SSL_ECH
 * @return is 1 for success, error otherwise
 */
static int local_ech_add(
        int ekfmt, size_t eklen, unsigned char *ekval,
        int *num_echs, SSL_ECH **echs);

/**
 * @brief free an ECH_DETS
 * @param in the thing to free
 * @return void
 */
static void ECH_DETS_free(ECH_DETS *in);

/**
 * @brief produce a printable string form of an ECHConfigs
 *
 * Note - the caller has to free the string returned if not NULL
 * @param c is the ECHConfigs
 * @return a printable string (or NULL)
 */
static char *ECHConfigs_print(ECHConfigs *c);

/**
 * @brief make up HPKE "info" input as per spec
 * @param tc is the ECHconfig being used
 * @param info is a caller-allocated buffer for results
 * @param info_len is the buffer size on input, used-length on output
 * @return 1 for success, other otherwise
 */
static int ech_make_enc_info(
        ECHConfig *tc,
        unsigned char *info,
        size_t *info_len);

/*
 * Telltales we use when guessing which form of encoded input we've
 * been given for an RR value or ECHConfig
 */
/* asci hex is easy:-) either case allowed, plus a semi-colon separator*/
static const char *AH_alphabet="0123456789ABCDEFabcdef;";
/* b64 plus a semi-colon - we accept multiple semi-colon separated values */
static const char *B64_alphabet=
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;";
/* telltale for ECH HTTPS/SVCB in presentation format, as per svcb draft-06 */
static const char *httpssvc_telltale="ech=";

/*
 * This is a special marker value. If set via a specific call
 * to our external API, then we'll override use of the
 * ECHConfig.public_name and send no outer SNI.
 */
char *ech_public_name_override_null="DON'T SEND ANY OUTER NAME";

/*
 * return values used to decide if a keypair needs reloading or not
 */
#define ECH_KEYPAIR_ERROR          0
#define ECH_KEYPAIR_NEW            1
#define ECH_KEYPAIR_UNMODIFIED     2
#define ECH_KEYPAIR_MODIFIED       3
#define ECH_KEYPAIR_FILEMISSING    4

/**
 * @brief Check if a key pair needs to be (re-)loaded or not
 * @param ctx is the SSL server context
 * @param pemfname is the PEM key filename
 * @param index is the index if we find a match
 * @return zero, ECH_KEYPAIR_UNMODIFIED ECH_KEYPAIR_MODIFIED ECH_KEYPAIR_NEW
 */
static int ech_check_filenames(SSL_CTX *ctx, const char *pemfname,int *index)
{
    struct stat pemstat;
    time_t pemmod;
    int ind=0;
    size_t pemlen=0;

    if (ctx==NULL || pemfname==NULL || index==NULL) return(ECH_KEYPAIR_ERROR);
    /* if we have none, then it is new */
    if (ctx->ext.ech==NULL || ctx->ext.nechs==0) return(ECH_KEYPAIR_NEW);
    /*
     * if no file info, crap out... hmm, that could happen if the
     * disk fails hence different return value - the application may
     * be able to continue anyway...
     */
    if (stat(pemfname,&pemstat) < 0) return(ECH_KEYPAIR_FILEMISSING);

    /* check the time info - we're only gonna do 1s precision on purpose */
#if defined(__APPLE__)
    pemmod=pemstat.st_mtimespec.tv_sec;
#elif defined(OPENSSL_SYS_WINDOWS)
    pemmod=pemstat.st_mtime;
#else
    pemmod=pemstat.st_mtim.tv_sec;
#endif

    /* search list of existing key pairs to see if we have that one already */
    pemlen=strlen(pemfname);
    for(ind=0;ind!=ctx->ext.nechs;ind++) {
        size_t llen=0;
        if (ctx->ext.ech[ind].pemfname==NULL) return(ECH_KEYPAIR_ERROR);
        llen=strlen(ctx->ext.ech[ind].pemfname);
        if (llen==pemlen &&
                !strncmp(ctx->ext.ech[ind].pemfname,pemfname,pemlen)) {
            /* matching files! */
            if (ctx->ext.ech[ind].loadtime<pemmod) {
                /* aha! load it up so */
                *index=ind;
                return(ECH_KEYPAIR_MODIFIED);
            } else {
                /* tell caller no need to bother */
                *index=-1; /* just in case:-> */
                return(ECH_KEYPAIR_UNMODIFIED);
            }
        }
    }
    *index=-1; /* just in case:-> */
    return ECH_KEYPAIR_NEW;
}

/**
 * @brief Decode from TXT RR to binary buffer
 *
 * This is like ct_base64_decode from crypto/ct/ct_b64.c
 * but a) that's static and b) we extend here to allow a
 * sequence of semi-colon separated strings as the input
 * to handle multivalued RRs. If the latter extension
 * were ok (it probably isn't) then we could merge these
 * functions, but better to not do that for now.
 *
 * Decodes the base64 string |in| into |out|.
 * A new string will be malloc'd and assigned to |out|. This will be owned by
 * the caller. Do not provide a pre-allocated string in |out|.
 * The input is modified if multivalued (NULL bytes are added in
 * place of semi-colon separators.
 *
 * @param in is the base64 encoded string
 * @param out is the binary equivalent
 * @return is the number of octets in |out| if successful, <=0 for failure
 */
static int ech_base64_decode(char *in, unsigned char **out)
{
    const char* sepstr=";";
    size_t inlen = 0;
    int i=0;
    int outlen=0;
    unsigned char *outbuf=NULL;
    char *inp=in;
    unsigned char *outp=NULL;
    size_t overallfraglen=0;

    if (!in || !out) return(0);
    inlen = strlen(in);
    if (inlen == 0) {
        *out = NULL;
        return 0;
    }
    /*
     * overestimate of space but easier than base64 finding padding right now
     */
    outbuf = OPENSSL_malloc(inlen);
    if (outbuf == NULL) {
        goto err;
    }
    outp=outbuf;
    while (overallfraglen<inlen) {
        int ofraglen=0;
        /* find length of 1st b64 string */
        size_t thisfraglen=strcspn(inp,sepstr);

        /* For ECH we'll never see this but just so we have bounds */
        if (thisfraglen<=4 || thisfraglen >HPKE_MAXSIZE) {
            goto err;
        }
        if (thisfraglen>inlen) {
            goto err;
        }
        inp[thisfraglen]='\0';
        overallfraglen+=(thisfraglen+1);
        ofraglen = EVP_DecodeBlock(outp, (unsigned char *)inp, thisfraglen);
        if (ofraglen < 0) {
            goto err;
        }
        /* Subtract padding bytes from |outlen|.  More than 2 is malformed. */
        i = 0;
        while (inp[thisfraglen-i-1] == '=') {
            if (++i > 2) {
                goto err;
            }
        }
        outp+=(ofraglen-i);
        outlen+=(ofraglen-i);
        inp+=(thisfraglen+1);
    }
    *out = outbuf;
    return outlen;
err:
    OPENSSL_free(outbuf);
    return -1;
}

/**
 * @brief Read an ECHConfig (only 1) and 1 private key from pemfile
 *
 * The file content should look as below. Note that as github barfs
 * if I provide an actual private key in PEM format, I've reversed
 * the string PRIVATE in the PEM header;-)
 *
 * -----BEGIN ETAVRIP KEY-----
 * MC4CAQAwBQYDK2VuBCIEIEiVgUq4FlrMNX3lH5osEm1yjqtVcQfeu3hY8VOFortE
 * -----END ETAVRIP KEY-----
 * -----BEGIN ECHCONFIG-----
 * AEP/CQBBAAtleGFtcGxlLmNvbQAkAB0AIF8i/TRompaA6Uoi1H3xqiqzq6IuUqFjT2GNT4wzWmF6ACAABAABAAEAAAAA
 * -----END ECHCONFIG-----
 *
 * There are two sensible ways to call this, either supply just a
 * filename (and inputIsFile=1) or else provide a pesudo-filename,
 * a buffer and the buffer length with inputIsFile=0. The buffer
 * should have contents like the PEM strings above.
 *
 * @param pemfile is the name of the file
 * @param ctx is the SSL context
 * @param inputIsFile is 1 if input a filename, 0 if a buffer
 * @param input is a filename or buffer
 * @param inlen is the length of input
 * @param sechs an (output) pointer to the SSL_ECH output
 * @return 1 for success, otherwise error
 */
static int ech_readpemfile(
        SSL_CTX *ctx,
        int inputIsFile,
        const char *pemfile,
        const unsigned char *input,
        size_t inlen,
        SSL_ECH **sechs)
{
    BIO *pem_in=NULL;
    char *pname=NULL;
    char *pheader=NULL;
    unsigned char *pdata=NULL;
    long plen;
    EVP_PKEY *priv=NULL;
    int num_echs=0;
    int rv=1;

    if (ctx==NULL || pemfile==NULL || sechs==NULL) return(0);
    switch (inputIsFile) {
        case 1:
            /* no additional check */
            break;
        case 0:
            if (input==NULL || inlen==0) return(0);
            break;
        default:
            return(0);
    }

    if (inputIsFile==1) {
        if (strlen(pemfile)==0) return(0);
        pem_in = BIO_new(BIO_s_file());
        if (pem_in==NULL) {
            goto err;
        }
        if (BIO_read_filename(pem_in,pemfile)<=0) {
            goto err;
        }
    } else {
        pem_in = BIO_new(BIO_s_mem());
        if (pem_in==NULL) {
            goto err;
        }
        if (BIO_write(pem_in, (void *)input, (int)inlen)<=0) {
            goto err;
        }
    }

    /*
     * Now check and parse inputs
     */
    if (!PEM_read_bio_PrivateKey(pem_in,&priv,NULL,NULL)) {
        goto err;
    }
    if (!priv) {
        goto err;
    }
    if (PEM_read_bio(pem_in,&pname,&pheader,&pdata,&plen)<=0) {
        goto err;
    }
    if (!pname) {
        goto err;
    }
    if (strlen(pname)==0) {
        goto err;
    }
    if (strncmp(PEM_STRING_ECHCONFIG,pname,strlen(pname))) {
        goto err;
    }
    OPENSSL_free(pname);  pname=NULL;
    if (pheader) {
        OPENSSL_free(pheader); pheader=NULL;
    }
    if (plen>=ECH_MAX_ECHCONFIG_LEN) {
        goto err;
    }
    BIO_free(pem_in);
    pem_in=NULL;

    /*
     * Now decode that ECHConfigs
     */
    rv=local_ech_add(ECH_FMT_GUESS,plen,pdata,&num_echs,sechs);
    if (rv!=1) {
        goto err;
    }

    (*sechs)->pemfname=OPENSSL_strdup(pemfile);
    (*sechs)->loadtime=time(0);
    (*sechs)->keyshare=priv;
    if (pheader!=NULL) OPENSSL_free(pheader);
    if (pname!=NULL) OPENSSL_free(pname);
    if (pdata!=NULL) OPENSSL_free(pdata);

    return(1);

err:
    if (priv!=NULL) EVP_PKEY_free(priv);
    if (pheader!=NULL) OPENSSL_free(pheader);
    if (pname!=NULL) OPENSSL_free(pname);
    if (pdata!=NULL) OPENSSL_free(pdata);
    if (pem_in!=NULL) BIO_free(pem_in);
    if (*sechs) { SSL_ECH_free(*sechs); OPENSSL_free(*sechs); *sechs=NULL;}
    return(0);
}

/**
 * @brief Try figure out ECHConfig encodng by looking for telltales
 *
 * We try check from most to least restrictive  to avoid wrong
 * answers. IOW we try from most constrained to least in that
 * order.
 *
 * The wrong answer could be derived with a low probability.
 * If the application can't handle that, then it ought not use
 * the ECH_FMT_GUESS value.
 *
 * @param eklen is the length of rrval
 * @param rrval is encoded thing
 * @param guessedfmt is our returned guess at the format
 * @return 1 for success, 0 for error
 */
static int ech_guess_fmt(size_t eklen,
                    unsigned char *rrval,
                    int *guessedfmt)
{
    if (!guessedfmt || eklen==0 || !rrval) {
        return(0);
    }
    if (strstr((char*)rrval,httpssvc_telltale)) {
        *guessedfmt=ECH_FMT_HTTPSSVC;
    } else if (eklen<=strspn((char*)rrval,AH_alphabet)) {
        *guessedfmt=ECH_FMT_ASCIIHEX;
    } else if (eklen<=strspn((char*)rrval,B64_alphabet)) {
        *guessedfmt=ECH_FMT_B64TXT;
    } else {
        /* fallback - try binary */
        *guessedfmt=ECH_FMT_BIN;
    }
    return(1);
}

/**
 * @brief Free an ECHConfig structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfig_free(ECHConfig *tbf)
{
    unsigned int i=0;
    if (!tbf) return;
    if (tbf->public_name) OPENSSL_free(tbf->public_name);
    if (tbf->pub) OPENSSL_free(tbf->pub);
    if (tbf->ciphersuites) OPENSSL_free(tbf->ciphersuites);
    if (tbf->exttypes) OPENSSL_free(tbf->exttypes);
    if (tbf->extlens) OPENSSL_free(tbf->extlens);
    for (i=0;i!=tbf->nexts;i++) {
        if (tbf->exts[i]) OPENSSL_free(tbf->exts[i]);
    }
    if (tbf->exts) OPENSSL_free(tbf->exts);
    if (tbf->encoding_start) OPENSSL_free(tbf->encoding_start);
    memset(tbf,0,sizeof(ECHConfig));
    return;
}

/**
 * @brief Free an ECHConfigs structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfigs_free(ECHConfigs *tbf)
{
    int i;
    if (!tbf) return;
    if (tbf->encoded) OPENSSL_free(tbf->encoded);
    for (i=0;i!=tbf->nrecs;i++) {
        ECHConfig_free(&tbf->recs[i]);
    }
    if (tbf->recs) OPENSSL_free(tbf->recs);
    memset(tbf,0,sizeof(ECHConfigs));
    return;
}

/*
 * @brief free an ECH_ENCCH
 * @param tbf is a ptr to an SSL_ECH structure
 */
void ECH_ENCCH_free(ECH_ENCCH *ev)
{
    if (!ev) return;
    if (ev->enc!=NULL) OPENSSL_free(ev->enc);
    if (ev->payload!=NULL) OPENSSL_free(ev->payload);
    return;
}


/**
 * @brief Free and NULL a simple malloc'd item
 *
 * Macro to free tbf->X if it's non NULL,
 * and then set it to NULL - that last is
 * sometimes needed if inner and outer CH
 * have common structures so we don't try
 * free twice.
 */
#define CFREE(__x__) \
    if (tbf->__x__) { OPENSSL_free(tbf->__x__); tbf->__x__=NULL; }

/**
 * @brief free an SSL_ECH
 *
 * Free everything within an SSL_ECH. Note that the
 * caller has to free the top level SSL_ECH, IOW the
 * pattern here is:
 *      SSL_ECH_free(tbf);
 *      OPENSSL_free(tbf);
 *
 * @param tbf is a ptr to an SSL_ECH structure
 */
void SSL_ECH_free(SSL_ECH *tbf)
{
    if (!tbf) return;
    if (tbf->cfg) {
        ECHConfigs_free(tbf->cfg);
        OPENSSL_free(tbf->cfg);
    }
    if (tbf->inner_name!=ECH_PUBLIC_NAME_OVERRIDE_NULL) {
        CFREE(inner_name);
    }
    if (tbf->outer_name!=ECH_PUBLIC_NAME_OVERRIDE_NULL) {
        CFREE(outer_name);
    }
    CFREE(pemfname);
    if (tbf->keyshare!=NULL) {
        EVP_PKEY_free(tbf->keyshare); tbf->keyshare=NULL;
    }
    memset(tbf,0,sizeof(SSL_ECH));
    return;
}

/**
 * @brief free an ECH_DETS
 * @param in the thing to free
 * @return void
 */
static void ECH_DETS_free(ECH_DETS *in)
{
    if (!in) return;
    OPENSSL_free(in->public_name);
    OPENSSL_free(in->inner_name);
    OPENSSL_free(in->outer_alpns);
    OPENSSL_free(in->inner_alpns);
    OPENSSL_free(in->echconfig);
    return;
}

/**
 * @brief free up memory for an ECH_DETS
 *
 * @param in is the structure to free up
 * @param size says how many indices are in in
 */
void SSL_ECH_DETS_free(ECH_DETS *in, int size)
{
    int i=0;
    if (!in) return;
    if (size<=0) return;
    for(i=0;i!=size;i++) {
        ECH_DETS_free(&in[i]);
    }
    OPENSSL_free(in);
    return;
}

/**
 * @brief Utility field-copy function (used by macro below)
 *
 * Copy a field old->foo based on old->foo_len to new->foo
 * We allocate one extra octet in case the value is a
 * string and NUL that out.
 *
 * @param old is the source buffer
 * @param len is the source buffer size
 * @return is NULL or the copied buffer
 */
static void *ech_len_field_dup(void *old, unsigned int len)
{
    void *new=NULL;
    if (!old || len==0) return NULL;
    new=(void*)OPENSSL_malloc(len+1);
    if (!new) return 0;
    memcpy(new,old,len);
    memset((unsigned char*)new+len,0,1);
    return new;
}

/**
 * @brief Copy old->f (with length flen) to new->f
 */
#define ECHFDUP(__f__,__flen__) \
    if (old->__flen__!=0) { \
        new->__f__=ech_len_field_dup((void*)old->__f__,old->__flen__); \
        if (new->__f__==NULL) return 0; \
    }

/**
 * @brief deep copy an ECHConfig
 * @param old is the one to copy
 * @param new is the (caller allocated) place to copy-to
 * @return 1 for sucess, other otherwise
 */
static int ECHConfig_dup(ECHConfig *old, ECHConfig *new)
{
    unsigned int i=0;
    if (!new || !old) return 0;
    *new=*old; /* shallow copy, followed by deep copies */
    /* but before deep copy make sure we don't free twice */
    new->ciphersuites=NULL;
    new->exttypes=NULL;
    new->extlens=NULL;
    new->exts=NULL;
    ECHFDUP(pub,pub_len);
    ECHFDUP(public_name,public_name_len);
    new->config_id=old->config_id;
    ECHFDUP(encoding_start,encoding_length);
    if (old->ciphersuites) {
        new->ciphersuites=
            OPENSSL_malloc(old->nsuites*sizeof(ech_ciphersuite_t));
        if (!new->ciphersuites) goto err;
        memcpy(new->ciphersuites,old->ciphersuites,
                old->nsuites*sizeof(ech_ciphersuite_t));
    }
    if (old->nexts) {
        new->exttypes=OPENSSL_malloc(old->nexts*sizeof(old->exttypes[0]));
        if (!new->exttypes) goto err;
        memcpy(new->exttypes,old->exttypes,old->nexts*sizeof(old->exttypes[0]));
        new->extlens=OPENSSL_malloc(old->nexts*sizeof(old->extlens[0]));
        if (!new->extlens) goto err;
        memcpy(new->extlens,old->extlens,old->nexts*sizeof(old->extlens[0]));
        new->exts=OPENSSL_zalloc(old->nexts*sizeof(old->exts[0]));
        if (!new->exts) goto err;
    }
    for (i=0;i!=old->nexts;i++) {
        new->exts[i]=OPENSSL_malloc(old->extlens[i]);
        if (!new->exts[i]) goto err;
        memcpy(new->exts[i],old->exts[i],old->extlens[i]);
    }
    return 1;
err:
    ECHConfig_free(new);
    return(0);
}

/**
 * @brief deep copy an ECHConfigs
 * @param old is the one to copy
 * @param new is the (caller allocated) place to copy-to
 * @return 1 for sucess, other otherwise
 */
static int ECHConfigs_dup(ECHConfigs *old, ECHConfigs *new)
{
    int i=0;
    if (!new || !old) return 0;
    if (old->encoded_len!=0) {
        new->encoded=
            ech_len_field_dup((void*)old->encoded,old->encoded_len);
        if (new->encoded==NULL) return 0;
        new->encoded_len=old->encoded_len;
    }
    new->recs=OPENSSL_malloc(old->nrecs*sizeof(ECHConfig));
    if (!new->recs) return(0);
    new->nrecs=old->nrecs;
    memset(new->recs,0,old->nrecs*sizeof(ECHConfig));
    for (i=0;i!=old->nrecs;i++) {
        if (ECHConfig_dup(&old->recs[i],&new->recs[i])!=1) return(0);
    }
    return(1);
}

/**
 * @brief Decode the first ECHConfigs from a binary buffer
 *
 * (and say how may octets not consumed)
 *
 * @param binbuf is the buffer with the encoding
 * @param binblen is the length of binbunf
 * @param leftover is the number of unused octets from the input
 * @return NULL on error, or a pointer to an ECHConfigs structure
 */
static ECHConfigs *ECHConfigs_from_binary(
        unsigned char *binbuf,
        size_t binblen,
        int *leftover)
{
    ECHConfigs *er=NULL; /* ECHConfigs record */
    ECHConfig  *te=NULL; /* Array of ECHConfig to be embedded in that */
    int rind=0;
    size_t remaining=0;
    PACKET pkt;
    unsigned int olen=0;
    unsigned int ooffset=0;
    size_t not_to_consume=0;

    if (!leftover || !binbuf || !binblen) {
        goto err;
    }
    if (binblen < ECH_MIN_ECHCONFIG_LEN) {
        goto err;
    }
    if (binblen >= ECH_MAX_ECHCONFIG_LEN) {
        goto err;
    }
   
    if (PACKET_buf_init(&pkt,binbuf,binblen)!=1) {
        goto err;
    }

    /*
     * Overall length of this ECHConfigs (olen) still could be
     * less than the input buffer length, (binblen) if the caller has been
     * given a catenated set of binary buffers, which could happen
     * and which we will support
     */
    if (!PACKET_get_net_2(&pkt,&olen)) {
        goto err;
    }
    if (olen < ECH_MIN_ECHCONFIG_LEN || olen > (binblen-2)) {
        goto err;
    }
    if (binblen<=olen) {
        goto err;
    }

    not_to_consume=binblen-olen;
    remaining=PACKET_remaining(&pkt);

    while (remaining>not_to_consume) {
        ECHConfig *ec=NULL;
        unsigned int ech_content_length;
        unsigned char *tmpecstart=NULL;

        te=OPENSSL_realloc(te,(rind+1)*sizeof(ECHConfig));
        if (!te) {
            goto err;
        }
        ec=&te[rind];
        memset(ec,0,sizeof(ECHConfig));

        /* set start of encoding of this ECHConfig */
        ooffset=pkt.curr-binbuf;
        ec->encoding_start=binbuf+ooffset;

        /*
         * Version
         */
        if (!PACKET_get_net_2(&pkt,&ec->version)) {
            goto err;
        }

        /*
         * Grab length of contents, needed in case we
         * want to skip over it, if it's a version we
         * don't support, or if >1 ECHConfig is in the
         * list.
         */
        if (!PACKET_get_net_2(&pkt,&ech_content_length)) {
            goto err;
        }
        remaining=PACKET_remaining(&pkt);
        if ((ech_content_length-2) > remaining) {
            goto err;
        }

        /*
         * check version
         */
        switch(ec->version) {
            case ECH_DRAFT_10_VERSION:
            case ECH_DRAFT_13_VERSION:
                break;
            default:
                /* skip over in case we get something we can handle later */
                {
                    unsigned char *foo=OPENSSL_malloc(ech_content_length);
                    if (!foo) goto err;
                    if (!PACKET_copy_bytes(&pkt, foo, ech_content_length)) {
                        OPENSSL_free(foo);
                        goto err;
                    }
                    OPENSSL_free(foo);
                    remaining=PACKET_remaining(&pkt);
                    continue;
                }
        }

        if (ec->version==ECH_DRAFT_10_VERSION ||
            ec->version==ECH_DRAFT_13_VERSION) {
            PACKET pub_pkt;
    	    PACKET cipher_suites;
    	    int suiteoctets=0;
            unsigned char cipher[ECH_CIPHER_LEN];
            int ci=0;
            PACKET public_name_pkt;
            PACKET exts;

            /* read config_id - a fixed single byte */
            if (!PACKET_copy_bytes(&pkt,&ec->config_id,1)) {
                goto err;
            }

            /* Kem ID */
            if (!PACKET_get_net_2(&pkt,&ec->kem_id)) {
                goto err;
            }

            /* read HPKE public key - just a blob */
            if (!PACKET_get_length_prefixed_2(&pkt, &pub_pkt)) {
                goto err;
            }
            ec->pub_len=PACKET_remaining(&pub_pkt);
            ec->pub=OPENSSL_malloc(ec->pub_len);
            if (ec->pub==NULL) {
                goto err;
            }
            if (PACKET_copy_bytes(&pub_pkt,ec->pub,ec->pub_len)!=1) {
                goto err;
            }

    	    /*
    	     * List of ciphersuites - 2 byte len + 2 bytes per ciphersuite
    	     * Code here inspired by ssl/ssl_lib.c:bytes_to_cipher_list
    	     */
    	    if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites)) {
    	        goto err;
    	    }
    	    suiteoctets=PACKET_remaining(&cipher_suites);
    	    if (suiteoctets<=0 || (suiteoctets%2)==1) {
    	        goto err;
    	    }
    	    ec->nsuites=suiteoctets/ECH_CIPHER_LEN;
    	    ec->ciphersuites=
                OPENSSL_malloc(ec->nsuites*sizeof(ech_ciphersuite_t));
    	    if (ec->ciphersuites==NULL) {
    	        goto err;
    	    }
            while (PACKET_copy_bytes(&cipher_suites, cipher, ECH_CIPHER_LEN)) {
                memcpy(ec->ciphersuites[ci++],cipher,ECH_CIPHER_LEN);
            }
            if (PACKET_remaining(&cipher_suites) > 0) {
                goto err;
            }
            /* Maximum name length */
            if (ec->version==ECH_DRAFT_13_VERSION) {
                unsigned char dat;
                if (!PACKET_copy_bytes(&pkt,&dat,1)) {
                    goto err;
                }
                ec->maximum_name_length=dat;
            } else {
                if (!PACKET_get_net_2(&pkt,&ec->maximum_name_length)) {
                    goto err;
                }
            }

            /* read public_name */
            if (ec->version==ECH_DRAFT_13_VERSION) {
                if (!PACKET_get_length_prefixed_1(&pkt, &public_name_pkt)) {
                    goto err;
                }
                ec->public_name_len=PACKET_remaining(&public_name_pkt);
                if (ec->public_name_len!=0) {
                    if (ec->public_name_len<=1 ||
                        ec->public_name_len>TLSEXT_MAXLEN_host_name) {
                        goto err;
                    }
                    ec->public_name=OPENSSL_malloc(ec->public_name_len+1);
                    if (ec->public_name==NULL) {
                        goto err;
                    }
                    if (PACKET_copy_bytes(&public_name_pkt,
                                ec->public_name,ec->public_name_len)!=1) {
                        goto err;
                    }
                    ec->public_name[ec->public_name_len]='\0';
                }

            } else {
                if (!PACKET_get_length_prefixed_2(&pkt, &public_name_pkt)) {
                    goto err;
                }
                ec->public_name_len=PACKET_remaining(&public_name_pkt);
                if (ec->public_name_len!=0) {
                    if (ec->public_name_len<=1 ||
                            ec->public_name_len>TLSEXT_MAXLEN_host_name) {
                        goto err;
                    }
                    ec->public_name=OPENSSL_malloc(ec->public_name_len+1);
                    if (ec->public_name==NULL) {
                        goto err;
                    }
                    if (PACKET_copy_bytes(&public_name_pkt,
                                ec->public_name,ec->public_name_len)!=1) {
                        goto err;
                    }
                    ec->public_name[ec->public_name_len]='\0';
                }
            }

            /*
             * Extensions: we'll just store 'em for now and maybe parse any
             * we understand later (there are no well defined extensions
             * as of now).
             */
            if (!PACKET_get_length_prefixed_2(&pkt, &exts)) {
                goto err;
            }
            while (PACKET_remaining(&exts) > 0) {
                unsigned int exttype=0;
                unsigned int extlen=0;
                unsigned char *extval=NULL;
                unsigned int *tip=NULL;
                unsigned int *lip=NULL;
                unsigned char **vip=NULL;

                ec->nexts+=1;
                /*
                 * a two-octet length prefixed list of:
                 * two octet extension type
                 * two octet extension length
                 * length octets
                 */
                if (!PACKET_get_net_2(&exts,&exttype)) {
                    goto err;
                }
                if (!PACKET_get_net_2(&exts,&extlen)) {
                    goto err;
                }
                if (extlen>=ECH_MAX_ECHCONFIGEXT_LEN) {
                    goto err;
                }
                if (extlen != 0 ) {
                    extval=(unsigned char*)OPENSSL_malloc(extlen);
                    if (extval==NULL) {
                        goto err;
                    }
                    if (!PACKET_copy_bytes(&exts,extval,extlen)) {
                        OPENSSL_free(extval);
                        goto err;
                    }
                }
                /* assign fields to lists, have to realloc */
                tip=(unsigned int*)OPENSSL_realloc(
                        ec->exttypes,ec->nexts*sizeof(ec->exttypes[0]));
                if (tip==NULL) {
                    if (extval!=NULL) OPENSSL_free(extval);
                    goto err;
                }
                ec->exttypes=tip;
                ec->exttypes[ec->nexts-1]=exttype;
                lip=(unsigned int*)OPENSSL_realloc(
                        ec->extlens,ec->nexts*sizeof(ec->extlens[0]));
                if (lip==NULL) {
                    if (extval!=NULL) OPENSSL_free(extval);
                    goto err;
                }
                ec->extlens=lip;
                ec->extlens[ec->nexts-1]=extlen;
                vip=(unsigned char**)OPENSSL_realloc(
                        ec->exts,ec->nexts*sizeof(unsigned char*));
                if (vip==NULL) {
                    if (extval!=NULL) OPENSSL_free(extval);
                    goto err;
                }
                ec->exts=vip;
                ec->exts[ec->nexts-1]=extval;
            }
   
        } /* END of ECH_DRAFT_10_VERSION ... or 13*/

        /* set length of encoding of this ECHConfig */
        ooffset=pkt.curr-binbuf;
        ec->encoding_length=(binbuf+ooffset)-ec->encoding_start;
        /* copy encoding_start as it might get free'd if a reduce happens */
        tmpecstart=OPENSSL_malloc(ec->encoding_length);
        if (!tmpecstart) goto err;
        memcpy(tmpecstart,ec->encoding_start,ec->encoding_length);
        ec->encoding_start=tmpecstart;

        rind++;
        remaining=PACKET_remaining(&pkt);
    }

    if (PACKET_remaining(&pkt)>binblen) {
        goto err;
    }

    /*
     * Success - make up return value
     */
    *leftover=PACKET_remaining(&pkt);
    er=(ECHConfigs*)OPENSSL_malloc(sizeof(ECHConfigs));
    if (er==NULL) {
        goto err;
    }
    memset(er,0,sizeof(ECHConfigs));
    er->nrecs=rind;
    er->recs=te;
    te=NULL;
    er->encoded_len=binblen;
    er->encoded=binbuf;

    return er;

err:
    if (er) {
        ECHConfigs_free(er);
        OPENSSL_free(er);
        er=NULL;
    }
    if (te) {
        OPENSSL_free(te);
        te=NULL;
    }
    return NULL;
}

/*
 * @brief Decode/check the value from DNS (binary, base64 or ascii-hex encoded)
 *
 * This does the real work, can be called to add to a context or a connection
 *
 * @param eklen length of the binary, base64 or ascii-hex encoded value from DNS
 * @param ekval is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param echs is a pointer to an array of decoded SSL_ECH
 * @return is 1 for success, error otherwise
 */
static int local_ech_add(
        int ekfmt,
        size_t eklen,
        unsigned char *ekval,
        int *num_echs,
        SSL_ECH **echs)
{
    /*
     * Sanity checks on inputs
     */
    int detfmt=ECH_FMT_GUESS;
    int rv=0;
    unsigned char *outbuf = NULL; /* sequence of ECHConfigs (binary) */
    size_t declen=0; /* length of the above */
    char *ekcpy=(char*)ekval;
    int done=0;
    unsigned char *outp=outbuf;
    int oleftover=0;
    int nlens=0;
    SSL_ECH *retechs=NULL;
    SSL_ECH *newech=NULL;
    int cfgind=0;

    if (eklen==0 || !ekval || !num_echs) {
        return(0);
    }
    if (eklen>=ECH_MAX_RRVALUE_LEN) {
        return(0);
    }
    switch (ekfmt) {
        case ECH_FMT_GUESS:
            rv=ech_guess_fmt(eklen,ekval,&detfmt);
            if (rv==0)  {
                return(rv);
            }
            break;
        case ECH_FMT_HTTPSSVC:
        case ECH_FMT_ASCIIHEX:
        case ECH_FMT_B64TXT:
        case ECH_FMT_BIN:
            detfmt=ekfmt;
            break;
        default:
            return(0);
    }
    /*
     * Do the various decodes
     */
    if (detfmt==ECH_FMT_HTTPSSVC) {
        ekcpy=strstr((char*)ekval,httpssvc_telltale);
        if (ekcpy==NULL) {
            return(rv);
        }
        /* point ekcpy at b64 encoded value */
        if (strlen(ekcpy)<=strlen(httpssvc_telltale)) {
            return(rv);
        }
        ekcpy+=strlen(httpssvc_telltale);
        detfmt=ECH_FMT_B64TXT; /* tee up next step */
    }
    if (detfmt==ECH_FMT_B64TXT) {
        /* need an int to get -1 return for failure case */
        int tdeclen = ech_base64_decode(ekcpy, &outbuf);
        if (tdeclen <= 0) {
            goto err;
        }
        declen=tdeclen;
    }
    if (detfmt==ECH_FMT_ASCIIHEX) {
        int adr=hpke_ah_decode(eklen,ekcpy,&declen,&outbuf);
        if (adr==0) {
            goto err;
        }
    }
    if (detfmt==ECH_FMT_BIN) {
        /* just copy over the input to where we'd expect it */
        declen=eklen;
        outbuf=OPENSSL_malloc(declen);
        if (outbuf==NULL){
            goto err;
        }
        memcpy(outbuf,ekcpy,declen);
    }
    /*
     * Now try decode the catenated binary encodings if we can
     * (But we'll probably only get one:-)
     */
    outp=outbuf;
    oleftover=declen;
    while (!done) {
        SSL_ECH *ts=NULL;
        int leftover=oleftover;
        ECHConfigs *er=NULL;
        ECHConfig  *ec=NULL;

        nlens+=1;
        ts=OPENSSL_realloc(retechs,nlens*sizeof(SSL_ECH));
        if (!ts) {
            goto err;
        }
        retechs=ts;
        newech=&retechs[nlens-1];
        memset(newech,0,sizeof(SSL_ECH));
   
        er=ECHConfigs_from_binary(outp,oleftover,&leftover);
        if (er==NULL) {
            goto err;
        }
        newech->cfg=er;

        /*
         * If needed, flatten the storage so each SSL_ECH has exactly
         * one ECHConfig which has exactly one public key, thus enabling
         * the application to sensibly downselect if they wish.
         */
        if (er->nrecs>1) {
            /* need bit more space to flatten into */
            ts=OPENSSL_realloc(retechs,(nlens+er->nrecs-1)*sizeof(SSL_ECH));
            if (!ts) {
                goto err;
            }
            retechs=ts;
            /* move the cfgs up a level as needed */
            for (cfgind=0;cfgind!=er->nrecs-1;cfgind++) {
                if (retechs[nlens-1].inner_name) {
                    retechs[nlens+cfgind].inner_name=
                        OPENSSL_strdup(retechs[nlens-1].inner_name);
                    if (!retechs[nlens+cfgind].inner_name) goto err;
                } else
                    retechs[nlens+cfgind].inner_name=NULL;
                if (retechs[nlens-1].outer_name) {
                    retechs[nlens+cfgind].outer_name=
                        OPENSSL_strdup(retechs[nlens-1].outer_name);
                    if (!retechs[nlens+cfgind].outer_name) goto err;
                } else
                    retechs[nlens+cfgind].outer_name=NULL;
                retechs[nlens+cfgind].pemfname=NULL;
                retechs[nlens+cfgind].loadtime=0;
                retechs[nlens+cfgind].keyshare=NULL;
                retechs[nlens+cfgind].cfg=
                    OPENSSL_malloc(sizeof(ECHConfigs));
                if (!retechs[nlens+cfgind].cfg) goto err;
                retechs[nlens+cfgind].cfg->nrecs=1;
                ec=OPENSSL_malloc(sizeof(ECHConfig));
                if (!ec) goto err;
                /* note - shallow copy is correct on next line */
                *ec=retechs[nlens-1].cfg->recs[cfgind+1];
                retechs[nlens+cfgind].cfg->recs=ec;
                retechs[nlens+cfgind].cfg->encoded_len=
                    retechs[nlens-1].cfg->encoded_len;
                retechs[nlens+cfgind].cfg->encoded=
                    OPENSSL_malloc(retechs[nlens-1].cfg->encoded_len);
                if (!retechs[nlens+cfgind].cfg->encoded) goto err;
                memcpy(retechs[nlens+cfgind].cfg->encoded,
                       retechs[nlens-1].cfg->encoded,
                        retechs[nlens-1].cfg->encoded_len);

            }
            nlens+=er->nrecs-1;
            er->nrecs=1;
        }

        if (leftover<=0) {
           done=1;
        }
        oleftover=leftover;
        outp+=er->encoded_len;
    }

    *num_echs=nlens;
    *echs=retechs;

    return(1);

err:
    if (outbuf!=NULL) {
        OPENSSL_free(outbuf);
    }
    return(0);
}

/**
 * @brief decode the DNS name in a binary RRData
 *
 * Encoding as defined in https://tools.ietf.org/html/rfc1035#section-3.1
 *
 * @param buf points to the buffer (in/out)
 * @param remaining points to the remaining buffer length (in/out)
 * @param dnsname returns the string form name on success
 * @return is 1 for success, error otherwise
 */
static int local_decode_rdata_name(
        unsigned char **buf,
        size_t *remaining,
        char **dnsname)
{
    unsigned char *cp=NULL;
    size_t rem=0;
    char *thename=NULL,*tp=NULL;
    unsigned char clen=0; /* chunk len */

    if (buf==NULL) return(0);
    if (remaining==NULL) return(0);
    rem=*remaining;
    if (dnsname==NULL) return(0);
    thename=OPENSSL_malloc(TLSEXT_MAXLEN_host_name);
    if (thename==NULL) {
        return(0);
    }
    cp=*buf;
    tp=thename;

    clen=*cp++;
    if (clen==0) {
        /*
         * special case - return "." as name
         */
        thename[0]='.';
        thename[1]=0x00;
    }
    while(clen!=0) {
        if (clen>rem) { OPENSSL_free(thename); return(1); }
        memcpy(tp,cp,clen);
        tp+=clen;
        *tp='.'; tp++;
        cp+=clen; rem-=clen+1;
        clen=*cp++;
    }

    *buf=cp;
    *remaining=rem;
    *dnsname=thename;
    return(1);
}

/**
 * @brief Decode/store ECHConfigs (binary, base64, or ascii-hex encoded)
 *
 * ekval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be
 * e.g. ECH_FMT_ASCII_HEX, or ECH_FMT_GUESS
 *
 * @param con is the SSL connection
 * @param eklen is the length of the ekval
 * @param ekval is the binary, base64 or ascii-hex encoded ECHConfigs
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_ech_add(
        SSL *con,
        int ekfmt,
        size_t eklen,
        char *ekval,
        int *num_echs)
{
    int rv=1;
    SSL_ECH *echs=NULL;
    SSL_CONNECTION *con = SSL_CONNECTION_FROM_SSL(s);

    /*
     * Sanity checks on inputs
     */
    if (!con) {
        return(0);
    }
    rv=local_ech_add(ekfmt,eklen,(unsigned char*)ekval,num_echs,&echs);
    if (rv!=1) {
        return(0);
    }
    con->ech=echs;
    con->nechs=*num_echs;
    con->ext.ech_attempted=1;
    con->ext.ech_attempted_type=TLSEXT_TYPE_ech_unknown;
    return(1);

}

/**
 * @brief Decode/store ECHConfigs (binary, base64 or ascii-hex encoded)
 *
 * ekval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be
 * e.g. ECH_FMT_ASCII_HEX, or ECH_FMT_GUESS
 *
 * @param ctx is the parent SSL_CTX
 * @param eklen is the length of the ekval
 * @param ekval is the binary, base64 or ascii-hex encoded ECHConfigs
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_ech_add(
        SSL_CTX *ctx,
        short ekfmt,
        size_t eklen,
        char *ekval,
        int *num_echs)
{
    SSL_ECH *echs=NULL;
    int rv=1;
    /*
     * Sanity checks on inputs
     */
    if (!ctx) {
        return(0);
    }
    rv=local_ech_add(ekfmt,eklen,(unsigned char*)ekval,num_echs,&echs);
    if (rv!=1) {
        return(0);
    }
    ctx->ext.ech=echs;
    ctx->ext.nechs=*num_echs;
    return(1);
}

/**
 * @brief Try turn on ECH for an (upcoming) TLS session on a client
 *
 * If outer_name is provided via this API as NULL, then
 * we'll use the ECHConfig.public_name.
 * If outer_name is ECH_PUBLIC_NAME_OVERRIDE_NULL then
 * no outer SNI will be sent.
 * If outer_name is not NULL then that value will override
 * the ECHConfig.public_name.
 *
 * For inner_name, a non-NULL value set will be sent as
 * the inner SNI (if things work).
 * If the inner_name is NULL, then no SNI will be sent
 * in the inner CH.
 *
 * @param s is the SSL context
 * @param inner_name is NULL or the hidden service name
 * @param outer_name is NULL or the the cleartext SNI to use
 * @return 1 for success, error otherwise
 *
 */
int SSL_ech_server_name(SSL *ssl, const char *inner_name, const char *outer_name)
{
    int nind=0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s==NULL) return(0);
    if (s->ech==NULL) return(0);

    for (nind=0;nind!=s->nechs;nind++) {
        if (s->ech[nind].inner_name!=NULL)
            OPENSSL_free(s->ech[nind].outer_name);
        if (inner_name!=NULL && strlen(inner_name)>0)
            s->ech[nind].inner_name=OPENSSL_strdup(inner_name);
        else s->ech[nind].inner_name=NULL;
        if (s->ech[nind].outer_name!=NULL &&
                s->ech[nind].outer_name!=ECH_PUBLIC_NAME_OVERRIDE_NULL)
            OPENSSL_free(s->ech[nind].outer_name);
        if (outer_name!=NULL && strlen(outer_name)>0 &&
                outer_name!=ECH_PUBLIC_NAME_OVERRIDE_NULL)
            s->ech[nind].outer_name=OPENSSL_strdup(outer_name);
        else if (outer_name==ECH_PUBLIC_NAME_OVERRIDE_NULL)
            s->ech[nind].outer_name=ECH_PUBLIC_NAME_OVERRIDE_NULL;
        else s->ech[nind].outer_name=NULL;
    }

    s->ext.ech_attempted=1;
    s->ext.ech_attempted_type=TLSEXT_TYPE_ech_unknown;
    return 1;
}

/**
 * @brief Set the outer SNI
 *
 * If outer_name is provided via this API as NULL, then
 * we'll use the ECHConfig.public_name.
 * If outer_name is ECH_PUBLIC_NAME_OVERRIDE_NULL then
 * no outer SNI will be sent.
 * If outer_name is not NULL then that value will override
 * the ECHConfig.public_name.
 *
 * @param ssl is the SSL context
 * @param outer_name is the (to be) hidden service name
 * @return 1 for success, error otherwise
 */
int SSL_ech_set_outer_server_name(SSL *ssl, const char *outer_name)
{
    int nind=0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s==NULL) return(0);
    if (s->ech==NULL) return(0);
    for (nind=0;nind!=s->nechs;nind++) {

        if (s->ech[nind].outer_name!=NULL &&
                s->ech[nind].outer_name!=ECH_PUBLIC_NAME_OVERRIDE_NULL)
            OPENSSL_free(s->ech[nind].outer_name);
        if (outer_name!=NULL && strlen(outer_name)>0 &&
                outer_name!=ECH_PUBLIC_NAME_OVERRIDE_NULL)
            s->ech[nind].outer_name=OPENSSL_strdup(outer_name);
        else if (outer_name==ECH_PUBLIC_NAME_OVERRIDE_NULL)
            s->ech[nind].outer_name=ECH_PUBLIC_NAME_OVERRIDE_NULL;
        else s->ech[nind].outer_name=NULL;
        /* if this is called and an SNI is set already we copy that to inner */
        if (s->ext.hostname) {
            if (s->ech[nind].inner_name!=NULL)
                OPENSSL_free(s->ech[nind].outer_name);
            s->ech[nind].inner_name=OPENSSL_strdup(s->ext.hostname);
        }
   
    }

    s->ext.ech_attempted=1;
    s->ext.ech_attempted_type=TLSEXT_TYPE_ech_unknown;
    return 1;
}

/**
 * @brief Set the outer SNI
 *
 * If outer_name is provided via this API as NULL, then
 * we'll use the ECHConfig.public_name.
 * If outer_name is ECH_PUBLIC_NAME_OVERRIDE_NULL then
 * no outer SNI will be sent.
 * If outer_name is not NULL then that value will override
 * the ECHConfig.public_name.
 *
 * @param s is the SSL_CTX
 * @param outer_name is the (to be) hidden service name
 * @return 1 for success, error otherwise
 */
int SSL_CTX_ech_set_outer_server_name(SSL_CTX *s, const char *outer_name)
{
    int nind=0;
    if (s==NULL) return(0);
    if (s->ext.ech==NULL) return(0);

    for (nind=0;nind!=s->ext.nechs;nind++) {

        if (s->ext.ech[nind].outer_name!=NULL &&
                s->ext.ech[nind].outer_name!=ECH_PUBLIC_NAME_OVERRIDE_NULL)
            OPENSSL_free(s->ext.ech[nind].outer_name);
        if (outer_name!=NULL && strlen(outer_name)>0 &&
                outer_name!=ECH_PUBLIC_NAME_OVERRIDE_NULL)
            s->ext.ech[nind].outer_name=OPENSSL_strdup(outer_name);
        else if (outer_name==ECH_PUBLIC_NAME_OVERRIDE_NULL)
            s->ext.ech[nind].outer_name=ECH_PUBLIC_NAME_OVERRIDE_NULL;
        else s->ext.ech[nind].outer_name=NULL;

    }

    return 1;
}

/**
 * @brief return a printable form of alpn
 *
 * ALPNs are multi-valued, with lengths between, we
 * map that to a comma-sep list
 *
 * @param alpn is the buffer with alpns
 * @param len is the length of the above
 * @return buffer with string form (caller has to free)
 */
static char *alpn_print(unsigned char *alpn, size_t len)
{
    size_t ind=0;
    char *vstr=NULL;
    vstr=OPENSSL_malloc(len+1);
    if (!vstr) return NULL;
    if (!alpn || len==0) return NULL;
    while (ind<len) {
        size_t vlen=alpn[ind];
        if (ind+vlen>(len-1)) return NULL;
        memcpy(&vstr[ind],&alpn[ind+1],vlen);
        vstr[ind+vlen]=',';
        ind+=(vlen+1);
    }
    vstr[len-1]='\0';
    return vstr;
}

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
 * @param ssl is the SSL session
 * @param out is the externally visible form of the SSL_ECH structure
 * @param nindices says how many entries are in the ECH_DETS structure
 * @return 1 for success, error otherwise
 */
int SSL_ech_query(SSL *ssl, ECH_DETS **out, int *nindices)
{
    ECH_DETS *rdiff=NULL;
    int i=0;
    int indices=0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (!s || !out || !nindices) goto err;
    indices=s->nechs;
    if (!s->ech || s->nechs<=0) {
        *out=NULL;
        *nindices=0;
        return 1;
    }
    rdiff=OPENSSL_zalloc(s->nechs*sizeof(ECH_DETS));
    if (rdiff==NULL) goto err;
    for (i=0;i!=s->nechs;i++) {
        ECH_DETS *inst=&rdiff[i];
        if (s->ech->inner_name) {
            inst->inner_name=OPENSSL_strdup(s->ech->inner_name);
            if (!inst->inner_name) goto err;
        }
        if (s->ech->outer_name) {
            inst->public_name=OPENSSL_strdup(s->ech->outer_name);
            if (!inst->public_name) goto err;
        }
        if (s->ext.alpn) {
            inst->inner_alpns=alpn_print(s->ext.alpn,s->ext.alpn_len);
        }
        if (s->ext.alpn_outer) {
            inst->outer_alpns=
                alpn_print(s->ext.alpn_outer,s->ext.alpn_outer_len);
        }
        /*
         * Now "print" the ECHConfig(s)
         */
        if (s->ech[i].cfg) {
            inst->echconfig=ECHConfigs_print(s->ech[i].cfg);
        }
    }
    *nindices=indices;
    *out=rdiff;
    return 1;
err:
    SSL_ECH_DETS_free(rdiff,indices);
    return 0;
}

/**
 * @brief utility fnc for application that wants to print an ECH_DETS
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param se is a pointer to an ECH_DETS struture
 * @param count is the number of elements in se
 * @return 1 for success, error othewise
 */
int SSL_ECH_DETS_print(BIO* out, ECH_DETS *se, int count)
{
    int i=0;
    if (!out || !se || count==0) return 0;
    BIO_printf(out,"ECH details (%d configs total)\n",count);
    for (i=0;i!=count;i++) {
        BIO_printf(out,
        "index: %d: SNI (inner:%s;outer:%s), ALPN (inner:%s;outer:%s)\n\t%s\n",
               i,
               se[i].inner_name?se[i].inner_name:"NULL",
               se[i].public_name?se[i].public_name:"NULL",
               se[i].inner_alpns?se[i].inner_alpns:"NULL",
               se[i].outer_alpns?se[i].outer_alpns:"NULL",
               se[i].echconfig?se[i].echconfig:"NULL");
    }
    return 1;
}

/**
 * @brief down-select to use of one option with an SSL_ECH
 *
 * This allows the caller to select one of the ECHConfig values
 * within an SSL_ECH for later use.
 *
 * @param ssl is an SSL structure with possibly multiple ECHConfigs
 * @param index is the index value from an ECH_DETS produced from the 'in'
 * @return 1 for success, error otherwise
 */
int SSL_ech_reduce(SSL *ssl, int index)
{
    SSL_ECH *new=NULL;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    int i=0;

    if (!s) return 0;
    if (index<0) return 0;
    if (!s->ech) return 0;
    if (s->nechs<=0) return 0;
    if (s->nechs<=index) return 0;
    /*
     * Copy the one to keep, then zap the pointers at that element in the array
     * free the array and fix s back up
     */
    new=OPENSSL_malloc(sizeof(SSL_ECH));
    if (!new) return 0;
    *new=s->ech[index];
    memset(&s->ech[index],0,sizeof(SSL_ECH));
    for(i=0;i!=s->nechs;i++) {
        SSL_ECH_free(&s->ech[i]);
    }
    OPENSSL_free(s->ech);
    s->ech=new;
    s->nechs=1;
    return 1;
}

/**
 * @brief Report on the number of ECH key RRs currently loaded
 *
 * @param s is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_key_status(SSL_CTX *s, int *numkeys)
{
    if (!numkeys) return 0;
    if (s->ext.ech) *numkeys=s->ext.nechs;
    else *numkeys=0;
    return 1;
}

/**
 * @brief Zap the stored ECH Keys to allow a re-load without hogging memory
 *
 * Supply a zero or negative age to delete all keys. Providing age=3600 will
 * keep keys loaded in the last hour.
 *
 * @param s is the SSL server context
 * @param age don't flush keys loaded in the last age seconds
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_flush_keys(SSL_CTX *s, int age)
{
    time_t now=time(0);
    int i=0;
    int deleted=0; /* number deleted */
    if (s==NULL) return 0;
    if (s->ext.ech==NULL) return 1;
    if (s->ext.nechs==0) return 1;
    if (age<=0) {
        SSL_ECH_free(s->ext.ech);
        OPENSSL_free(s->ext.ech);
        s->ext.ech=NULL;
        s->ext.nechs=0;
        return 1;
    }
    /*
     * Otherwise go through them and delete as needed
     */
    for (i=0;i!=s->ext.nechs;i++) {
        SSL_ECH *ep=&s->ext.ech[i];
        if ((ep->loadtime + age) <= now ) {
            SSL_ECH_free(ep);
            deleted++;
            continue;
        }
        s->ext.ech[i-deleted]=s->ext.ech[i]; /* struct copy! */
    }
    s->ext.nechs -= deleted;
    return 1;
}

/**
 * @brief Turn on ECH server-side
 *
 * When this works, the server will decrypt any ECH seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 * If we already loaded the file, and the file modification time isn't
 * newer than the load time, then we'll do nothing.
 *
 * @param ctx is the SSL connection (can be NULL)
 * @param pemfile has the relevant ECHConfig(s) and private key in PEM format
 * @return success:1, SSL_ECH_FILEMISSING/2 if can't read file, other otherwise
 */
int SSL_CTX_ech_server_enable(SSL_CTX *ctx, const char *pemfile)
{
    int index=-1;
    int fnamestat=0;
    SSL_ECH *sechs=NULL;
    int rv=1;

    if (ctx==NULL || pemfile==NULL) {
        return(0);
    }

    /*
     * Check if we already loaded that one etc.
     */
    fnamestat=ech_check_filenames(ctx,pemfile,&index);
    switch (fnamestat) {
        case ECH_KEYPAIR_UNMODIFIED:
            /* nothing to do */
            return(1);
        case ECH_KEYPAIR_FILEMISSING:
            /* nothing to do, but trace this and let caller handle it */
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,
                    "Returning ECH_FILEMISSING from SSL_CTX_ech_server_enable "
                    "for %s\n",
                    pemfile);
                BIO_printf(trc_out,"That's unexpected and likely indicates a "
                    "problem, but the application might be able to continue\n");
            } OSSL_TRACE_END(TLS);
#endif
            return(ECH_FILEMISSING);
        case ECH_KEYPAIR_ERROR:
            return(0);
    }

    /*
     * Load up the file content
     */
    rv=ech_readpemfile(ctx,1,pemfile,NULL,0,&sechs);
    if (rv!=1) {
        return(rv);
    }

    /*
     * This is a restriction of our PEM file scheme - we only accept
     * one public key per PEM file
     */
    if (!sechs || ! sechs->cfg || sechs->cfg->nrecs!=1) {
        return(0);
    }

    /*
     * Now store the keypair in a new or current place
     */
    if (fnamestat==ECH_KEYPAIR_MODIFIED) {
        SSL_ECH *curr_ec=NULL;
        if (index<0 || index >=ctx->ext.nechs) {
            SSL_ECH_free(sechs);
            OPENSSL_free(sechs);
            return(0);
        }
        curr_ec=&ctx->ext.ech[index];
        SSL_ECH_free(curr_ec);
        memset(curr_ec,0,sizeof(SSL_ECH));
        *curr_ec=*sechs; /* struct copy */
        OPENSSL_free(sechs);
        return(1);
    }
    if (fnamestat==ECH_KEYPAIR_NEW) {
        SSL_ECH *re_ec=OPENSSL_realloc(ctx->ext.ech,
                            (ctx->ext.nechs+1)*sizeof(SSL_ECH));
        SSL_ECH *new_ec=NULL;
        if (re_ec==NULL) {
            SSL_ECH_free(sechs);
            OPENSSL_free(sechs);
            return(0);
        }
        ctx->ext.ech=re_ec;
        new_ec=&ctx->ext.ech[ctx->ext.nechs];
        memset(new_ec,0,sizeof(SSL_ECH));
        *new_ec=*sechs;
        ctx->ext.nechs++;
        OPENSSL_free(sechs);
        return(1);
    }

    return 0;
}

/**
 * Turn on ECH server-side, with a buffer input
 *
 * When this works, the server will decrypt any ECH seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 * If we have exactly that buffer already loaded, we'll do nothing.
 *
 * @param ctx is the SSL connection (can be NULL)
 * @param buf has the relevant ECHConfig(s) and private key in PEM format
 * @param blen is the length of buf
 * @return success:1, other otherwise
 */
int SSL_CTX_ech_server_enable_buffer(
        SSL_CTX *ctx,
        const unsigned char *buf,
        const size_t blen)
{
    SSL_ECH *sechs=NULL;
    int rv=1;
    EVP_MD_CTX *mdctx;
    const EVP_MD *md=NULL;
    unsigned int i=0;
    int j=0;
    unsigned char hashval[EVP_MAX_MD_SIZE];
    unsigned int hashlen;
    char ah_hash[2*EVP_MAX_MD_SIZE+1];
    SSL_ECH *re_ec=NULL;
    SSL_ECH *new_ec=NULL;

    /*
     * Pseudo-filename is hash of input buffer
     */
    md=ctx->ssl_digest_methods[SSL_HANDSHAKE_MAC_SHA256];
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) return(0);
    if (EVP_DigestInit_ex(mdctx, md, NULL) <= 0
        || EVP_DigestUpdate(mdctx, buf, blen) <= 0
        || EVP_DigestFinal_ex(mdctx, hashval, &hashlen) <= 0) {
        if (mdctx) EVP_MD_CTX_free(mdctx);
        return(0);
    }
    if (mdctx) EVP_MD_CTX_free(mdctx);
    /*
     * AH encode hashval to be a string, as replacement for
     * file name
     */
    for (i=0;i!=hashlen;i++) {
        uint8_t tn=(hashval[i]>>4)&0x0f;
        uint8_t bn=(hashval[i]&0x0f);
        ah_hash[2*i]=(tn<10?tn+'0':(tn-10+'A'));
        ah_hash[2*i+1]=(bn<10?bn+'0':(bn-10+'A'));
    }
    ah_hash[i]='\0';

    /*
     * Check if we have that buffer loaded already
     * If we did, we're done
     */
    for (j=0;j!=ctx->ext.nechs;j++) {
        SSL_ECH *se=&ctx->ext.ech[j];
        if (se->pemfname
            && strlen(se->pemfname)==strlen(ah_hash)
            && !memcpy(se->pemfname,ah_hash,strlen(ah_hash))) {
            /*
             * we're done here
             */
            return(1);
        }
    }

    /*
     * Load up the buffer content
     */
    rv=ech_readpemfile(ctx,0,ah_hash,buf,blen,&sechs);
    if (rv!=1) {
        return(rv);
    }

    /*
     * This is a restriction of our PEM file scheme - we only accept
     * one public key per PEM file
     */
    if (!sechs || ! sechs->cfg || sechs->cfg->nrecs!=1) {
        return(0);
    }

    /*
     * Now store the keypair in a new or current place
     */
    re_ec=OPENSSL_realloc(ctx->ext.ech,(ctx->ext.nechs+1)*sizeof(SSL_ECH));
    if (re_ec==NULL) {
        SSL_ECH_free(sechs);
        OPENSSL_free(sechs);
        return(0);
    }
    ctx->ext.ech=re_ec;
    new_ec=&ctx->ext.ech[ctx->ext.nechs];
    memset(new_ec,0,sizeof(SSL_ECH));
    *new_ec=*sechs;
    ctx->ext.nechs++;
    OPENSSL_free(sechs);
    return(1);

}


/**
 * @brief Print the status/content of an SSL session wrt ECH
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param ssl is an SSL session strucutre
 * @param selector all (ECH_SELECT_ALL==-1) or just one of the SSL_ECH values
 * @return 1 for success, anything else for failure
 *
 */
int SSL_ech_print(BIO* out, SSL *ssl, int selector)
{
    char *cfg=NULL;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    BIO_printf(out,"*** SSL_ech_print ***\n");
#ifdef ECH_SUPERVERBOSE
    BIO_printf(out,"s=%p\n",(void*)s);
    BIO_printf(out,"inner_s=%p\n",(void*)s->ext.inner_s);
    BIO_printf(out,"outer_s=%p\n",(void*)s->ext.outer_s);
#endif
    BIO_printf(out,"ech_attempted_type=0x%4x\n",s->ext.ech_attempted_type);
    BIO_printf(out,"ech_attempted=%d\n",s->ext.ech_attempted);
    BIO_printf(out,"ech_done=%d\n",s->ext.ech_done);
    BIO_printf(out,"ech_grease=%d\n",s->ext.ech_grease);
#ifdef ECH_SUPERVERBOSE
    BIO_printf(out,"ech_returned=%p\n",(void*)s->ext.ech_returned);
#endif
    BIO_printf(out,"ech_returned_len=%ld\n",(long)s->ext.ech_returned_len);
    BIO_printf(out,"ech_success=%d\n",s->ext.ech_success);
    if (s->ech) {
        int i=0;
        for (i=0;i!=s->nechs;i++) {
            if (selector==ECH_SELECT_ALL || selector==i) {
                cfg=ECHConfigs_print(s->ech[i].cfg);
                BIO_printf(out,"ECHConfig %d\n\t%s\n",i,cfg);
                OPENSSL_free(cfg);
                if (s->ech[i].keyshare) {

/* apparently 26 is all we need */
#define ECH_TIME_STR_LEN 32
                    struct tm local,*local_p=NULL;
                    char lstr[ECH_TIME_STR_LEN];
#if !defined(OPENSSL_SYS_WINDOWS)
                    local_p=gmtime_r(&s->ech[i].loadtime,&local);
                    if (local_p!=&local) {
                        strcpy(lstr,"sometime");
                    }
#else
                    errno_t grv;
                    grv=gmtime_s(&local,&s->ech[i].loadtime);
                    if (grv!=0) {
                        strcpy(lstr,"sometime");
                    }
#endif
                    else { 
                        int srv=strftime(lstr,ECH_TIME_STR_LEN,
                                "%c",&local);
                        if (srv==0) {
                            strcpy(lstr,"sometime");
                        }
                    }
                    BIO_printf(out,"\tpriv=%s, loaded at %s\n",
                        s->ech[i].pemfname,lstr);

                }
            }
        }
    } else {
        BIO_printf(out,"cfg=NONE\n");
    }
    if (s->ext.ech_returned) {
        size_t i=0;
        BIO_printf(out,"ret=");
        for (i=0;i!=s->ext.ech_returned_len;i++) {
            if ((i!=0) && (i%16==0))
                BIO_printf(out,"\n    ");
            BIO_printf(out,"%02x:",(unsigned)(s->ext.ech_returned[i]));
        }
        BIO_printf(out,"\n");
    }

    BIO_printf(out,"*** SSL_ech_print ***\n");
    return 1;
}

/**
 * @brief API to allow calling code know ECH outcome, post-handshake
 *
 * This is intended to be called by applications after the TLS handshake
 * is complete. This works for both client and server. The caller does
 * not have to (and shouldn't) free the inner_sni or outer_sni strings.
 *
 * @param ssl The SSL session
 * @param inner_sni will be set to the SNI from the inner CH (if any)
 * @param outer_sni will be set to the SNI from the outer CH (if any)
 * @return 1 for success, other otherwise
 */
int SSL_ech_get_status(SSL *ssl, char **inner_sni, char **outer_sni)
{
    char *sinner=NULL;
    char *souter=NULL;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s==NULL || outer_sni==NULL || inner_sni==NULL) {
        return SSL_ECH_STATUS_BAD_CALL;
    }
    *outer_sni=NULL;
    *inner_sni=NULL;

    if (s->ext.ech_grease==ECH_IS_GREASE) {
        if (s->ext.ech_returned)
            return SSL_ECH_STATUS_GREASE_ECH;
        return SSL_ECH_STATUS_GREASE;
    }
    if (s->ext.ech_backend) {
        return SSL_ECH_STATUS_BACKEND;
    }
    if (s->ech==NULL) {
        return SSL_ECH_STATUS_NOT_CONFIGURED;
    }

    /*
     * set vars - note we may be pointing to NULL which is fine
     */
    if (!s->server) {
        if (s->ext.inner_s!=NULL) sinner=s->ext.inner_s->ext.hostname;
        else sinner=s->ext.hostname;
        if (s->ext.outer_s!=NULL) souter=s->ext.outer_s->ext.hostname;
        else souter=s->ext.hostname;
    } else {
        if (s->ech && s->ext.ech_success) {
            sinner=s->ech->inner_name;
            souter=s->ech->outer_name;
        }
    }

    if (s->ech!=NULL && s->ext.ech_attempted==1 &&
            s->ext.ech_grease!=ECH_IS_GREASE) {
        long vr=X509_V_OK;
        vr=SSL_get_verify_result(ssl);
        *inner_sni=sinner;
        *outer_sni=souter;
        if (s->ext.ech_success==1) {
            if (vr == X509_V_OK ) {
                return SSL_ECH_STATUS_SUCCESS;
            } else {
                return SSL_ECH_STATUS_BAD_NAME;
            }
        } else {
            if (s->ext.ech_returned)
                return SSL_ECH_STATUS_FAILED_ECH;
            return SSL_ECH_STATUS_FAILED;
        }
    } else if (s->ext.ech_grease==ECH_IS_GREASE) {
        return SSL_ECH_STATUS_GREASE;
    }
    return SSL_ECH_STATUS_NOT_TRIED;
}

/*
 * A macro to check we have __n__ allocated octets left before we
 * write to the 'alen' sized string buffer 'str' using pointer 'cp'
 */
#define STILLLEFT(__n__) \
    if (((size_t)(cp-str)+(size_t)(__n__))>alen) return(NULL);


/**
 * @brief produce a printable string form of an ECHConfigs
 *
 * Note - the caller has to free the string returned if not NULL
 * @param c is the ECHConfigs
 * @return a printable string (or NULL)
 */
static char *ECHConfigs_print(ECHConfigs *c)
{
    int i=0;
    char *str=NULL; /* final string */
    size_t alen=0;  /* allocated len = 3*encoded_len + overhead */
    char *cp=NULL; /* current string pointer */
    if (!c) return(str);
    if (!c->recs) return(str);
    alen=c->encoded_len*3+80;
    str=OPENSSL_malloc(alen);
    if (!str) return(str);
    memset(str,0,alen);
    cp=str;
    for (i=0;i!=c->nrecs;i++) {
        unsigned int j=0;
        STILLLEFT(1);
        *cp++='[';
        /* version */
        STILLLEFT(5);
        snprintf(cp,(alen-(cp-str)),"%04x,",c->recs[i].version); cp+=5;
        /* config_id */
        STILLLEFT(3);
        snprintf(cp,(alen-(cp-str)),"%02x,",c->recs[i].config_id); cp+=3;
        /* public_name */
        STILLLEFT(c->recs[i].public_name_len+1);
        snprintf(cp,(alen-(cp-str)),"%s,",c->recs[i].public_name);
        cp+=(c->recs[i].public_name_len+1);
        /* ciphersuites */
        STILLLEFT(6);
        snprintf(cp,(alen-(cp-str)),"%04x,[",c->recs[i].kem_id); cp+=6;
        for (j=0;j!=c->recs[i].nsuites;j++) {
            unsigned char *es=(unsigned char*)&c->recs[i].ciphersuites[j];
            uint16_t kdf_id=es[0]*256+es[1];
            uint16_t aead_id=es[2]*256+es[3];
            STILLLEFT(5);
            snprintf(cp,(alen-(cp-str)),"%04x,",kdf_id); cp+=5;
            STILLLEFT(4);
            snprintf(cp,(alen-(cp-str)),"%04x",aead_id); cp+=4;
            if (j<(c->recs[i].nsuites-1)) {
                STILLLEFT(1);
                *cp++=',';
            }
        }
        STILLLEFT(1); *cp++=']';
        STILLLEFT(1); *cp++=',';
        /* public key */
        for (j=0;j!=c->recs[i].pub_len;j++) {
            STILLLEFT(2);
            snprintf(cp,(alen-(cp-str)),"%02x",c->recs[i].pub[j]); cp+=2;
        }
        /* max name length */
        if (c->recs[i].version==ECH_DRAFT_13_VERSION) {
            STILLLEFT(4);
            snprintf(cp,(alen-(cp-str)),",%02x,",
                c->recs[i].maximum_name_length); cp+=4;
        } else {
            STILLLEFT(6);
            snprintf(cp,(alen-(cp-str)),",%04x,",
                c->recs[i].maximum_name_length); cp+=6;
        }
        /* just number of extensions */
        STILLLEFT(2);
        snprintf(cp,(alen-(cp-str)),"%02x",c->recs[i].nexts); cp+=2;
        STILLLEFT(1);
        *cp++=']';
    }
    STILLLEFT(1);
    *cp++='\0';
    return(str);
}

/**
 * @brief Duplicate the configuration related fields of an SSL_ECH
 *
 * This is needed to handle the SSL_CTX->SSL factory model.
 *
 * @param orig is the input array of SSL_ECH to be partly deep-copied
 * @param nech is the number of elements in the array
 * @param selector dup all (ECH_SELECT_ALL==-1) or just one
 * @return a deep-copy array or NULL if errors occur
 */
SSL_ECH* SSL_ECH_dup(SSL_ECH* orig, size_t nech, int selector)
{
    SSL_ECH *new_se=NULL;
    int min_ind=0;
    int max_ind=nech;
    int i=0;

    if ((selector != ECH_SELECT_ALL) && selector<0) return(0);
    if (selector!=ECH_SELECT_ALL) {
        if ((unsigned int)selector>=nech) goto err;
        min_ind=selector;
        max_ind=selector+1;
    }
    new_se=OPENSSL_malloc((max_ind-min_ind)*sizeof(SSL_ECH));
    if (!new_se) goto err;
    memset(new_se,0,(max_ind-min_ind)*sizeof(SSL_ECH));

    for (i=min_ind;i!=max_ind;i++) {
        new_se[i].cfg=OPENSSL_malloc(sizeof(ECHConfigs));
        if (new_se[i].cfg==NULL) goto err;
        if (ECHConfigs_dup(orig[i].cfg,new_se[i].cfg)!=1) goto err;

        if (orig[i].inner_name!=NULL) {
            new_se[i].inner_name=OPENSSL_strdup(orig[i].inner_name);
        }
        if (orig[i].outer_name!=NULL) {
            new_se[i].outer_name=OPENSSL_strdup(orig[i].outer_name);
        }
        if (orig[i].pemfname!=NULL) {
            new_se[i].pemfname=OPENSSL_strdup(orig[i].pemfname);
        }
        new_se[i].loadtime=orig[i].loadtime;
        if (orig[i].keyshare!=NULL) {
            new_se[i].keyshare=orig[i].keyshare;
            EVP_PKEY_up_ref(orig[i].keyshare);
        }

    }

    return new_se;
err:
    if (new_se!=NULL) {
        SSL_ECH_free(new_se);
    }
    return NULL;
}

/**
 * @brief Decode SVCB/HTTPS RR value provided as binary or ascii-hex
 *
 * The rrval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g.
 * ECH_FMT_ASCII_HEX.
 *
 * Note that we "succeed" even if there is no ECHConfigs in the input - some
 * callers might download the RR from DNS and pass it here without looking
 * inside, and there are valid uses of such RRs. The caller can check though
 * using the num_echs output.
 *
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param echs is the returned array of SSL_ECH
 * @return is 1 for success, error otherwise
 */
static int local_svcb_add(
        int rrfmt,
        size_t rrlen,
        char *rrval,
        int *num_echs,
        SSL_ECH **echs)
{
    int detfmt=ECH_FMT_GUESS;
    int rv=0;
    size_t binlen=0; /* the RData */
    unsigned char *binbuf=NULL;
    size_t eklen=0; /* the ECHConfigs, within the above */
    unsigned char *ekval=NULL;
    unsigned char *cp=NULL;
    size_t remaining=0;
    char *dnsname=NULL;
    unsigned short pcode=0;
    unsigned short plen=0;
    int done=0;

    if (rrfmt==ECH_FMT_ASCIIHEX) {
        detfmt=rrfmt;
    } else if (rrfmt==ECH_FMT_BIN) {
        detfmt=rrfmt;
    } else {
        rv=ech_guess_fmt(rrlen,(unsigned char*)rrval,&detfmt);
        if (rv==0)  {
            return(rv);
        }
    }
    if (detfmt==ECH_FMT_ASCIIHEX) {
        rv=hpke_ah_decode(rrlen,rrval,&binlen,&binbuf);
        if (rv==0) {
            return(rv);
        }
    } else if (detfmt==ECH_FMT_B64TXT) {
        int ebd_rv=ech_base64_decode(rrval,&binbuf);
        if (ebd_rv<=0) {
            return(0);
        }
        binlen=(size_t)ebd_rv;
    }

    /*
     * Now we have a binary encoded RData so we'll skip the
     * name, and then walk through the SvcParamKey binary
     * codes 'till we find what we want
     */
    cp=binbuf;
    remaining=binlen;

    /*
     * skip 2 octet priority and TargetName as those are the
     * application's responsibility, not the library's
     */
    if (remaining<=2) goto err;
    cp+=2; remaining-=2;
    rv=local_decode_rdata_name(&cp,&remaining,&dnsname);
    if (rv!=1) {
        goto err;
    }
    OPENSSL_free(dnsname); dnsname=NULL;

    while (!done && remaining>=4) {
        pcode=(*cp<<8)+(*(cp+1)); cp+=2;
        plen=(*cp<<8)+(*(cp+1)); cp+=2;
        remaining-=4;
        if (pcode==ECH_PCODE_ECH) {
            eklen=(size_t)plen;
            ekval=cp;
            done=1;
        }
        if (plen!=0 && plen <= remaining) {
            cp+=plen;
            remaining-=plen;
        }
    }
    if (!done) {
        *num_echs=0;
        OPENSSL_free(binbuf);
        return(1);
    }
    /*
     * Parse & load any ECHConfigs that we found
     */
    rv=local_ech_add(ECH_FMT_BIN,eklen,ekval,num_echs,echs);
    if (rv!=1) {
        goto err;
    }
    OPENSSL_free(binbuf);
    return(1);
err:
    OPENSSL_free(dnsname);
    OPENSSL_free(binbuf);
    return(0);
}

/**
 * @brief Decode/store SVCB/HTTPS RR value provided as (binary or ascii-hex encoded)
 *
 * The input rrval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECH_FMT_ASCII_HEX
 * This API is additive, i.e. values from multiple calls will be merged, but
 * not that the merge isn't clever so the application would need to take that
 * into account if it cared about priority.
 * In the case of decoding error, any existing ECHConfigs are unaffected.
 *
 * @param ctx is the parent SSL_CTX
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are loaded in total
 * @return is 1 for success, error otherwise
 */
int SSL_CTX_svcb_add(SSL_CTX *ctx, short rrfmt, size_t rrlen, char *rrval, int *num_echs)
{
    SSL_ECH *new_echs=NULL;
    int num_new=0;
    SSL_ECH *all_echs=NULL;
    int i;
    if (!ctx || !rrval || !num_echs || rrlen==0) return(0);
    if (local_svcb_add(rrfmt,rrlen,rrval,&num_new,&new_echs)!=1) {
        return 0;
    }
    if (num_new==0) {
        *num_echs=ctx->ext.nechs;
        return(1);
    }
    /* merge new and old */
    all_echs=OPENSSL_realloc(ctx->ext.ech,(ctx->ext.nechs+num_new)*sizeof(SSL_ECH));
    if (!all_echs) {
        for (i=0;i!=num_new;i++) {
            SSL_ECH_free(&new_echs[i]);
        }
        OPENSSL_free(new_echs);
        return(0);
    }
    ctx->ext.ech=all_echs;
    for (i=0;i!=num_new;i++) {
        ctx->ext.ech[ctx->ext.nechs+i]=new_echs[i]; /* struct  copy */
    }
    OPENSSL_free(new_echs);
    ctx->ext.nechs+=num_new;
    *num_echs=ctx->ext.nechs;
    return 1;

}

/**
 * @brief Decode/store SVCB/HTTPS RR value provided as (binary or ascii-hex encoded)
 *
 * The input rrval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECH_FMT_ASCII_HEX
 * This API is additive, i.e. values from multiple calls will be merged, but
 * not that the merge isn't clever so the application would need to take that
 * into account if it cared about priority.
 * In the case of decoding error, any existing ECHConfigs are unaffected.
 *
 * @param ssl is the SSL session
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_svcb_add(SSL *ssl, int rrfmt, size_t rrlen, char *rrval, int *num_echs)
{
    SSL_ECH *new_echs=NULL;
    int num_new=0;
    SSL_ECH *all_echs=NULL;
    int i;
    SSL_CONNECTION *con = SSL_CONNECTION_FROM_SSL(ssl);

    if (!con || !rrval || !num_echs || rrlen==0) return(0);
    if (local_svcb_add(rrfmt,rrlen,rrval,&num_new,&new_echs)!=1) {
        return 0;
    }
    if (num_new==0) {
        *num_echs=con->nechs;
        return(1);
    }
    /* merge new and old */
    all_echs=OPENSSL_realloc(con->ech,(con->nechs+num_new)*sizeof(SSL_ECH));
    if (!all_echs) {
        for (i=0;i!=num_new;i++) {
            SSL_ECH_free(&new_echs[i]);
        }
        OPENSSL_free(new_echs);
        return(0);
    }
    con->ech=all_echs;
    for (i=0;i!=num_new;i++) {
        con->ech[con->nechs+i]=new_echs[i]; /* struct  copy */
    }
    OPENSSL_free(new_echs);
    con->nechs+=num_new;
    *num_echs=con->nechs;
    return 1;
}

/**
 * @brief say if extension at index i in ext_defs is to be ECH compressed
 * @param ind is the index of this extension in ext_defs (and ech_outer_config)
 * @return 1 if this one is to be compressed, 0 if not, -1 for error
 */
int ech_2bcompressed(int ind)
{
    int nexts=sizeof(ech_outer_config)/sizeof(int);
    if (ind <0 || ind>=nexts) return(-1);
    return(ech_outer_config[ind]);
}

/**
 * @brief repeat extension from inner in outer and handle compression
 *
 * @param ssl is the SSL session
 * @param pkt is the packet containing extensions
 * @return 0: error, 1: copied existing and done, 2: ignore existing
 */
int ech_same_ext(SSL *ssl, WPACKET* pkt)
{
    SSL_CONNECTION *inner=NULL;
    unsigned int type=0;
    unsigned int nexts=0;
    int tind=0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

/*
 * DUPEMALL is handy for testing
 */
#undef DUPEMALL
#ifdef DUPEMALL
    /*
     * Setting this means no compression at all.
     */
    return(ECH_SAME_EXT_CONTINUE);
#endif
    if (!s->ech) return(ECH_SAME_EXT_CONTINUE); /* nothing to do */
    inner=s->ext.inner_s;
    type=s->ext.etype;
    nexts=sizeof(ech_outer_config)/sizeof(int);
    tind=ech_map_ext_type_to_ind(type);

    /*
     * If this index'd extension won't be compressed, we're done
     */
    if (tind==-1) return(ECH_SAME_EXT_ERR);
    if (tind>=(int)nexts) return(ECH_SAME_EXT_ERR);

    if (s->ext.ch_depth==1) {
        /* inner CH - just note compression as configured */
        if (!ech_outer_config[tind]) {
            return(ECH_SAME_EXT_CONTINUE);
        }
        if (s->ext.n_outer_only>=ECH_OUTERS_MAX) {
            return ECH_SAME_EXT_ERR;
        }
        /* mark this one to be "compressed" */
        s->ext.outer_only[s->ext.n_outer_only]=type;
        s->ext.n_outer_only++;
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,
                "ech_same_ext: Marking ext (type %x,ind %d) for compression\n",
                s->ext.etype,tind);
        } OSSL_TRACE_END(TLS);
#endif
        return(ECH_SAME_EXT_CONTINUE);
    }

    /*
     * Copy value from inner to outer, or indicate a new value needed
     */
    if (s->ext.ch_depth==0) {
        if (!inner->clienthello) return(ECH_SAME_EXT_ERR);
        if (!pkt) return(ECH_SAME_EXT_ERR);
        if (ech_outer_indep[tind]) {
            /* continue processing, meaning get a new value */
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,
                    "ech_same_ext: New outer value for ext (type %x,ind %d)\n",
                    s->ext.etype,tind);
            } OSSL_TRACE_END(TLS);
#endif
            return(ECH_SAME_EXT_CONTINUE);
        } else {
            size_t ind=0;
            RAW_EXTENSION *myext=NULL;
            RAW_EXTENSION *raws=inner->clienthello->pre_proc_exts;
            size_t nraws=0;
            /* copy inner to outer */
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,
                    "ech_same_ext: Copying ext (type %x,ind %d) to outer\n",
                    s->ext.etype,tind);
            } OSSL_TRACE_END(TLS);
#endif
            if (raws==NULL) {
                return ECH_SAME_EXT_ERR;
            }
            nraws=inner->clienthello->pre_proc_exts_len;
            for (ind=0;ind!=nraws;ind++) {
                if (raws[ind].type==type) {
                    myext=&raws[ind];
                    break;
                }
            }
            if (myext==NULL) {
                /* This one wasn't in inner, so re-do processing */
                return ECH_SAME_EXT_CONTINUE;
            }
            /* copy inner value to outer */
            if (myext->data.curr!=NULL && myext->data.remaining>0) {
                if (!WPACKET_put_bytes_u16(pkt, type)
                    || !WPACKET_sub_memcpy_u16(pkt,
                        myext->data.curr, myext->data.remaining)) {
                    return ECH_SAME_EXT_ERR;
                }
            } else {
                /* empty extension */
                if (!WPACKET_put_bytes_u16(pkt, type)
                        || !WPACKET_put_bytes_u16(pkt, 0)) {
                    return ECH_SAME_EXT_ERR;
                }
            }
            /* we've done the copy so we're done */
            return(ECH_SAME_EXT_DONE);
        }
    }
    /* just in case - shouldn't happen */
    return ECH_SAME_EXT_ERR;
}

/**
 * @brief After "normal" 1st pass CH is done, fix encoding as needed
 *
 * This will make up the ClientHelloInner and EncodedClientHelloInner buffers
 *
 * @param ssl is the SSL session
 * @return 1 for success, error otherwise
 */
int ech_encode_inner(SSL *ssl)
{
    unsigned char *innerch_full=NULL;
    WPACKET inner; /* "fake" pkt for inner */
    BUF_MEM *inner_mem=NULL;
    int mt=SSL3_MT_CLIENT_HELLO;
    RAW_EXTENSION *raws=NULL;
    size_t nraws=0;
    size_t ind=0;
    size_t innerinnerlen=0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    /* barf if nothing to do */
    if (s == NULL || s->ech==NULL) return(0);

    /*
     * So encode s->ext.innerch into s->ext.encoded_innerch,
     * but handling ECH-compression
     *
     * As a reminder the CH is:
     *  struct {
     *    ProtocolVersion legacy_version = 0x0303;    TLS v1.2
     *    Random random;
     *    opaque legacy_session_id<0..32>;
     *    CipherSuite cipher_suites<2..2^16-2>;
     *    opaque legacy_compression_methods<1..2^8-1>;
     *    Extension extensions<8..2^16-1>;
     *  } ClientHello;
     */

    if ((inner_mem = BUF_MEM_new()) == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!BUF_MEM_grow(inner_mem, SSL3_RT_MAX_PLAIN_LENGTH)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!WPACKET_init(&inner,inner_mem)
            || !ssl_set_handshake_header(s, &inner, mt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Add ver/rnd/sess-id/suites to buffer */
    if (!WPACKET_put_bytes_u16(&inner, s->client_version)
        || !WPACKET_memcpy(&inner, s->s3.client_random, SSL3_RANDOM_SIZE)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Session ID is forced to zero in the encoded inner */
    if (!WPACKET_start_sub_packet_u8(&inner)
            || !WPACKET_close(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Ciphers supported */
    if (!WPACKET_start_sub_packet_u16(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!ssl_cipher_list_to_bytes(s, SSL_get_ciphers(ssl), &inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!WPACKET_close(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* COMPRESSION */
    if (!WPACKET_start_sub_packet_u8(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Add the NULL compression method */
    if (!WPACKET_put_bytes_u8(&inner, 0) || !WPACKET_close(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Now handle extensions */
    if (!WPACKET_start_sub_packet_u16(&inner)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Grab a pointer to the alraedy constructed extensions */
    raws=s->clienthello->pre_proc_exts;
    nraws=s->clienthello->pre_proc_exts_len;

    /*  We put compressed stuff first (if any), because we can */
    if (s->ext.n_outer_only>0) {
        int iind=0;
        if (!WPACKET_put_bytes_u16(&inner, TLSEXT_TYPE_outer_extensions) ||
            !WPACKET_put_bytes_u16(&inner, 2*s->ext.n_outer_only+1)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (!WPACKET_put_bytes_u8(&inner, 2*s->ext.n_outer_only)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        for (iind=0;iind!=s->ext.n_outer_only;iind++) {
            if (!WPACKET_put_bytes_u16(&inner, s->ext.outer_only[iind])) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    /* now copy the rest for encoded inner */
    for (ind=0;ind!=nraws;ind++) {
        int present=raws[ind].present;
        if (!present) continue;
        if (ech_2bcompressed(ind)==1) continue;
        if (raws[ind].data.curr!=NULL) {
            if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                || !WPACKET_sub_memcpy_u16(&inner,
                    raws[ind].data.curr, raws[ind].data.remaining)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            /*
            * empty extension
            */
            if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                    || !WPACKET_put_bytes_u16(&inner, 0)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    /* close the exts sub packet */
    if (!WPACKET_close(&inner))  {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* close the inner CH */
    if (!WPACKET_close(&inner))  {
        goto err;
    }
    /* Set pointer/len for inner CH */
    if (!WPACKET_get_length(&inner, &innerinnerlen)) {
        goto err;
    }
    innerch_full=OPENSSL_malloc(innerinnerlen);
    if (!innerch_full) {
        goto err;
    }
    /* Finally ditch the type and 3-octet length */
    memcpy(innerch_full,inner_mem->data+4,innerinnerlen-4);
    s->ext.encoded_innerch=innerch_full;
    s->ext.encoded_innerch_len=innerinnerlen-4;
    /* and clean up */
    WPACKET_cleanup(&inner);
    BUF_MEM_free(inner_mem);
    inner_mem=NULL;
    return(1);
err:
    WPACKET_cleanup(&inner);
    if (inner_mem) BUF_MEM_free(inner_mem);
    return(0);
}

/**
 * @brief After successful ECH decrypt, decode, decompress etc.
 *
 * We also need the outer CH as a buffer (ob, below) so we can
 * ECH-decompress.
 * The plaintext we start from is in s->ext.encoded_innerch
 * and our final decoded, decompressed buffer will end up
 * in s->ext.innerch (which'll then be further processed).
 * That further processing includes all existing decoding
 * checks so we should be fine wrt fuzzing without having
 * to make all checks here (e.g. we can assume that the
 * protocol version, NULL compression etc are correct here -
 * if not, those'll be caught later).
 *
 * @param ssl is the SSL session
 * @param ob is the outer CH as a buffer
 * @param ob_len is the size of the above
 * @param outer_startofexts is the offset of exts in ob
 * @return 1 for success, error otherwise
 */
static int ech_decode_inner(
        SSL *ssl, 
        const unsigned char *ob,
        size_t ob_len,
        size_t outer_startofexts)
{
    size_t initial_decomp_len=0;
    unsigned char *initial_decomp=NULL;
    size_t offset2sessid=0;
    size_t suiteslen=0;
    size_t startofexts=0;
    int found=0;
    int remaining=0;
    size_t oneextstart=0;
    uint16_t etype=0;
    size_t elen=0;
    int n_outers=0;
    uint16_t outers[ECH_OUTERS_MAX]; /* extension types that were compressed */
    uint8_t slen=0;
    const unsigned char *oval_buf=NULL;
    int i=0;
    int j=0;
    int iind=0;
    size_t tot_outer_lens=0; /* total length of outers (incl. type+len+val) */
    size_t outer_sizes[ECH_OUTERS_MAX]; /* sizes, in same order of "outers" */
    int outer_offsets[ECH_OUTERS_MAX]; /* offsets in same order of "outers" */
    const unsigned char *exts_start=NULL;
    size_t exts_len=0;
    const unsigned char *ep=NULL;
    int found_outers=0;
    size_t outer_exts_len=0;
    unsigned char *final_decomp=NULL;
    size_t final_decomp_len=0;
    size_t offset=0;
    size_t initial_extslen=0;
    size_t final_extslen=0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s->ext.encoded_innerch==NULL) return(0);
    if (ob_len<=(outer_startofexts+2)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return(0);
    }

    /*
     * So we'll try decode s->ext.encoded_innerch into
     * s->ext.innerch, modulo s->ext.outers
     *
     * As a reminder the CH is:
     *  struct {
     *    ProtocolVersion legacy_version = 0x0303;    TLS v1.2
     *    Random random;
     *    opaque legacy_session_id<0..32>;
     *    CipherSuite cipher_suites<2..2^16-2>;
     *    opaque legacy_compression_methods<1..2^8-1>;
     *    Extension extensions<8..2^16-1>;
     *  } ClientHello;
     */

    /*
     * add bytes for session ID and its length (1)
     * minus the length of the empty session ID (1)
     * that was there already
     */
    initial_decomp_len=s->ext.encoded_innerch_len;
    initial_decomp_len+=s->tmp_session_id_len+1-1;
    initial_decomp=OPENSSL_malloc(initial_decomp_len);
    if (!initial_decomp) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return(0);
    }
    /*
     * Jump over the ciphersuites and (MUST be NULL) compression to
     * the start of extensions
     */
    offset2sessid=2+32;
    suiteslen=s->ext.encoded_innerch[offset2sessid+1]*256+
              s->ext.encoded_innerch[offset2sessid+1+1];
    startofexts=offset2sessid+1+
                s->tmp_session_id_len +  /* skipping session id */
                2+suiteslen +            /* skipping suites */
                2;                       /* skipping NULL compression */
    if (startofexts>=initial_decomp_len) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Oops - exts out of bounds\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(initial_decomp,s->ext.encoded_innerch,offset2sessid);
    initial_decomp[offset2sessid]=(unsigned char)(s->tmp_session_id_len&0xff);
    memcpy(initial_decomp+offset2sessid+1,
                s->tmp_session_id,
                s->tmp_session_id_len);
    memcpy(initial_decomp+offset2sessid+1+s->tmp_session_id_len,
                s->ext.encoded_innerch+offset2sessid+1,
                s->ext.encoded_innerch_len-offset2sessid-1);
    ech_pbuf("Inner CH (session-id-added but no decompression)",
            initial_decomp,initial_decomp_len);
    ech_pbuf("start of exts",&initial_decomp[startofexts],
            initial_decomp_len-startofexts);
    /*
     * Now skip over exts until we do/don't see outers
     */
    found=0;
    remaining=initial_decomp[startofexts]*256+initial_decomp[startofexts+1];
    oneextstart=startofexts+2; /* 1st ext type, skip the overall exts len */
    etype=0;
    elen=0;

    if ((startofexts+2+remaining)>initial_decomp_len) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Oops - exts out of bounds\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }

    while (!found && remaining>0) {
        etype=initial_decomp[oneextstart]*256+initial_decomp[oneextstart+1];
        elen=initial_decomp[oneextstart+2]*256+initial_decomp[oneextstart+3];
        if ((oneextstart+4+elen)>initial_decomp_len) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Oops - exts out of bounds\n");
            } OSSL_TRACE_END(TLS);
#endif
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (etype==TLSEXT_TYPE_outer_extensions) {
            found=1;
        } else {
            remaining-=(elen+4);
            oneextstart+=(elen+4);
        }
    }

    if (found==0) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"We had no compression\n");
        } OSSL_TRACE_END(TLS);
#endif
        /*
         * We still need to add msg type & 3-octet length
         */
        final_decomp_len=initial_decomp_len+4;
        final_decomp=OPENSSL_malloc(final_decomp_len);
        if (!final_decomp) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        final_decomp[0]=SSL3_MT_CLIENT_HELLO;
        final_decomp[1]=((initial_decomp_len)>>16)%256;
        final_decomp[2]=((initial_decomp_len)>>8)%256;
        final_decomp[3]=(initial_decomp_len)%256;
        memcpy(final_decomp+4,initial_decomp,initial_decomp_len);
        if (s->ext.innerch) {
            OPENSSL_free(s->ext.innerch);
        }
        s->ext.innerch=final_decomp;
        s->ext.innerch_len=final_decomp_len;
        return(1);
    }
    /*
     * At this point, onextstart is the offset of the outer extensions in the
     * encoded_innerch
     */
    n_outers=elen/2;
    slen=initial_decomp[oneextstart+4];
    if (!ossl_assert(n_outers==slen/2)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    oval_buf=&initial_decomp[oneextstart+5];
    if (n_outers<=0 || n_outers>ECH_OUTERS_MAX) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    for (i=0;i!=n_outers;i++) {
        outers[i]=oval_buf[2*i]*256+oval_buf[2*i+1];
        if (outers[i]==TLSEXT_TYPE_ech || outers[i]==TLSEXT_TYPE_ech13) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"You can't de-compress ECH within an ECH\n");
            } OSSL_TRACE_END(TLS);
#endif
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
    }
    /* brute force check there are no duplicates in outers */
    for (i=0;i!=n_outers;i++) {
        for (j=0;j!=n_outers;j++) {
            if (outers[i]==outers[j] && i!=j) {
#ifndef OPENSSL_NO_SSL_TRACE
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out,"Repeated outer (%d)\n",outers[i]);
                } OSSL_TRACE_END(TLS);
#endif
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
        }
    }

#ifndef OPENSSL_NO_SSL_TRACE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"We have %d outers compressed\n",n_outers);
    } OSSL_TRACE_END(TLS);
#endif
    if (n_outers<=0 || n_outers > ECH_OUTERS_MAX ) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Bad ECH compression (too few or too many!\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    /*
     * Got through outer exts and mark what we need
     */
    exts_start=ob+outer_startofexts+2;
    exts_len=ob_len-outer_startofexts-2;

    remaining=exts_len;
    ep=exts_start;
    while (remaining>0) {
        etype=*ep*256+*(ep+1);
        elen=*(ep+2)*256+*(ep+3);
        if ( (size_t)((ep+4+elen)-ob) > ob_len) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Oops - exts out of bounds\n");
            } OSSL_TRACE_END(TLS);
#endif
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        for (iind=0;iind<n_outers;iind++) {
            if (etype==outers[iind]) {
                outer_sizes[iind]=elen;
                outer_offsets[iind]=ep-exts_start;
                tot_outer_lens+=(elen+4);
                /*
                 * Note that this check depends on previously barfing on
                 * a single extension appearing twice
                 */
                found_outers++;
            }
        }
        remaining-=(elen+4);
        ep+=(elen+4);
    }
    if (found_outers!=n_outers) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,
                "Error found outers (%d) not same as claimed (%d)\n",
                found_outers,n_outers);
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    /*
     * Now almost-finally, package up the lot
     */
    outer_exts_len=5+2*n_outers;
    final_decomp_len= 4 /* the type and 3-octet length */
            + initial_decomp_len /* where we started */
            - outer_exts_len /* removing the size of the outers_extension */
            + tot_outer_lens; /* add back the length of spliced-in exts */
    if (outer_exts_len>=(4+initial_decomp_len+tot_outer_lens)) {
        /* that'd make final_decomp_len go zero/negative */
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Oops - exts out of bounds\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    final_decomp=OPENSSL_malloc(final_decomp_len);
    if (final_decomp==NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    offset=oneextstart;
    final_decomp[0]=0x01;
    final_decomp[1]=((final_decomp_len-4)>>16)%256;
    final_decomp[2]=((final_decomp_len-4)>>8)%256;
    final_decomp[3]=(final_decomp_len-4)%256;
    if (((offset+4)>=final_decomp_len) || (offset>initial_decomp_len)) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Oops - exts out of bounds\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(final_decomp+4,initial_decomp,offset);
    offset+=4; /* the start up to the "outers"  */
    /* now splice in from the outer CH */
    for (iind=0;iind!=n_outers;iind++) {
        int ooffset=outer_offsets[iind]+4;
        size_t osize=outer_sizes[iind];
        if ((offset+4)>=final_decomp_len) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Oops - exts out of bounds\n");
            } OSSL_TRACE_END(TLS);
#endif
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        final_decomp[offset]=(outers[iind]/256)&0xff; offset++;
        final_decomp[offset]=(outers[iind]%256)&0xff; offset++;
        final_decomp[offset]=(osize/256)&0xff; offset++;
        final_decomp[offset]=(osize%256)&0xff; offset++;
        if (((offset+osize)>final_decomp_len) ||
               ((size_t)((exts_start+ooffset+osize)-ob) > ob_len)) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Oops - exts out of bounds\n");
            } OSSL_TRACE_END(TLS);
#endif
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        memcpy(final_decomp+offset,exts_start+ooffset,osize); offset+=osize;
    }

    if (
        ((offset+initial_decomp_len-oneextstart-outer_exts_len)>
            final_decomp_len) ||
        ((oneextstart+outer_exts_len+initial_decomp_len-
          oneextstart-outer_exts_len) > initial_decomp_len)
       ) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Oops - exts out of bounds\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    /* now copy over extensions from inner CH from after "outers" to end */
    memcpy(final_decomp+offset,
            initial_decomp+oneextstart+outer_exts_len,
            initial_decomp_len-oneextstart-outer_exts_len);
    /*
     * the +4 and +5 are because the final_decomp has the type+3-octet length
     * and startofexts is the offset within initial_decomp which doesn't have
     * those
     */
    if ((startofexts+5)>final_decomp_len) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Oops - exts out of bounds\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    initial_extslen=
        final_decomp[startofexts+4]*256+
        final_decomp[startofexts+5];

    if ((initial_extslen+tot_outer_lens) < outer_exts_len) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Oops - exts out of bounds\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }

    final_extslen=initial_extslen+tot_outer_lens-outer_exts_len;
#ifndef OPENSSL_NO_SSL_TRACE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,
           "Initial extensions length: 0x%zx, Final extensions length: 0x%zx\n",
            initial_extslen, final_extslen);
    } OSSL_TRACE_END(TLS);
#endif
    /* the added 4 is for the type+3-octets len */
    final_decomp[startofexts+4]=(final_extslen/256)&0xff;
    final_decomp[startofexts+5]=final_extslen%256;
    ech_pbuf("final_decomp",final_decomp,final_decomp_len);
    if (s->ext.innerch) {
        OPENSSL_free(s->ext.innerch);
    }
    s->ext.innerch=final_decomp;
    s->ext.innerch_len=final_decomp_len;
    OPENSSL_free(initial_decomp);
    initial_decomp=NULL;
    return(1);
err:
    if (initial_decomp!=NULL) {
        OPENSSL_free(initial_decomp);
    }
    return(0);
}

/**
 * @brief print a buffer nicely for debug/interop purposes
 */
void ech_pbuf(const char *msg, const unsigned char *buf, const size_t blen)
{
#ifndef OPENSSL_NO_SSL_TRACE
    OSSL_TRACE_BEGIN(TLS) {
    if (msg==NULL) {
        BIO_printf(trc_out,"msg is NULL\n");
    } else if (buf==NULL) {
        BIO_printf(trc_out,"%s: buf is NULL\n",msg);
    } else if (blen==0) {
        BIO_printf(trc_out,"%s: blen is zero\n",msg);
    } else {
        size_t i;
        BIO_printf(trc_out,"%s (%lu):\n    ",msg,(unsigned long)blen);
        for (i=0;i<blen;i++) {
            if ((i!=0) && (i%16==0))
                BIO_printf(trc_out,"\n    ");
            BIO_printf(trc_out,"%02x:",(unsigned)(buf[i]));
        }
        BIO_printf(trc_out,"\n");
        }
    } OSSL_TRACE_END(TLS);
#endif
    return;
}

/*
 * @brief reset the handshake buffer for transcript after ECH is good
 *
 * @param ssl is the session
 * @param buf is the data to put into the transcript (usuallhy inner CH)
 * @param blen is the length of buf
 * @return 1 for success
 */
int ech_reset_hs_buffer(SSL *ssl, unsigned char *buf, size_t blen)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s->s3.handshake_buffer) {
        (void)BIO_set_close(s->s3.handshake_buffer, BIO_CLOSE);
        BIO_free(s->s3.handshake_buffer);
        s->s3.handshake_buffer=NULL;
    }
    EVP_MD_CTX_free(s->s3.handshake_dgst);
    s->s3.handshake_dgst=NULL;
    s->s3.handshake_buffer = BIO_new(BIO_s_mem());
    BIO_write(s->s3.handshake_buffer, (void *)buf, (int)blen);
    return 1;
}

/*
 * @brief Handling for the ECH accept_confirmation
 *
 * This is a magic value in
 * the ServerHello.random lower 8 octets that is
 * used to signal that the inner worked.
 *
 * As per the draft-10 spec:
 *
 * accept_confirmation =
 *          Derive-Secret(Handshake Secret,
 *                        "ech accept confirmation",
 *                        ClientHelloInner...ServerHelloECHConf)
 *
 * This changes in draft-13:
 *
 * accept_confirmation = HKDF-Expand-Label(
 *         HKDF-Extract(0, ClientHelloInner.random),
 *         "ech accept confirmation",
 *         transcript_ech_conf,
 *         8)
 *
 * transcript_ech_conf = ClientHelloInner..ServerHello
 *         with last 8 octets of ServerHello.random==0x00
 *
 * @param ssl is the SSL inner context
 * @param ac is (a caller allocated) 8 octet buffer
 * @param shbuf is a pointer to the SH buffer (incl. the type+3-octet length)
 * @param shlen is the length of the SH buf
 * @return: 1 for success, 0 otherwise
 */
int ech_calc_accept_confirm(
        SSL *ssl,
        unsigned char *acbuf,
        const unsigned char *shbuf,
        const size_t shlen)
{
    unsigned char *tbuf=NULL; /* local transcript buffer */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t tlen=0;
    unsigned char *chbuf=NULL;
    size_t chlen=0;
    size_t shoffset=6+24; /* offset to "magic" bits in SH.random within shbuf */
    const EVP_MD *md=NULL;
    char *label=NULL;
    size_t labellen=0;
    unsigned int hashlen=0;
    unsigned char hashval[EVP_MAX_MD_SIZE];
    unsigned char hoval[EVP_MAX_MD_SIZE];
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    unsigned char zeros[EVP_MAX_MD_SIZE];
    EVP_PKEY_CTX *pctx=NULL;

    chbuf=s->ext.innerch;
    chlen=s->ext.innerch_len;

#ifdef ECH_SUPERVERBOSE
    ech_pbuf("calc conf : innerch",chbuf,chlen);
    ech_pbuf("calc conf : SH",shbuf,shlen);
#endif

    if (s->server) {
        tlen=chlen+shlen;
    } else {
        /* need to add type + 3-octet length for client */
        tlen=chlen+shlen+4;
    }
    tbuf=OPENSSL_malloc(tlen);
    if (!tbuf) {
        goto err;
    }
    memcpy(tbuf,chbuf,chlen);
    /*
     * For some reason the internal 3-length of the shbuf is
     * wrong at this point. We'll fix it so, but here and
     * not in the actual shbuf, just in case that breaks some
     * other thing.
     */
    if (s->server) {
        memcpy(tbuf+chlen,shbuf,shlen);
        tbuf[chlen+1]=((shlen-4)>>16)&0xff;
        tbuf[chlen+2]=((shlen-4)>>8)&0xff;
        tbuf[chlen+3]=(shlen-4)&0xff;
    } else {
        /* need to add type + 3-octet length for client */
        tbuf[chlen]=SSL3_MT_SERVER_HELLO;
        tbuf[chlen+1]=(shlen>>16)&0xff;
        tbuf[chlen+2]=(shlen>>8)&0xff;
        tbuf[chlen+3]=shlen&0xff;
        memcpy(tbuf+chlen+4,shbuf,shlen);
    }
    memset(tbuf+chlen+shoffset,0,8);
    /* figure out  h/s hash */
    md=ssl_handshake_md(s);
    if (md==NULL) {
        /* fallback to one from the chosen ciphersuite */
        const unsigned char *cipherchars=&tbuf[chlen+shoffset+8+1+32];
        const SSL_CIPHER *c=ssl_get_cipher_by_char(s, cipherchars, 0);
        md=ssl_md(ssl->ctx, c->algorithm2);
        if (md==NULL) {
            /* ultimate fallback sha266 */
            md=ssl->ctx->ssl_digest_methods[SSL_HANDSHAKE_MAC_SHA256];
        }
    }

#ifdef ECH_SUPERVERBOSE
    ech_pbuf("calc conf : tbuf",tbuf,tlen);
#endif

    /* Next, zap the magic bits and do the keyed hashing */
    label=ECH_ACCEPT_CONFIRM_STRING;
    labellen=strlen(label);
    hashlen=EVP_MD_size(md);
    if (EVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVP_DigestUpdate(ctx, tbuf, tlen) <= 0
            || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
#ifdef ECH_SUPERVERBOSE
    ech_pbuf("calc conf : hashval",hashval,hashlen);
#endif

    if (s->ext.ech_attempted_type==ECH_DRAFT_10_VERSION) {
        unsigned char *insecret=s->handshake_secret;

        /* Next, do the keyed hashing */
#ifdef ECH_SUPERVERBOSE
        ech_pbuf("calc conf : h/s secret",insecret,EVP_MAX_MD_SIZE);
#endif
        if (!tls13_hkdf_expand(s, md, insecret,
                               (const unsigned char *)label,labellen,
                               hashval, hashlen,
                               hoval, hashlen, 1)) {
            goto err;
        }
   
    }

    if (s->ext.ech_attempted_type==ECH_DRAFT_13_VERSION) {
        /*
         * For all versions so far, I've had to see
         * someone else's code to get this correct.
         * So we'll just get a maybe-correct version
         * that works locally (meaning s_client to
         * s_server) for now and fix later via interop.
         * TODO: fix via interop!
         */
        unsigned char notsecret[EVP_MAX_MD_SIZE];
        size_t retlen=0;

        memset(zeros,0,EVP_MAX_MD_SIZE);

        /*
         * We still don't have an hkdf-extract that's exposed by
         * libcrypto (or hpke, as I took that out just a while
         * ago). Once this is done, it'll be fine though to fix
         * that or leave it as per below. No point in trying to
         * do that now, 'till we have interop.
         */
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!pctx) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_derive_init(pctx)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set_hkdf_md(pctx, md)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx,
               s->s3.client_random, SSL3_RANDOM_SIZE)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, zeros, hashlen)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* get the right size set first - new in latest upstream */
        if (EVP_PKEY_derive(pctx, NULL, &retlen)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (hashlen!=retlen) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_derive(pctx, notsecret, &retlen)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        EVP_PKEY_CTX_free(pctx); pctx=NULL;

#ifdef ECH_SUPERVERBOSE
        ech_pbuf("calc conf : notsecret",notsecret,hashlen);
#endif

        if (!tls13_hkdf_expand(s, md, notsecret,
                               (const unsigned char *)label,labellen,
                               hashval, hashlen,
                               hoval, hashlen, 1)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
   
    }

    /* Put back the transpript buffer as it was where we got it */
#ifdef ECH_SUPERVERBOSE
    ech_pbuf("calc conf : hoval",hoval,hashlen);
#endif

    /* Finally, set the output */
    memcpy(acbuf,hoval,8);
#ifdef ECH_SUPERVERBOSE
    ech_pbuf("calc conf : result",acbuf,8);
#endif
    if (!s->ext.ech_backend)
        ech_reset_hs_buffer(ssl,s->ext.innerch,s->ext.innerch_len);

    if (tbuf) OPENSSL_free(tbuf);
    if (ctx) EVP_MD_CTX_free(ctx);

    return(1);

err:
    if (tbuf) OPENSSL_free(tbuf);
    if (ctx) EVP_MD_CTX_free(ctx);
    if (pctx) EVP_PKEY_CTX_free(pctx);
    return(0);
}

/**
 * @brief set client callback to be called when ECH succeeded
 *
 * @param ssl is the SSL session
 * @param f is the callback
 */
void SSL_ech_set_callback(SSL *ssl, SSL_ech_cb_func f)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    s->ech_cb=f;
}

/**
 * @brief set client callback to be called when ECH succeeded
 *
 * @param s is the SSL_CTX session
 * @param f is the callback
 */
void SSL_CTX_ech_set_callback(SSL_CTX *s, SSL_ech_cb_func f)
{
    s->ext.ech_cb=f;
}

/**
 * @brief Swap the inner and outer
 *
 * The only reason to make this a function is because it's
 * likely very brittle - if we need any other fields to be
 * handled specially (e.g. because of some so far untested
 * combination of extensions), then this may fail, so good
 * to keep things in one place as we find that out.
 *
 * @param s is the SSL session to swap about
 * @return 0 for error, 1 for success
 */
int ech_swaperoo(SSL_CONNECTION *s)
{
    SSL_CONNECTION *inp=NULL;
    SSL_CONNECTION *outp=NULL;
    SSL_CONNECTION tmp_outer;
    SSL_CONNECTION tmp_inner;
    unsigned char *curr_buf=NULL;
    size_t curr_buflen=0;
    unsigned char *new_buf=NULL;
    size_t new_buflen=0;
    size_t outer_chlen=0;
    size_t other_octets=0;

    ech_ptranscript("ech_swaperoo, b4",s);

    /* Make some checks */
    if (s==NULL) return(0);
    if (s->ext.inner_s==NULL) return(0);
    if (s->ext.inner_s->ext.outer_s==NULL) return(0);
    inp=s->ext.inner_s;
    outp=s->ext.inner_s->ext.outer_s;
    if (!ossl_assert(outp==s))
        return(0);

    /* Stash fields */
    tmp_outer=*s;
    tmp_inner=*s->ext.inner_s;

    /* General field swap */
    *s=tmp_inner;
    *inp=tmp_outer;
    s->ext.outer_s=inp;
    s->ext.inner_s=NULL;
    s->ext.outer_s->ext.inner_s=s;
    s->ext.outer_s->ext.outer_s=NULL;

    /* Copy readers and writers */
    s->wbio=tmp_outer.wbio;
    s->rbio=tmp_outer.rbio;
    s->bbio=tmp_outer.bbio;

    /* Fields we (for now) need the same in both */
    s->rlayer=tmp_outer.rlayer;
    s->rlayer.s=s;
    s->init_buf=tmp_outer.init_buf;
    s->init_msg=tmp_outer.init_msg;
    s->init_off=tmp_outer.init_off;
    s->init_num=tmp_outer.init_num;

    /*  lighttpd failure case implies I need this */
    s->handshake_func=tmp_outer.handshake_func;

    s->ext.debug_cb=tmp_outer.ext.debug_cb;
    s->ext.debug_arg=tmp_outer.ext.debug_arg;
    s->statem=tmp_outer.statem;

    /* Used by CH callback in lighttpd */
    s->ssl.ex_data=tmp_outer.ssl.ex_data;

    /*
     * Fix up the transcript to reflect the inner CH
     * If there's a cilent hello at the start of the buffer, then
     * it's likely that's the outer CH and we want to replace that
     * with the inner. We need to be careful that there could be a
     * server hello following and can't lose that.
     * I don't think the outer client hello can be anwhere except
     * at the start of the buffer.
     */

    curr_buflen = BIO_get_mem_data(tmp_outer.s3.handshake_buffer, &curr_buf);
    if (curr_buflen>0 && curr_buf[0]==SSL3_MT_CLIENT_HELLO) {
        /* It's a client hello, presumably the outer */
        outer_chlen=1+curr_buf[1]*256*256+curr_buf[2]*256+curr_buf[3];
        if (outer_chlen>curr_buflen) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return(0);
        }
        other_octets=curr_buflen-outer_chlen;
        if (other_octets>0) {
            new_buflen=tmp_outer.ext.innerch_len+other_octets;
            new_buf=OPENSSL_malloc(new_buflen);
            if (tmp_outer.ext.innerch) /* asan check added */
                memcpy(new_buf,tmp_outer.ext.innerch,tmp_outer.ext.innerch_len);
            memcpy(new_buf+tmp_outer.ext.innerch_len,
                    &curr_buf[outer_chlen],
                    other_octets);
        } else {
            new_buf=tmp_outer.ext.innerch;
            new_buflen=tmp_outer.ext.innerch_len;
        }
    } else {
        new_buf=tmp_outer.ext.innerch;
        new_buflen=tmp_outer.ext.innerch_len;
    }
    /*
     * And now reset the handshake transcript to our buffer
     * Note ssl3_finish_mac isn't that great a name - that one just
     * adds to the transcript but doesn't actually "finish" anything
     */
    if (!ssl3_init_finished_mac(s)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return(0);
    }
    if (!ssl3_finish_mac(s, new_buf, new_buflen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return(0);
    }
    ech_ptranscript("ech_swaperoo, after",s);
    if (other_octets>0) {
        OPENSSL_free(new_buf);
    }
    /*
     * Finally! Declare victory - in both contexts.
     * The outer's ech_attempted will have been set already
     * but not the rest of 'em.
     */
    s->ext.outer_s->ext.ech_attempted=1;
    s->ext.ech_attempted=1;
    s->ext.ech_attempted_type=s->ext.outer_s->ext.ech_attempted_type;
    s->ext.outer_s->ext.ech_success=1;
    s->ext.ech_success=1;
    s->ext.outer_s->ext.ech_done=1;
    s->ext.ech_done=1;
    s->ext.outer_s->ext.ech_grease=ECH_NOT_GREASE;
    s->ext.ech_grease=ECH_NOT_GREASE;

    /*
     * call ECH callback
     */
    if (s->ech!=NULL && s->ext.ech_done==1 && s->ech_cb != NULL) {
        char pstr[ECH_PBUF_SIZE+1];
        BIO *biom = BIO_new(BIO_s_mem());
        unsigned int cbrv=0;
        memset(pstr,0,ECH_PBUF_SIZE+1);
        SSL_ech_print(biom,&s->ssl,ECH_SELECT_ALL);
        BIO_read(biom,pstr,ECH_PBUF_SIZE);
        cbrv=s->ech_cb(&s->ssl,pstr);
        BIO_free(biom);
        if (cbrv != 1) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Exiting ech_swaperoo at %d\n",__LINE__);
            } OSSL_TRACE_END(TLS);
#endif
            return 0;
        }
    }

    return(1);
}

/**
 * @brief trace out transcript
 * @param msg pre-pend to trace lines
 * @param s is the SSL sessions
 */
void ech_ptranscript(const char *msg, SSL_CONNECTION *s)
{
    size_t hdatalen=0;
    unsigned char *hdata=NULL;
    unsigned char ddata[1000];
    size_t ddatalen;

    if (!s) return;
    hdatalen = BIO_get_mem_data(s->s3.handshake_buffer, &hdata);
    ech_pbuf(msg,hdata,hdatalen);
    if (s->s3.handshake_dgst!=NULL) {
        if (!ssl_handshake_hash(s,ddata,1000,&ddatalen)) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"ssl_handshake_hash failed\n");
            } OSSL_TRACE_END(TLS);
#endif
        }
        ech_pbuf(msg,ddata,ddatalen);
    } else {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"handshake_dgst is NULL\n");
        } OSSL_TRACE_END(TLS);
#endif
    }
    return;
}

/**
 * @brief send a GREASy ECH
 *
 * We send some random stuff that we hope looks like a real ECH
 *
 * The unused parameters are just to match tls_construct_ctos_ech
 * which calls this - that's in case we need 'em later.
 *
 * @param ssl is the SSL session
 * @param pkt is the in-work CH packet
 * @return 1 for success, 0 otherwise
 */
int ech_send_grease(SSL *ssl, WPACKET *pkt)
{
    hpke_suite_t hpke_suite_in = HPKE_SUITE_DEFAULT;
    hpke_suite_t *hpke_suite_in_p = NULL;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    size_t cid_len=1;
    unsigned char cid;
    size_t senderpub_len=MAX_ECH_ENC_LEN;
    unsigned char senderpub[MAX_ECH_ENC_LEN];
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);
    /*
     * 0x1d3 is what I produce for a real ECH when including padding in
     * the inner CH with the default/current client hello padding code
     * this value doesn't vary with at least minor changes to inner.sni
     * length.
     */
    size_t cipher_len=0x1d3;
     /*
      * We can add some jitter to that size, but doing so might not be
      * wise so for now, we turn off jitter as it seems like the default
      * CH padding results in a fixed length CH for at least many options.
      */
    size_t cipher_len_jitter=0;
    unsigned char cipher[MAX_ECH_PAYLOAD_LEN];
    /* stuff for copying to ech_sent */
    unsigned char *pp=WPACKET_get_curr(pkt);
    size_t pp_at_start=0;
    size_t pp_at_end=0;
   
    WPACKET_get_total_written(pkt,&pp_at_start);

    if (ssl == NULL || s == NULL || ssl->ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (RAND_bytes_ex(s->ssl.ctx->libctx, &cid, cid_len, RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (cipher_len_jitter!=0) {
        cipher_len-=cipher_len_jitter;
        cipher_len+=(cid%cipher_len_jitter);
    }
    if (s->ext.ech_grease_suite) {
        if (hpke_str2suite(s->ext.ech_grease_suite,&hpke_suite_in)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        hpke_suite_in_p=&hpke_suite_in;
    }
    if (hpke_good4grease(hpke_suite_in_p, hpke_suite,
                senderpub,&senderpub_len,cipher,cipher_len)!=1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (RAND_bytes_ex(s->ssl.ctx->libctx, &cid, cid_len, RAND_DRBG_STRENGTH) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (s->ext.ech_attempted_type==ECH_DRAFT_10_VERSION) {
        if (!WPACKET_put_bytes_u16(pkt, s->ext.ech_attempted_type)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_memcpy(pkt, &cid, cid_len)
            || !WPACKET_sub_memcpy_u16(pkt, senderpub, senderpub_len)
            || !WPACKET_sub_memcpy_u16(pkt, cipher, cipher_len)
            || !WPACKET_close(pkt)
                ) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else if (s->ext.ech_attempted_type==ECH_DRAFT_13_VERSION) {
        if (!WPACKET_put_bytes_u16(pkt, s->ext.ech_attempted_type)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, ECH_OUTER_CH_TYPE)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_memcpy(pkt, &cid, cid_len)
            || !WPACKET_sub_memcpy_u16(pkt, senderpub, senderpub_len)
            || !WPACKET_sub_memcpy_u16(pkt, cipher, cipher_len)
            || !WPACKET_close(pkt)
                ) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (s->ext.ech_sent!=NULL) OPENSSL_free(s->ext.ech_sent);
    WPACKET_get_total_written(pkt,&pp_at_end);
    s->ext.ech_sent_len=pp_at_end-pp_at_start;
    s->ext.ech_sent=OPENSSL_malloc(s->ext.ech_sent_len);
    if (!s->ext.ech_sent) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(s->ext.ech_sent,pp,s->ext.ech_sent_len);

    s->ext.ech_grease=ECH_IS_GREASE;
#ifndef OPENSSL_NO_SSL_TRACE
    OSSL_TRACE_BEGIN(TLS) {
        if (s->ext.ech_attempted_type==TLSEXT_TYPE_ech)
            BIO_printf(trc_out,"ECH - sending GREASE\n");
        else
            BIO_printf(trc_out,"ECH - sending DRAFT-13 GREASE\n");
    } OSSL_TRACE_END(TLS);
#endif
    return 1;
}

/**
 * @brief make up HPKE "info" input as per spec
 * @param tc is the ECHconfig being used
 * @param info is a caller-allocated buffer for results
 * @param info_len is the buffer size on input, used-length on output
 * @return 1 for success, other otherwise
 */
static int ech_make_enc_info(
        ECHConfig *tc,
        unsigned char *info,
        size_t *info_len)
{
    unsigned char *ip=info;

    if (!tc || !info || !info_len) return 0;
    if (*info_len < (strlen(ECH_CONTEXT_STRING)+1+tc->encoding_length))
        return 0;
   
    memcpy(ip,ECH_CONTEXT_STRING,strlen(ECH_CONTEXT_STRING));
    ip+=strlen(ECH_CONTEXT_STRING);
    *ip++=0x00;
    memcpy(ip,tc->encoding_start,tc->encoding_length);
    *info_len= strlen(ECH_CONTEXT_STRING)+1+tc->encoding_length;
    return 1;
}

/**
 * @brief Calculate AAD and then do ECH encryption
 *
 * 1. Make up the AAD:
 *   For draft-10:
 *      - the HPKE suite
 *      - my HPKE ephemeral public key
 *      - the encoded outer, minus the ECH
 *   For draft-13:
 *      - the encoded outer, with ECH ciphertext octets zero'd
 * 2. Do the encryption
 * 3. Put the ECH back into the encoding
 * 4. Encode the outer (again!)
 *
 * @param ssl is the SSL struct
 * @param pkt is the packet to send
 * @return 1 for success, other otherwise
 *
 */
int ech_aad_and_encrypt(SSL *ssl, WPACKET *pkt)
{
    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    size_t cipherlen=HPKE_MAXSIZE;
    unsigned char cipher[HPKE_MAXSIZE];
    unsigned char *aad=NULL;
    size_t aad_len=0;
    unsigned char config_id_to_use=0x00; /* we might replace with random */
    /*
     * My ephemeral key pair for HPKE encryption
     * Has to be externally generated so public can be part of AAD (sigh)
     */
    unsigned char mypub[HPKE_MAXSIZE];
    size_t mypub_len=HPKE_MAXSIZE;
    EVP_PKEY *mypriv_evp=NULL;

    /*
     * Pick a matching public key from the Config (if we can)
     * We'll just take the 1st matching.
     */
    unsigned char *peerpub=NULL;
    size_t peerpub_len=0;

    ECHConfig *tc=NULL;
    int cind=0;
    ECHConfigs *cfgs=NULL;
    unsigned int onlen=0;
    int prefind=-1;
    ECHConfig *firstmatch=NULL;
    unsigned char *cp=NULL;
    unsigned char info[HPKE_MAXSIZE];
    size_t info_len=HPKE_MAXSIZE;
    int rv=0;
    size_t echextlen=0;
    unsigned char *startofmessage=NULL;
    size_t suitesoffset=0;
    size_t suiteslen=0;
    size_t startofexts=0;
    size_t origextlens=0;
    size_t newextlens=0;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (!s || !s->ech || !pkt) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    cfgs=s->ech->cfg;
    if (!cfgs || cfgs->nrecs==0) {
        /*
         * Treating this as an error. Note there could be
         * some corner case with SCVB that gets us here
         * with cfgs==NULL but hopefully not
         */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * Search through the ECHConfigs for one that's a best
     * match in terms of outer_name==public_name.
     * If no public_name was set via API then we
     * just take the 1st match where we locally support
     * the HPKE suite.
     * If OTOH, a public_name was provided via API then
     * we prefer the first that matches that.
     */
    onlen=(s->ech->outer_name==NULL?0:strlen(s->ech->outer_name));
    for (cind=0;cind!=cfgs->nrecs;cind++) {
        ECHConfig *ltc=&cfgs->recs[cind];
        unsigned int csuite=0;
        if (s->ech->outer_name && (
                ltc->public_name_len!=onlen ||
                strncmp(s->ech->outer_name,(char*)ltc->public_name,onlen))) {
            prefind=cind;
        }
        hpke_suite.kem_id=ltc->kem_id;
        for (csuite=0;csuite!=ltc->nsuites;csuite++) {
            unsigned char *es=(unsigned char*)&ltc->ciphersuites[csuite];
            hpke_suite.kdf_id=es[0]*256+es[1];
            hpke_suite.aead_id=es[2]*256+es[3];
            if (hpke_suite_check(hpke_suite)==1) {
                /* success if both "fit" */
                if (prefind!=-1) {
                    tc=ltc;
                    break;
                }
                if (firstmatch==NULL) {
                    firstmatch=ltc;
                }
            }
        }
    }
    if (tc==NULL && firstmatch==NULL) {
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"EAAE: No matching ECHConfig sadly\n");
        } OSSL_TRACE_END(TLS);
#endif
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (tc==NULL && firstmatch!=NULL) {
        tc=firstmatch;
    }
    /* tc is our selected config */
#ifndef OPENSSL_NO_SSL_TRACE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"EAAE: selected: version: %4x, config %2x\n",
                tc->version,tc->config_id);
    } OSSL_TRACE_END(TLS);
#endif
    if (tc->pub_len==0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    peerpub_len=tc->pub_len;
    peerpub=tc->pub;
    if (s->ext.inner_s==NULL || s->ext.inner_s->ech==NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ech_pbuf("EAAE: peer pub",peerpub,peerpub_len);
    ech_pbuf("EAAE: clear",s->ext.inner_s->ext.encoded_innerch,
            s->ext.inner_s->ext.encoded_innerch_len);

    if (hpke_kg_evp(hpke_mode, hpke_suite, &mypub_len, mypub, &mypriv_evp)!=1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (mypub_len>HPKE_MAXSIZE || mypriv_evp==NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ech_pbuf("EAAE: my pub",mypub,mypub_len);
    ech_pbuf("EAAE: config id input",tc->encoding_start,tc->encoding_length);
    if (s->ssl.ctx && (s->ssl.ctx->options & SSL_OP_ECH_IGNORE_CID)) {
        RAND_bytes(&config_id_to_use,1);
        ech_pbuf("EAAE: random config_id",&config_id_to_use,1);
    } else {
        config_id_to_use=tc->config_id;
        ech_pbuf("EAAE: config_id",&config_id_to_use,1);
    }

    if (tc->version==ECH_DRAFT_10_VERSION) {
        /*
         * draft-10 AAD:
         * struct {
         *   HpkeSymmetricCipherSuite cipher_suite;
         *   uint8 config_id;
         *   opaque enc<1..2^16-1>;
         *   opaque outer_hello<1..2^24-1>;
         * } ClientHelloOuterAAD;
         *
         * The struct above causes the aad_len values below.
         * The "-4" for the pkt removes the type and 3-octet
         * length from the encoded CH as per the spec.
         */
        aad_len=4+1+2+mypub_len+3+pkt->written-4;
        aad=OPENSSL_malloc(aad_len);
        if (aad==NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        cp=aad;
        *cp++=(unsigned char)((hpke_suite.kdf_id&0xffff)/256);
        *cp++=(unsigned char)((hpke_suite.kdf_id&0xffff)%256);
        *cp++=(unsigned char)((hpke_suite.aead_id&0xffff)/256);
        *cp++=(unsigned char)((hpke_suite.aead_id&0xffff)%256);
        *cp++=(unsigned char)config_id_to_use;
        *cp++=(unsigned char)((mypub_len&0xffff)/256);
        *cp++=(unsigned char)((mypub_len&0xffff)%256);
        memcpy(cp,mypub,mypub_len); cp+=mypub_len;
        *cp++=(unsigned char)(((pkt->written-4)&0xffffff)/(256*256));
        *cp++=(unsigned char)(((pkt->written-4)&0xffffff)/256);
        *cp++=(unsigned char)((pkt->written-4)%256);
        memcpy(cp,pkt->buf->data+4,pkt->written-4);
        ech_pbuf("EAAE: aad",aad,aad_len);

        if (ech_make_enc_info(tc,info,&info_len)!=1) {
         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
         goto err;
        }
        ech_pbuf("EAAE info",info,info_len);
        rv=hpke_enc_evp(
            hpke_mode, hpke_suite, /* mode, suite */
            NULL, 0, NULL, /* pskid, psk */
            peerpub_len,peerpub,
            0, NULL, /* priv */
            s->ext.inner_s->ext.encoded_innerch_len,
            s->ext.inner_s->ext.encoded_innerch, /* clear */
            aad_len, aad,
            info_len, info,
            mypub_len, mypub, mypriv_evp,
            &cipherlen, cipher
            );
        if (rv!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ech_pbuf("EAAE: hpke mypub",mypub,mypub_len);
        ech_pbuf("EAAE: cipher",cipher,cipherlen);
        OPENSSL_free(aad); aad=NULL;
        /*
        * We ditch the ephemeral key now.
        * We would need that for HRR, but likely we'll
        * only code up HRR for draft-13 so it'll be ok
        * to not hang onto the private key here if
        * that's easier.
        */
        EVP_PKEY_free(mypriv_evp); mypriv_evp=NULL;
        ech_pbuf("EAAE pkt b4",(unsigned char*) pkt->buf->data,pkt->written);
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ech)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_put_bytes_u8(pkt, config_id_to_use)
            || !WPACKET_sub_memcpy_u16(pkt, mypub, mypub_len)
            || !WPACKET_sub_memcpy_u16(pkt, cipher, cipherlen)
            || !WPACKET_close(pkt)
                ) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
        }

        /*
         * draft-10 length of ECH to include is the usual ext
         * type and length (2 octets each) plus...
         *
         *  struct {
         *     HpkeSymmetricCipherSuite cipher_suite;
         *     uint8 config_id;
         *     opaque enc<1..2^16-1>;
         *     opaque payload<1..2^16-1>;
         *  } ClientECH;
         *
         */
        echextlen=2+ /* ext type */
                  2+ /* ext len */
                  4+ /* cipher_suite */
                  1+ /* config id */
                  2+ /* len(enc) */
                  mypub_len+ /* enc */
                  2+ /* len(payload) */
                  cipherlen; /* payload */

        /*
         * suitesoffset points to the end of the session ID, just
         * before the ciphersuites
         */
        startofmessage=(unsigned char*)pkt->buf->data;
        suitesoffset=6+32+1+s->tmp_session_id_len;
        suiteslen=startofmessage[suitesoffset]*256+
            startofmessage[suitesoffset+1];
        startofexts=suitesoffset+suiteslen+2+2; /* the 2 for the suites len */
        origextlens=startofmessage[startofexts]*256+
            startofmessage[startofexts+1];
        newextlens=origextlens+echextlen;
        startofmessage[startofexts]=(unsigned char)((newextlens&0xffff)/256);
        startofmessage[startofexts+1]=(unsigned char)((newextlens&0xffff)%256);

    }

    if (tc->version==ECH_DRAFT_13_VERSION) {
        /*
         * For draft-13 the AAD is the full outer client hello but
         * with the correct number of zeros for where the ciphertext
         * octets will later be placed.
         *
         * Add the ECH extension to the |pkt| but with zeros for
         * ciphertext - that'll form up the AAD for us, then after
         * we've encrypted, we'll splice in the actual ciphertext
         *
         * Watch out for the the "4" offsets that remove the type
         * and 3-octet length from the encoded CH as per the spec.
         */
        size_t lcipherlen=0;
        size_t echlen=0;
        unsigned char *zeros=NULL;
        int length_of_padding=0;
        int length_with_snipadding=0;
        int length_with_padding=0;
        unsigned char *clear=NULL;
        size_t clear_len=0;
        size_t mnl=tc->maximum_name_length;
        int innersnipadding=0;

        /*
         * "recommended" inner SNI padding scheme as per spec
         * might remove later - overall message padding seems
         * better really, BUT... we might want to keep this if
         * others (e.g. browsers) do it so as to not stand
         * out compared to them
         */
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"EAAE: ECHConfig had max name len of %zu\n",mnl);
        } OSSL_TRACE_END(TLS);
#endif
        if (mnl!=0) {
            /* do weirder padding if SNI present in inner */
            if (s->ext.inner_s->ext.hostname!=0) {
                size_t isnilen=strlen(s->ext.inner_s->ext.hostname)+9;
                innersnipadding=mnl-isnilen;
            } else {
                innersnipadding=mnl+9;
            }
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"EAAE: innersnipadding of %d\n",
                        innersnipadding);
            } OSSL_TRACE_END(TLS);
#endif
            if (innersnipadding<0) {
#ifndef OPENSSL_NO_SSL_TRACE
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out,"EAAE: innersnipadding zero'd\n");
                } OSSL_TRACE_END(TLS);
#endif
                innersnipadding=0;
            }
        }

        /* draft-13 padding is after the encoded client hello*/
        length_with_snipadding=innersnipadding+
                            s->ext.inner_s->ext.encoded_innerch_len;
        length_of_padding=31-((length_with_snipadding-1)%32);
        length_with_padding=s->ext.inner_s->ext.encoded_innerch_len+
                length_of_padding+innersnipadding;
        /*
         * finally - make sure we're longer than padding target too
         * this is a local addition - might take it out if it makesw
         * us stick out (of if we take out the above more complicated
         * scheme, we may only need this in the end
         */
        while(length_with_padding<ECH_PADDING_TARGET) {
            length_with_padding+=ECH_PADDING_INCREMENT;
        }
        clear_len=length_with_padding;
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"EAAE: padding: mnl: %zu, lws: %d " \
                    "lop: %d, lwp: %d, clear_len: %zu, orig: %zu\n",
                mnl, length_with_snipadding, length_of_padding,
                length_with_padding, clear_len,
                s->ext.inner_s->ext.encoded_innerch_len);
        } OSSL_TRACE_END(TLS);
#endif
        if (hpke_expansion(hpke_suite,clear_len,&lcipherlen)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        echlen=1+4+1+2+mypub_len+2+lcipherlen;

        zeros=OPENSSL_zalloc(lcipherlen);
        if (!zeros) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ech13)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, ECH_OUTER_CH_TYPE)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
            || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
            || !WPACKET_put_bytes_u8(pkt, config_id_to_use)
            || !WPACKET_sub_memcpy_u16(pkt, mypub, mypub_len)
            || !WPACKET_sub_memcpy_u16(pkt, zeros, lcipherlen)
            || !WPACKET_close(pkt)
           ) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        OPENSSL_free(zeros); zeros=NULL;

        aad=(unsigned char*)(pkt->buf->data)+4;
        aad_len=pkt->written-4;

        /* fix up the overall extensions length in the aad */
        suitesoffset=2+32+1+s->tmp_session_id_len;
        suiteslen=aad[suitesoffset]*256+aad[suitesoffset+1];
        startofexts=suitesoffset+suiteslen+2+2; /* the 2 for the suites len */
        origextlens=aad[startofexts]*256+aad[startofexts+1];
        newextlens=origextlens+4+echlen;
        aad[startofexts]=(unsigned char)((newextlens&0xffff)/256);
        aad[startofexts+1]=(unsigned char)((newextlens&0xffff)%256);
        ech_pbuf("EAAE: aad",aad,aad_len);

        if (ech_make_enc_info(tc,info,&info_len)!=1) {
         SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
         goto err;
        }
        ech_pbuf("EAAE info",info,info_len);

        clear=OPENSSL_zalloc(clear_len);
        if (!clear) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(clear,s->ext.inner_s->ext.encoded_innerch,
                s->ext.inner_s->ext.encoded_innerch_len);
        ech_pbuf("EAAE: draft-13 padded clear",clear,clear_len);

        rv=hpke_enc_evp(
            hpke_mode, hpke_suite, /* mode, suite */
            NULL, 0, NULL, /* pskid, psk */
            peerpub_len,peerpub,
            0, NULL, /* priv */
            clear_len,clear,
            aad_len, aad,
            info_len, info,
            mypub_len, mypub, mypriv_evp,
            &cipherlen, cipher
            );
        OPENSSL_free(clear);
        if (rv!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ech_pbuf("EAAE: hpke mypub",mypub,mypub_len);
        ech_pbuf("EAAE: cipher",cipher,cipherlen);

        /*
        * We ditch the ephemeral key now.
        * TODO: we'll need that for HRR later
        */
        EVP_PKEY_free(mypriv_evp); mypriv_evp=NULL;

        /* splice real ciphertext back in now */
        memcpy(aad+aad_len-cipherlen,cipher,cipherlen);

    }

    ech_pbuf("EAAE pkt to startofexts+6 (startofexts is 4 offset so +2 really)",
            (unsigned char*) pkt->buf->data,startofexts+6);
    ech_pbuf("EAAE pkt aftr",(unsigned char*) pkt->buf->data,pkt->written);

    return 1;

err:
    if (aad!=NULL) OPENSSL_free(aad);
    if (mypriv_evp!=NULL) EVP_PKEY_free(mypriv_evp);
    return 0;
}

/**
 * @brief Server forms up AAD from included fields
 *
 * The actual AAD length is returned on success.
 *
 * @param kdf_id is obvious
 * @param aead_id is obvious
 * @param pub_len is the length of the public key
 * @param pub is the public key
 * @param config_id is the ECH config id
 * @param de_len is the length of the CH minus ECH
 * @param de is the CH minus ECH
 * @param aad_len is the length of AAD buffer on input
 * @param aad is the AAD buffer on input
 * @param de is the CH minus ECH
 * @return 1 for good, other otherwise
 */
static int ech_srv_get_aad(
        uint16_t kdf_id, uint16_t aead_id,
        size_t pub_len, unsigned char *pub,
        uint8_t config_id,
        size_t de_len, unsigned char *de,
        size_t *aad_len,unsigned char *aad)
{
    unsigned char *cp=aad;

    if (!pub || !de || !aad_len || !aad) return 0;

#define CPCHECK if ((size_t)(cp-aad)>*aad_len) return 0;

    *cp++=((kdf_id&0xffff)/256);
    CPCHECK
    *cp++=((kdf_id&0xffff)%256);
    CPCHECK
    *cp++=((aead_id&0xffff)/256);
    CPCHECK
    *cp++=((aead_id&0xffff)%256);
    CPCHECK
    *cp++=config_id&0xff;
    CPCHECK
    *cp++=(unsigned char)((pub_len&0xffff)/256);
    CPCHECK
    *cp++=(unsigned char)((pub_len&0xffff)%256);
    CPCHECK
    memcpy(cp,pub,pub_len); cp+=pub_len;
    CPCHECK

    *cp++=(unsigned char)((de_len&0xffffff)/(256*256));
    CPCHECK
    *cp++=(unsigned char)((de_len&0xffff)/256);
    CPCHECK
    *cp++=(unsigned char)((de_len&0xff)%256);
    CPCHECK
    memcpy(cp,de,de_len); cp+=de_len;
    CPCHECK

    *aad_len=(size_t)(cp-aad);

    ech_pbuf("SRV AAD:",aad,*aad_len);

    return 1;
}

/*!
 * Given a CH find the offsets of the session id, extensions and ECH
 *
 * @param: pkt is the CH
 * @param: sessid points to offset of session_id length
 * @param: exts points to offset of extensions
 * @param: echoffset points to offset of ECH
 * @param: echtype points to the ext type of the ECH
 * @param: snioffset points to offset of (outer) SNI
 * @return 1 for success, other otherwise
 *
 * Offsets are set to zero at start and must be non-zero to be
 * meaningful. If no ECH is present (or no extensions) then
 * those will be returned as zero.
 * Offsets are returned to the type or length field in question.
 */
static int ech_get_offsets(
        PACKET *pkt,
        size_t *sessid,
        size_t *exts,
        size_t *echoffset,
        uint16_t *echtype,
        size_t *snioffset)
{
    const unsigned char *ch=NULL;
    size_t ch_len=0;
    size_t genoffset=0;
    size_t sessid_len=0;
    size_t suiteslen=0;
    size_t startofexts=0;
    size_t origextlens=0;
    size_t echlen=0; /* length of ECH, including type & ECH-internal length */
    size_t snilen=0;
    const unsigned char *e_start=NULL;
    int extsremaining=0;
    uint16_t etype=0;
    size_t elen=0;

    if (!pkt || !sessid || !exts || !echoffset || !echtype) return(0);

    *sessid=0;
    *exts=0;
    *echoffset=0;
    *echtype=TLSEXT_TYPE_ech_unknown;
    *snioffset=0;

    ch=pkt->curr;
    ch_len=pkt->remaining;

    /*
     * We'll start genoffset at the start of the session ID, just
     * before the ciphersuites
     */
    *sessid=2+32; /* point to length of sessid */
    genoffset=*sessid;
    if (ch_len<=genoffset) return 0;
    sessid_len=ch[genoffset];
    genoffset+=(1+sessid_len);
    if (ch_len<=(genoffset+2)) return 0;
    suiteslen=ch[genoffset]*256+ch[genoffset+1];
    startofexts=genoffset+suiteslen+2+2; /* the 2 for the suites len */
    if (startofexts==ch_len) {
        /* no extensions present, which is fine */
        return(1);
    }
    if (startofexts>ch_len) {
        /* oops, shouldn't happen but just in case... */
        return(0);
    }
    *exts=startofexts; /* set output */
    origextlens=ch[startofexts]*256+ch[startofexts+1];
    if ((startofexts+2)>(ch_len-startofexts)) {
         return 0;
    }
    /*
     * find ECH if it's there
     */
    e_start=&ch[startofexts+2];
    extsremaining=origextlens-2;

    while (extsremaining>0) {
        if (ch_len<(4+(size_t)(e_start-ch))) {
            return 0;
        }
        etype=e_start[0]*256+e_start[1];
        elen=e_start[2]*256+e_start[3];
        if (etype==TLSEXT_TYPE_ech || etype==TLSEXT_TYPE_ech13) {
            echlen=elen+4; /* type and length included */
            *echtype=etype;
            *echoffset=(e_start-ch); /* set output */
        } else if (etype==TLSEXT_TYPE_server_name) {
            snilen=elen+4; /* type and length included */
            *snioffset=(e_start-ch); /* set output */
        }
        e_start+=(4+elen);
        extsremaining-=(4+elen);
    }
    ech_pbuf("orig CH",(unsigned char*) ch,ch_len);
    ech_pbuf("orig CH session_id",(unsigned char*) ch+*sessid+1,sessid_len);
    ech_pbuf("orig CH exts",(unsigned char*) ch+*exts,origextlens);
#ifndef OPENSSL_NO_SSL_TRACE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"orig CH/ECH type: %4x\n",*echtype);
    } OSSL_TRACE_END(TLS);
#endif
    ech_pbuf("orig CH/ECH",(unsigned char*) ch+*echoffset,echlen);
    ech_pbuf("orig CH SNI",(unsigned char*) ch+*snioffset,snilen);
    return(1);
}

/**
 * @brief wrapper for hpke_dec just to save code repetition
 *
 * The plaintext returned is allocated here and must
 * be freed by the caller later.
 *
 * @param ech is the selected ECHConfig
 * @param the_ech is the value sent by the client
 * @param aad_len is the length of the AAD to use
 * @param aad is the AAD to use
 * @param innerlen points to the size of the recovered plaintext
 * @return pointer to plaintext or NULL (if error)
 */
static unsigned char *hpke_decrypt_encch(
        SSL_ECH *ech,
        ECH_ENCCH *the_ech,
        size_t aad_len, unsigned char *aad,
        size_t *innerlen)
{
    size_t publen=0; unsigned char *pub=NULL;
    size_t cipherlen=0; unsigned char *cipher=NULL;
    size_t senderpublen=0; unsigned char *senderpub=NULL;
    size_t clearlen=0; unsigned char *clear=NULL;
    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    unsigned char info[HPKE_MAXSIZE];
    size_t info_len=HPKE_MAXSIZE;
    int rv=0;

    cipherlen=the_ech->payload_len;
    cipher=the_ech->payload;
    senderpublen=the_ech->enc_len;
    senderpub=the_ech->enc;
    hpke_suite.aead_id=the_ech->aead_id;
    hpke_suite.kdf_id=the_ech->kdf_id;
    clearlen=cipherlen; /* small overestimate */
    clear=OPENSSL_malloc(clearlen);
    if (!clear) return NULL;
    /*
     * We only support one ECHConfig for now on the server side
     * The calling code looks after matching the ECH.config_id
     * and/or trial decryption.
     */
    publen=ech->cfg->recs[0].pub_len;
    pub=ech->cfg->recs[0].pub;
    hpke_suite.kem_id=ech->cfg->recs[0].kem_id;

    ech_pbuf("aad",aad,aad_len);
    ech_pbuf("my local pub",pub,publen);
    ech_pbuf("senderpub",senderpub,senderpublen);
    ech_pbuf("cipher",cipher,cipherlen);
    if (ech_make_enc_info(ech->cfg->recs,info,&info_len)!=1) {
        OPENSSL_free(clear);
        return NULL;
    }
    ech_pbuf("info",info,info_len);
    /*
     * We may generate externally visible OpenSSL errors
     * if decryption fails (which is normal) but we'll
     * ignore those as we might be dealing with a GREASEd
     * ECH. The way to do that is to consume all
     * errors generated internally during the attempt
     * to decrypt. Failing to clear those errors can
     * trigger an application to consider TLS session
     * establishment has failed when someone just
     * GREASEd or used an old key.  But to do that we
     * first need to know there are no other errors in
     * the queue that we ought not consume as the application
     * really should know about those.
     */
    if (ERR_peek_error()!=0) {
        OPENSSL_free(clear);
        return NULL;
    }
#ifndef OPENSSL_NO_SSL_TRACE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"hpke_dec suite: kem: %04x, kdf: %04x, aead: %04x\n",
            hpke_suite.kem_id, hpke_suite.kdf_id, hpke_suite.aead_id);
    } OSSL_TRACE_END(TLS);
#endif
    rv=hpke_dec( hpke_mode, hpke_suite,
                NULL, 0, NULL, /* pskid, psk */
                0, NULL, /* publen, pub, recipient public key */
                0,NULL,ech->keyshare, /* private key in EVP_PKEY form */
                senderpublen, senderpub, /* sender public */
                cipherlen, cipher,
                aad_len,aad,
                info_len, info,
                &clearlen, clear);
    /*
     * clear errors from failed decryption as per the above
     * we do this before checking the result from hpke_dec
     * */
    while (ERR_get_error()!=0);
    if (rv!=1) {
        OPENSSL_free(clear);
        return NULL;
    }
    ech_pbuf("clear",clear,clearlen);
    *innerlen=clearlen;
    if (ech->cfg->recs[0].version==ECH_DRAFT_13_VERSION) {
        /* draft-13 pads after the encoded CH with zeros */
        /* TODO: merge this, and any similar, with ech_get_offsets */
        /* TODO: add bounds checks */
        size_t suitesoffset=2+0x20+1;
        size_t suiteslen=0;
        size_t extsoffset=0;
        size_t extslen=0;
        size_t ch_len=0;
        if ((suitesoffset+1) > clearlen) {
            OPENSSL_free(clear);
            return NULL;
        }
        suiteslen=(unsigned char)(clear[suitesoffset])*256+
                         (unsigned char)(clear[suitesoffset+1]);
        extsoffset=suitesoffset+2+suiteslen+2;
        if ((extsoffset+1) > clearlen) {
            OPENSSL_free(clear);
            return NULL;
        }
        extslen=(unsigned char)(clear[extsoffset])*256+
                       (unsigned char)(clear[extsoffset+1]);
        ch_len=extsoffset+2+extslen;
        if (ch_len>clearlen) {
            OPENSSL_free(clear);
            return NULL;
        }
#define CHECKZEROS
#ifdef CHECKZEROS
        {
            size_t zind=0;
            size_t nonzeros=0;
            size_t zeros=0;
            if (*innerlen<=ch_len) {
                OPENSSL_free(clear); clear=NULL;
                return NULL;
            }
            for(zind=ch_len;zind!=*innerlen;zind++) {
                if (clear[zind]==0x00) {
                    zeros++;
                } else {
                    nonzeros++;
                }
            }
            if (nonzeros>0 || zeros!=(*innerlen-ch_len)) {
                OPENSSL_free(clear); clear=NULL;
                return NULL;
            }
        }
#endif
        *innerlen=ch_len;
        ech_pbuf("unpadded clear",clear,*innerlen);
    }
    return clear;
}

/*
 * If an ECH is present, attempt decryption
 *
 * If decryption succeeds, then we'll swap the inner and outer
 * CHs so that all further processing will only take into account
 * the inner CH.
 *
 * The fact that decryption worked is signalled to the caller
 * via s->ext.ech_success
 *
 * This function is called early, (hence then name:-), before
 * the outer CH decoding has really started
 *
 * @param ssl: SSL session stuff
 * @param pkt: the received CH that might include an ECH
 * @param newpkt: the plaintext from ECH
 * @return 1 for success, zero otherwise
 */
int ech_early_decrypt(SSL *ssl, PACKET *outerpkt, PACKET *newpkt)
{
    /*
     * The plan:
     * 1. check if there's an ECH
     * 2. trial-decrypt or check if config matches one loaded
     * 3. if decrypt fails tee-up GREASE
     * 4. if decrypt worked, decode and de-compress cleartext to
     *    make up real inner CH for later processing
     */
    int rv=0;
    ECH_ENCCH *extval=NULL;
    PACKET echpkt;
    PACKET *pkt=NULL;
    const unsigned char *startofech=NULL;
    size_t echlen=0;
    size_t clearlen=0;
    unsigned char *clear=NULL;
    unsigned int tmp;
    unsigned char aad[HPKE_MAXSIZE];
    size_t aad_len=HPKE_MAXSIZE;
    unsigned char de[HPKE_MAXSIZE];
    size_t de_len=HPKE_MAXSIZE;
    size_t newextlens=0;
    size_t beforeECH=0;
    size_t afterECH=0;
    int cfgind=-1;
    int foundcfg=0;

    /*
     * 1. check if there's an ECH
     */
    size_t startofsessid=0; /**< offset of session id within Ch */
    size_t startofexts=0; /**< offset of extensions within CH */
    size_t echoffset=0; /**< offset of start of ECH within CH */
    uint16_t echtype=TLSEXT_TYPE_ech_unknown; /**< type of ECH seen */
    size_t outersnioffset=0; /**< offset to SNI in outer */
    size_t ch_len=outerpkt->remaining; /**< overall length of outer CH */
    const unsigned char *ch=outerpkt->curr;
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (s == NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return(rv);
    }
    rv=ech_get_offsets(outerpkt,&startofsessid,&startofexts,
            &echoffset,&echtype,&outersnioffset);
    if (rv!=1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return(rv);
    }
    if (echoffset==0) return(1); /* ECH not present */
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"EARLY: found an ECH\n");
    } OSSL_TRACE_END(TLS);

    /* Remember that we got an ECH */
    s->ext.ech_attempted=1;
    s->ext.ech_attempted_type=echtype;

    /* We need to grab the session id */
    s->tmp_session_id_len=outerpkt->curr[startofsessid];
    if (s->tmp_session_id_len>SSL_MAX_SSL_SESSION_ID_LENGTH) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"EARLY: bad sess id len %zu vs max %d\n",
                s->tmp_session_id_len,SSL_MAX_SSL_SESSION_ID_LENGTH);
        } OSSL_TRACE_END(TLS);
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    memcpy(s->tmp_session_id,
           &outerpkt->curr[startofsessid+1],
           s->tmp_session_id_len);

    /* Grab the outer SNI for tracing.  */
    if (outersnioffset>0) {
        PACKET osni;
        const unsigned char *osnibuf=&outerpkt->curr[outersnioffset+4];
        size_t osnilen=outerpkt->curr[outersnioffset+2]*256+
                       outerpkt->curr[outersnioffset+3];
        if (PACKET_buf_init(&osni,osnibuf,osnilen)!=1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (tls_parse_ctos_server_name(s, &osni, 0, NULL, 0)!=1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        s->ech->outer_name=s->ext.hostname;
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"EARLY: outer SNI of %s\n",s->ext.hostname);
        } OSSL_TRACE_END(TLS);
#endif
        /* clean up  */
        s->ext.hostname=NULL;
        s->servername_done=0;
    }
#ifndef OPENSSL_NO_SSL_TRACE
    else
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"EARLY: no sign of an outer SNI\n");
        } OSSL_TRACE_END(TLS);
#endif

    /*
     * 2. trial-decrypt or check if config matches one loaded
     */
    startofech=&outerpkt->curr[echoffset+4];
    echlen=outerpkt->curr[echoffset+2]*256+outerpkt->curr[echoffset+3];
    rv=PACKET_buf_init(&echpkt,startofech,echlen);
    pkt=&echpkt;

    /*
     * Try Decode the inbound value.
     * For draft-10:
     *  struct {
     *    ECHCipherSuite cipher_suite;
     *    uint8 config_id;
     *    opaque enc<1..2^16-1>;
     *    opaque payload<1..2^16-1>;
     *   } ClientECH;
     *
     * For draft-13, we're only concerned with the "inner"
     * form just here:
     *  enum { outer(0), inner(1) } ECHClientHelloType;
     *  struct {
     *     ECHClientHelloType type;
     *     select (ECHClientHello.type) {
     *         case outer:
     *             HpkeSymmetricCipherSuite cipher_suite;
     *             uint8 config_id;
     *             opaque enc<0..2^16-1>;
     *             opaque payload<1..2^16-1>;
     *         case inner:
     *             Empty;
     *     };
     *  } ECHClientHello;
     */

    extval=OPENSSL_zalloc(sizeof(ECH_ENCCH));
    if (extval==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (echtype==ECH_DRAFT_13_VERSION) {
        unsigned char innerorouter=0xff;
        if (!PACKET_copy_bytes(pkt, &innerorouter, 1)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (innerorouter!=ECH_OUTER_CH_TYPE) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
    }
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->kdf_id=tmp&0xffff;
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->aead_id=tmp&0xffff;

    /* config id */
    if (!PACKET_copy_bytes(pkt, &extval->config_id, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    ech_pbuf("EARLY config id",&extval->config_id,1);

    /* enc - the client's public share */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > ECH_MAX_ECH_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp>PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->enc_len=tmp;
    extval->enc=OPENSSL_malloc(tmp);
    if (extval->enc==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, extval->enc, tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }

    /* payload - the encrypted CH */
    if (!PACKET_get_net_2(pkt, &tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp > ECH_MAX_PAYLOAD_LEN) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (tmp>PACKET_remaining(pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    extval->payload_len=tmp;
    extval->payload=OPENSSL_malloc(tmp);
    if (extval->payload==NULL) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    if (!PACKET_copy_bytes(pkt, extval->payload, tmp)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }

    /*
     * Calculate AAD value
     */
    if (echtype==ECH_DRAFT_10_VERSION) {
        /* newextlen = length of exts after taking out ech */
        newextlens=ch_len-echlen-startofexts-6;
        memcpy(de,ch,startofexts);
        de[startofexts]=(unsigned char)((newextlens&0xffff)/256);
        de[startofexts+1]=(unsigned char)((newextlens&0xffff)%256);
        beforeECH=echoffset-startofexts-2;
        afterECH=ch_len-(echoffset+echlen);
        memcpy(de+startofexts+2,ch+startofexts+2,beforeECH);
        memcpy(de+startofexts+2+beforeECH,
                ch+startofexts+2+beforeECH+echlen+4,
                afterECH);
        de_len=ch_len-echlen-4;
        if (ech_srv_get_aad(
                    extval->kdf_id, extval->aead_id,
                    extval->enc_len, extval->enc,
                    extval->config_id,
                    de_len,de,
                    &aad_len,aad)!=1) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        ech_pbuf("EARLY aad",aad,aad_len);
    }

    if (echtype==ECH_DRAFT_13_VERSION) {
        /* AAD in draft-13 is rx'd packet with ciphertext zero'd */
        /* TODO: merge with ech_get_offsets */
        size_t startofciphertext=0;
        size_t lenofciphertext=0;
        size_t enclen=0;
        size_t offsetofencwithinech=0;
        offsetofencwithinech=2+2+1+2+2+1;
        if ((echoffset+offsetofencwithinech+1)>ch_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        enclen=
            ch[echoffset+offsetofencwithinech]*256+
            ch[echoffset+offsetofencwithinech+1];
        if ((echoffset+offsetofencwithinech+2+enclen+1)>ch_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        lenofciphertext=
            ch[echoffset+offsetofencwithinech+2+enclen]*256+
            ch[echoffset+offsetofencwithinech+2+enclen+1];
        startofciphertext=echoffset+offsetofencwithinech+2+enclen+2;
        if ((startofciphertext+lenofciphertext)>ch_len) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        if (ch_len>HPKE_MAXSIZE) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            goto err;
        }
        aad_len=ch_len;
        memcpy(aad,ch,aad_len);
        memset(aad+startofciphertext,0,lenofciphertext);
        ech_pbuf("EARLY aad",aad,aad_len);
    }

    /*
     * Now see which (if any) of our configs match, or whether
     * we want/need to trial decrypt
     */
    s->ext.ech_grease=ECH_GREASE_UNKNOWN;
   
    if (s->ech->cfg==NULL || s->ech->cfg->nrecs==0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        goto err;
    }
    for (cfgind=0;cfgind!=s->nechs;cfgind++) {
        ECHConfig *e=&s->ech[cfgind].cfg->recs[0];
#ifndef OPENSSL_NO_SSL_TRACE
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,
                    "EARLY: rx'd config id (%x) ==? %d-th configured (%x)\n",
                    extval->config_id,cfgind,e->config_id);
        } OSSL_TRACE_END(TLS);
#endif
        if (extval->config_id==e->config_id) {
            foundcfg=1;
            break;
        }
    }
    if (foundcfg==1) {
        clear=hpke_decrypt_encch(&s->ech[cfgind],extval,aad_len,aad,&clearlen);
        if (clear==NULL) {
            s->ext.ech_grease=ECH_IS_GREASE;
        }
    }

    /*
     * Trial decrypt, if still needed
     */
    if (!foundcfg && (s->options & SSL_OP_ECH_TRIALDECRYPT)) {
        for (cfgind=0;cfgind!=s->nechs;cfgind++) {
            clear=hpke_decrypt_encch(&s->ech[cfgind],
                    extval,aad_len,aad,&clearlen);
            if (clear!=NULL) {
                foundcfg=1;
                break;
            }
        }
    }

    /*
     * We succeeded or failed in decrypting, but we're done
     * with that now.
     */
    s->ext.ech_done=1;

    /*
     * 3. if decrypt fails tee-up GREASE
     */
    if (clear==NULL) {
        s->ext.ech_grease=ECH_IS_GREASE;
        s->ext.ech_success=0;
    } else {
        s->ext.ech_grease=ECH_NOT_GREASE;
        s->ext.ech_success=1;
    }
#ifndef OPENSSL_NO_SSL_TRACE
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,
            "EARLY: success: %d, assume_grease: %d, " \
            "foundcfg: %d, cfgind: %d, clearlen: %zd, clear %p\n",
            s->ext.ech_success,s->ext.ech_grease,foundcfg,
            cfgind,clearlen,(void*)clear);
    } OSSL_TRACE_END(TLS);
#endif

    /*
     * Bit more logging
     */
    if (foundcfg==1) {
        ECHConfig *e=&s->ech[cfgind].cfg->recs[0];
        ech_pbuf("local config_id",&e->config_id,1);
        ech_pbuf("remote config_id",&extval->config_id,1);
        ech_pbuf("clear",clear,clearlen);
    }

    if (extval!=NULL) {
        ECH_ENCCH_free(extval);
        OPENSSL_free(extval);
        extval=NULL;
    }

    if (s->ext.ech_grease==ECH_IS_GREASE) {
        return 1;
    }

    /*
     * 4. if decrypt worked, de-compress cleartext to make up real inner CH
     */
    s->ext.encoded_innerch=clear;
    s->ext.encoded_innerch_len=clearlen;
    if (ech_decode_inner(&s->ssl,ch,ch_len,startofexts)!=1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ech_pbuf("Inner CH (decoded)",s->ext.innerch,s->ext.innerch_len);
    /*
     * The +4 below is because tls_process_client_hello doesn't
     * want to be given the message type & length, so the buffer should
     * start with the version octets (0x03 0x03)
     */
    if (PACKET_buf_init(newpkt,s->ext.innerch+4,s->ext.innerch_len-4)!=1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    return(1);
err:

    if (extval!=NULL) {
        ECH_ENCCH_free(extval);
        OPENSSL_free(extval);
        extval=NULL;
    }
    return(0);
}

/*
 * @brief API to set a preferred HPKE suite to use when GREASEing
 *
 * @param ssl is the SSL session
 * @param suite is the relevant suite string
 * @return 1 for success, other otherwise
 */
int SSL_ech_set_grease_suite(SSL *ssl, const char* suite)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (!s || !suite) return 0;
    /* Just stash the value for now and interpret when/if we do GREASE */
    if (s->ext.ech_grease_suite) OPENSSL_free(s->ext.ech_grease_suite);
    s->ext.ech_grease_suite=OPENSSL_strdup(suite);
    return 1;
}

/*
 * @brief API to set a preferred ECH ext type to use when GREASEing
 *
 * @param s is the SSL session
 * @param type is the relevant type
 * @return 1 for success, other otherwise
 */
int SSL_ech_set_grease_type(SSL *s, uint16_t type)
{
    if (!s) return(0);
    /* Just stash the value for now and interpret when/if we do GREASE */
    if (type!=TLSEXT_TYPE_ech &&
        type!=TLSEXT_TYPE_ech13) {
        return(0);
    }
    s->ext.ech_attempted_type=type;
    return 1;
}


/*!
 * @brief API to load all the key files found in a directory
 *
 * @param ctx is an SSL_CTX
 * @param echdir is the directory name
 * @oaram number_loaded returns the number of key pairs successfully loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_readpemdir(SSL_CTX *ctx, const char *echdir, int *number_loaded)
{
    OPENSSL_DIR_CTX *d = NULL;
    const char *filename;
    if (!ctx || !echdir || !number_loaded) return(0);
    while ((filename = OPENSSL_DIR_read(&d, echdir))) {
        char echname[PATH_MAX];
        size_t nlen=0;
        int r;
        const char *last4=NULL;
        struct stat thestat;

        if (strlen(echdir) + strlen(filename) + 2 > sizeof(echname)) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,
                    "name too long: %s/%s - skipping it \r\n",echdir,filename);
            } OSSL_TRACE_END(TLS);
#endif
            continue;
        }
#ifdef OPENSSL_SYS_VMS
        r = BIO_snprintf(echname, sizeof(echname), "%s%s", echdir, filename);
#else
        r = BIO_snprintf(echname, sizeof(echname), "%s/%s", echdir, filename);
#endif
        if (r <= 0 || r >= (int)sizeof(echname)) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"name oddity: %s/%s - skipping it \r\n",
                        echdir,filename);
            } OSSL_TRACE_END(TLS);
#endif
            continue;
        }
        nlen=strlen(filename);
        if (nlen <= 4 ) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"name too short: %s/%s - skipping it \r\n",
                        echdir,filename);
            } OSSL_TRACE_END(TLS);
#endif
            continue;
        }
        last4=filename+nlen-4;
        if (strncmp(last4,".pem",4) && strncmp(last4,".ech",4)) {
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,
                    "name doesn't end in .pem: %s/%s - skipping it \r\n",
                    echdir,filename);
            } OSSL_TRACE_END(TLS);
#endif
            continue;
        }
        if (stat(echname,&thestat)==0) {
            if (SSL_CTX_ech_server_enable(ctx,echname)==1) {
                *number_loaded=*number_loaded+1;
#ifndef OPENSSL_NO_SSL_TRACE
            } else {
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out, "Failed to set ECT parameters for %s\n",
                            echname);
                } OSSL_TRACE_END(TLS);
#endif
            }
#ifndef OPENSSL_NO_SSL_TRACE
            OSSL_TRACE_BEGIN(TLS) {
                BIO_printf(trc_out,"Added %d-th ECH key pair from: %s\n",
                        *number_loaded,echname);
            } OSSL_TRACE_END(TLS);
#endif
        }
    }
    if (d)
        OPENSSL_DIR_end(&d);

    return 1;
}

/*
 * @brief provide a way to do raw ECH decryption for split-mode frontends
 *
 * Note that the outer_ch's length is inside the TLV data
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
 */
int SSL_CTX_ech_raw_decrypt(SSL_CTX *ctx,
                            unsigned char *outer_ch, size_t outer_len,
                            unsigned char *inner_ch, size_t *inner_len,
                            char **inner_sni, char **outer_sni,
                            int *decrypted_ok)
{
    SSL *s=NULL;
    PACKET pkt_outer;
    PACKET pkt_inner;
    unsigned char *inner_buf=NULL;
    size_t inner_buf_len=0;
    int rv=0;
    size_t startofsessid=0; /**< offset of session id within Ch */
    size_t startofexts=0; /**< offset of extensions within CH */
    size_t echoffset=0; /**< offset of start of ECH within CH */
    uint16_t echtype=TLSEXT_TYPE_ech_unknown; /**< type of ECH seen */
    size_t innersnioffset=0; /**< offset to SNI in inner */
    SSL_CONNECTION *sc = NULL;

    if (!ctx || !outer_ch || outer_len==0 || !inner_ch || !inner_len
                || !inner_sni || !outer_sni || !decrypted_ok) return 0;
    inner_buf_len=*inner_len;
    s=SSL_new(ctx);
    if (s==NULL) return 0;
    if (PACKET_buf_init(&pkt_outer,outer_ch+9,outer_len-9)!=1) goto err;
    inner_buf=OPENSSL_malloc(inner_buf_len);
    if (inner_buf==NULL) goto err;
    if (PACKET_buf_init(&pkt_inner,inner_buf,inner_buf_len)!=1) goto err;

    rv=ech_early_decrypt(s,&pkt_outer,&pkt_inner);
    if (rv!=1) goto err;

    sc = SSL_CONNECTION_FROM_SSL(s);
    if (sc == NULL) return 0;

    if (sc->ech && sc->ech->outer_name) *outer_sni=OPENSSL_strdup(sc->ech->outer_name);

    if (sc->ext.ech_success==0) {
        *decrypted_ok=0;
    } else {
        size_t ilen=pkt_inner.remaining;

        /* make sure there's space */
        if ((ilen+9)>inner_buf_len) goto err;

        /* Fix up header and length of inner CH */
        inner_ch[0]=0x16;
        inner_ch[1]=0x03;
        inner_ch[2]=0x01;
        inner_ch[3]=((ilen+4)>>8)&0xff;
        inner_ch[4]=(ilen+4)&0xff;
        inner_ch[5]=0x01;
        inner_ch[6]=(ilen>>16)&0xff;
        inner_ch[7]=(ilen>>8)&0xff;
        inner_ch[8]=ilen&0xff;
        memcpy(inner_ch+9,pkt_inner.curr,ilen);
        *inner_len=ilen+9;

        /* Grab the inner SNI (if it's there) */
        rv=ech_get_offsets(&pkt_inner,&startofsessid,&startofexts,
                &echoffset,&echtype,&innersnioffset);
        if (rv!=1) return(rv);
        if (innersnioffset>0) {
            PACKET isni;
            const unsigned char *isnibuf=&pkt_inner.curr[innersnioffset+4];
            size_t isnilen=pkt_inner.curr[innersnioffset+2]*256+
                           pkt_inner.curr[innersnioffset+3];
            if (PACKET_buf_init(&isni,isnibuf,isnilen)!=1) {
                SSLfatal(sc, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
            if (tls_parse_ctos_server_name(sc, &isni, 0, NULL, 0)!=1) {
                SSLfatal(sc, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
                goto err;
            }
            if (sc->ext.hostname) *inner_sni=OPENSSL_strdup(sc->ext.hostname);
        }

        /* Declare success to caller */
        *decrypted_ok=1;
    }
    if (s) SSL_free(s);
    if (inner_buf) OPENSSL_free(inner_buf);
    return 1;
err:
    if (s) SSL_free(s);
    if (inner_buf) OPENSSL_free(inner_buf);
    return 0;
}

/**
 * @brief set the ALPN values for the outer ClientHello
 *
 * @param s is the SSL_CTX
 * @param protos encodes the ALPN values
 * @param protos_len is the length of protos
 * @return 1 for success, error otherwise
 */
int SSL_CTX_ech_set_outer_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
                            const size_t protos_len)
{
    OPENSSL_free(ctx->ext.alpn_outer);
    ctx->ext.alpn_outer = OPENSSL_memdup(protos, protos_len);
    if (ctx->ext.alpn_outer == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        return 1;
    }
    ctx->ext.alpn_outer_len = protos_len;
    return 0;
}

/**
 * @brief set the ALPN values for the outer ClientHello
 *
 * @param ssl is the SSL session
 * @param protos encodes the ALPN values
 * @param protos_len is the length of protos
 * @return 1 for success, error otherwise
 */
int SSL_ech_set_outer_alpn_protos(SSL *ssl, const unsigned char *protos,
                        unsigned int protos_len)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    OPENSSL_free(s->ext.alpn_outer);
    s->ext.alpn_outer = OPENSSL_memdup(protos, protos_len);
    if (s->ext.alpn_outer == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        return 1;
    }
    s->ext.alpn_outer_len = protos_len;
    return 0;
}

/**
 * @brief provide access to a returned ECH value
 *
 * If we GREASEd, or tried and failed, and got an ECH in return
 * the application can access the ECHConfig returned via this
 * API.
 *
 * @param ssl is the SSL session
 * @param eclen is a pointer to the length of the ECHConfig (zero if none)
 * @param ec is a pointer to the ECHConfig
 * @return 1 for success, other othewise
 */
int SSL_ech_get_returned(SSL *ssl, size_t *eclen, const unsigned char **ec)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (!s || !eclen || !ec) return 0;
    if (s->ext.ech_returned) {
        *eclen=s->ext.ech_returned_len;
        *ec=s->ext.ech_returned;
    } else {
        *eclen=0;
        *ec=NULL;
    }
    return 1;
}

#endif
