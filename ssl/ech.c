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

#ifndef OPENSSL_NO_ECH

# include <openssl/ssl.h>
# include <openssl/ech.h>
# include "ssl_local.h"
# include "ech_local.h"
# include "statem/statem_local.h"
#include <openssl/rand.h>
#include <openssl/trace.h>

/*
 * Needed to use stat for file status below in ech_check_filenames
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
/*
 * For ossl_assert
 */
#include "internal/cryptlib.h"

/*
 * For raw attempt with hpke_expand
 */
#include <crypto/hpke.h>

/*
 * This is in ssl/statem/extensions.c - we'll try a call to that and
 * if it works, fix up some header file somwwhere
 */
extern int final_server_name(SSL *s, unsigned int context, int sent);

/*
 * This used be static inside ssl/statem/statem_clnt.c
 */
extern int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk,
                                    WPACKET *pkt);

/*
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 * 
 * This does the real work, can be called to add to a context or a connection
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param ekval is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @param echs is a pointer to an array of decoded SSL_ECH
 * @return is 1 for success, error otherwise
 */
static int local_ech_add( int ekfmt, size_t eklen, unsigned char *ekval, int *num_echs, SSL_ECH **echs);

/*
 * Yes, global vars! 
 * For decoding input strings with public keys (aka ECHConfig) we'll accept
 * semi-colon separated lists of strings via the API just in case that makes
 * sense.
 */

/* asci hex is easy:-) either case allowed*/
const char *AH_alphabet="0123456789ABCDEFabcdef;";
/* we actually add a semi-colon here as we accept multiple semi-colon separated values */
const char *B64_alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;";
/* telltale for HTTPSSVC in presentation format */
const char *httpssvc_telltale="echconfig=";

/*
 * Ancilliary definintions
 */

#define ECH_KEYPAIR_ERROR          0
#define ECH_KEYPAIR_NEW            1
#define ECH_KEYPAIR_UNMODIFIED     2
#define ECH_KEYPAIR_MODIFIED       3

/*
#define SSL_ECH_I_HATE_GREASE 0
#define SSL_ECH_SEND_NO_GREASE 1
#define SSL_ECH_SEND_GREASE 2
#define SSL_ECH_SEND_REAL 3
*/

#define SSL_ECH_GREASE_BUFSIZ 255

/**
 * Check if key pair needs to be (re-)loaded or not
 *
 * We go through the keys we have and see what we find
 *
 * @param ctx is the SSL server context
 * @param pemfname is the PEM key filename
 * @param index is the index if we find a match
 * @return zero for error, otherwise one of: ECH_KEYPAIR_UNMODIFIED ECH_KEYPAIR_MODIFIED ECH_KEYPAIR_NEW
 */
static int ech_check_filenames(SSL_CTX *ctx, const char *pemfname,int *index)
{
    struct stat pemstat;
    // if bad input, crap out
    if (ctx==NULL || pemfname==NULL || index==NULL) return(ECH_KEYPAIR_ERROR);
    // if we have none, then it is new
    if (ctx->ext.ech==NULL || ctx->ext.nechs==0) return(ECH_KEYPAIR_NEW);
    // if no file info, crap out
    if (stat(pemfname,&pemstat) < 0) return(ECH_KEYPAIR_ERROR);
    // check the time info - we're only gonna do 1s precision on purpose
#if defined(__APPLE__)
    time_t pemmod=pemtat.st_mtimespec.tv_sec;
#elif defined(OPENSSL_SYS_WINDOWS)
    time_t pemmod=pemtat.st_mtime;
#else
    time_t pemmod=pemstat.st_mtim.tv_sec;
#endif
    // now search list of existing key pairs to see if we have that one already
    int ind=0;
    size_t pemlen=strlen(pemfname);
    for(ind=0;ind!=ctx->ext.nechs;ind++) {
        if (ctx->ext.ech[ind].pemfname==NULL) return(ECH_KEYPAIR_ERROR);
        size_t llen=strlen(ctx->ext.ech[ind].pemfname);
        if (llen==pemlen && !strncmp(ctx->ext.ech[ind].pemfname,pemfname,pemlen)) {
            // matching files!
            if (ctx->ext.ech[ind].loadtime<pemmod) {
                // aha! load it up so
                *index=ind;
                return(ECH_KEYPAIR_MODIFIED);
            } else {
                // tell caller no need to bother
                *index=-1; // just in case:->
                return(ECH_KEYPAIR_UNMODIFIED);
            }
        }
    }
    *index=-1; // just in case:->
    return ECH_KEYPAIR_NEW;
}

/**
 * @brief Decode from TXT RR to binary buffer
 *
 * This is like ct_base64_decode from crypto/ct/ct_b64.c
 * but a) isn't static and b) is extended to allow a set of 
 * semi-colon separated strings as the input to handle
 * multivalued RRs.
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
    size_t inlen = strlen(in);
    int i=0;
    int outlen=0;
    unsigned char *outbuf = NULL;
    int overallfraglen=0;
    if (out == NULL) {
        return 0;
    }
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
    char *inp=in;
    unsigned char *outp=outbuf;
    while (overallfraglen<inlen) {
        /* find length of 1st b64 string */
        int ofraglen=0;
        int thisfraglen=strcspn(inp,sepstr);
        inp[thisfraglen]='\0';
        overallfraglen+=(thisfraglen+1);
        ofraglen = EVP_DecodeBlock(outp, (unsigned char *)inp, thisfraglen);
        if (ofraglen < 0) {
            goto err;
        }
        /* Subtract padding bytes from |outlen|.  Any more than 2 is malformed. */
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
 * @brief Read an ECHConfigs (better only have 1) and single private key from
 *
 * @param pemfile is the name of the file
 * @param ctx is the SSL context
 * @param sechs an (output) pointer to the SSL_ECH output
 * @return 1 for success, otherwise error
 */
static int ech_readpemfile(SSL_CTX *ctx, const char *pemfile, SSL_ECH **sechs)
{
    if (ctx==NULL || pemfile==NULL || sechs==NULL) return(0);
    /*
     * The file content should look as below. Note that as girhub barfs
     * if I provide an actual private key in PEM format, I've reversed
     * the string PRIVATE in the PEM header;-)
     *
     * -----BEGIN ETAVRIP KEY-----
     * MC4CAQAwBQYDK2VuBCIEIEiVgUq4FlrMNX3lH5osEm1yjqtVcQfeu3hY8VOFortE
     * -----END ETAVRIP KEY-----
     * -----BEGIN ECHCONFIG-----
     * AEP/CQBBAAtleGFtcGxlLmNvbQAkAB0AIF8i/TRompaA6Uoi1H3xqiqzq6IuUqFjT2GNT4wzWmF6ACAABAABAAEAAAAA
     * -----END ECHCONFIG-----
     */

    BIO *pem_in=NULL;
    unsigned char *inbuf=NULL;
    char *pname=NULL;
    char *pheader=NULL;
    unsigned char *pdata=NULL;
    long plen;
    EVP_PKEY *priv=NULL;

    /*
     * Now check and parse inputs
     */
    pem_in = BIO_new(BIO_s_file());
    if (pem_in==NULL) {
        goto err;
    }
    if (BIO_read_filename(pem_in,pemfile)<=0) {
        goto err;
    }
    unsigned char prbuf[HPKE_MAXSIZE];
    size_t prbuf_len=HPKE_MAXSIZE;
    if (PEM_read_bio(pem_in,&pname,&pheader,&pdata,&plen)<=0) {
        goto err;
    }
    if (!pheader) {
        goto err;
    }
    if (strncmp(PEM_STRING_ECPRIVATEKEY,pheader,strlen(pheader))) {
        goto err;
    }
    prbuf_len=plen;
    memcpy(prbuf,pdata,plen);

    if (pname!=NULL) { OPENSSL_free(pname);  pname=NULL; }
    if (pheader!=NULL) { OPENSSL_free(pheader);  pheader=NULL;}
    if (pname!=NULL) { OPENSSL_free(pname);  pname=NULL;}
    if (pdata!=NULL) { OPENSSL_free(pdata);  pdata=NULL;}

    inbuf=OPENSSL_malloc(ECH_MAX_ECHCONFIG_LEN);
    if (inbuf==NULL) {
        goto err;
    }
    if (PEM_read_bio(pem_in,&pname,&pheader,&pdata,&plen)<=0) {
        goto err;
    }
    if (!pheader) {
        goto err;
    }
    if (strncmp(PEM_STRING_ECHCONFIG,pheader,strlen(pheader))) {
        goto err;
    }
    OPENSSL_free(pheader); pheader=NULL;
    if (pname) {
        OPENSSL_free(pname);  pname=NULL;
    }
    if (plen>=ECH_MAX_ECHCONFIG_LEN) {
        goto err;
    }
    BIO_free(pem_in);
    pem_in=NULL;

    /*
     * Now decode that ECHConfigs
     */
    int num_echs=0;
    int rv=local_ech_add(ECH_FMT_GUESS,plen,pdata,&num_echs,sechs);
    if (rv!=1) {
        goto err;
    }

    /*
     * Map the prbuf to an EVP_PKEY
     * We only support one private-key/ECHConfig pair per file and they
     * need to match for now.
     */
    if (num_echs>1) {
        goto err;
    }
    SSL_ECH *se=*sechs;
    if (se==NULL) {
        goto err;
    }
    if (se->cfg->nrecs!=1) {
        goto err;
    }
    unsigned int kem_id=se->cfg->recs[0].kem_id;
    if (hpke_prbuf2evp(kem_id,prbuf,prbuf_len,NULL,0,&priv)!=1) {
        goto err;
    }
    if (!priv) {
        goto err;
    }
    
    (*sechs)->pemfname=OPENSSL_strdup(pemfile);
    (*sechs)->loadtime=time(0);
    (*sechs)->keyshare=priv;
    if (inbuf!=NULL) OPENSSL_free(inbuf);
    if (pheader!=NULL) OPENSSL_free(pheader); 
    if (pname!=NULL) OPENSSL_free(pname); 
    if (pdata!=NULL) OPENSSL_free(pdata); 

    return(1);

err:
    if (priv!=NULL) EVP_PKEY_free(priv);
    if (inbuf!=NULL) OPENSSL_free(inbuf);
    if (prbuf!=NULL) OPENSSL_free(prbuf);
    if (pheader!=NULL) OPENSSL_free(pheader); 
    if (pname!=NULL) OPENSSL_free(pname); 
    if (pdata!=NULL) OPENSSL_free(pdata); 
    if (pem_in!=NULL) BIO_free(pem_in);
    if (*sechs) { SSL_ECH_free(*sechs); OPENSSL_free(*sechs); *sechs=NULL;}
    return(0);
}

/**
 * Try figure out ECHConfig encodng
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
    if (!guessedfmt || eklen <=0 || !rrval) {
        return(0);
    }

    /*
     * Try from most constrained to least in that order
     */
    if (strstr((char*)rrval,httpssvc_telltale)) {
        *guessedfmt=ECH_FMT_HTTPSSVC;
    } else if (eklen<=strspn((char*)rrval,AH_alphabet)) {
        *guessedfmt=ECH_FMT_ASCIIHEX;
    } else if (eklen<=strspn((char*)rrval,B64_alphabet)) {
        *guessedfmt=ECH_FMT_B64TXT;
    } else {
        // fallback - try binary
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
    if (!tbf) return;
    if (tbf->public_name) OPENSSL_free(tbf->public_name);
    if (tbf->pub) OPENSSL_free(tbf->pub);
    if (tbf->ciphersuites) OPENSSL_free(tbf->ciphersuites);
    if (tbf->exttypes) OPENSSL_free(tbf->exttypes);
    if (tbf->extlens) OPENSSL_free(tbf->extlens);
    if (tbf->config_id) OPENSSL_free(tbf->config_id);
    int i=0;
    for (i=0;i!=tbf->nexts;i++) {
        if (tbf->exts[i]) OPENSSL_free(tbf->exts[i]);
    }
    if (tbf->exts) OPENSSL_free(tbf->exts);
    memset(tbf,0,sizeof(ECHConfig));
    return;
}

/**
 * @brief Free an ECHConfigs structure's internals
 * @param tbf is the thing to be free'd
 */
void ECHConfigs_free(ECHConfigs *tbf)
{
    if (!tbf) return;
    if (tbf->encoded) OPENSSL_free(tbf->encoded);
    int i;
    for (i=0;i!=tbf->nrecs;i++) {
        ECHConfig_free(&tbf->recs[i]);
    }
    if (tbf->recs) OPENSSL_free(tbf->recs);
    memset(tbf,0,sizeof(ECHConfigs));
    return;
}

/*
 * Copy a field old->foo based on old->foo_len to new->foo
 * We allocate one extra octet in case the value is a
 * string and NUL that out.
 */
static void *ech_len_field_dup(void *old, unsigned int len)
{
    if (!old || len==0) return NULL;
    void *new=(void*)OPENSSL_malloc(len+1);
    if (!new) return 0;
    memcpy(new,old,len);
    memset(new+len,0,1);
    return new;
} 

#define ECHFDUP(__f__,__flen__) \
    if (old->__flen__!=0) { \
        new->__f__=ech_len_field_dup((void*)old->__f__,old->__flen__); \
        if (new->__f__==NULL) return 0; \
    }

/*
 * currently not needed - might want it later so keep for a bit
 * @brief free an ECH_ENCCH
 * @param tbf is a ptr to an SSL_ECH structure
static int ECH_ENCCH_dup(ECH_ENCCH *old, ECH_ENCCH *new)
{
    if (!old || !new) return 0;
    ECHFDUP(config_id,config_id_len);
    ECHFDUP(enc,enc_len);
    ECHFDUP(payload,payload_len);
    return 1;
}
 */

/*
 * @brief free an ECH_ENCCH
 * @param tbf is a ptr to an SSL_ECH structure
 */
void ECH_ENCCH_free(ECH_ENCCH *ev)
{
    if (!ev) return;
    if (ev->config_id!=NULL) OPENSSL_free(ev->config_id);
    if (ev->enc!=NULL) OPENSSL_free(ev->enc);
    if (ev->payload!=NULL) OPENSSL_free(ev->payload);
    return;
}

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

#define CFREE(__x__) if (tbf->__x__) { OPENSSL_free(tbf->__x__); tbf->__x__=NULL; }

    CFREE(inner_name);
    CFREE(outer_name);
    CFREE(pemfname);
    if (tbf->keyshare!=NULL) { EVP_PKEY_free(tbf->keyshare); tbf->keyshare=NULL; }
    CFREE(dns_alpns);

    memset(tbf,0,sizeof(SSL_ECH));
    return;
}

/*
 * @brief client-side calculation of config_id as per draft-09
 *
 * @param cfg is the ECHConfigs structure
 * @param cind is the index of the ECHConfig we want
 * @param olen is buffer size of out on inpuit and actual size on success 
 * @param out is a caller-allocated buffer for the result
 * @return 1 for success, error otherwise
 */
static int ech_calc_config_id(ECHConfigs *cfg, int cind)
{

    if (!cfg) return 0;
    if (cind>cfg->nrecs) return 0;

    ECHConfig *thecfg=&cfg->recs[cind];
    if (thecfg->config_id!=NULL) return 1; // already done

    size_t encodedechlen=thecfg->encoding_length;
    unsigned char *encodedech=thecfg->encoding_start;

#undef DOATEST
#ifdef DOATEST

    /*
     * Now do the extract/expand thing
     */
    // initial testcase thanks to Cloudflare providing the test vector privately
    unsigned char testech[]={
            0xfe,0x09,0x00,0x4f,0x00,0x13,0x63,0x6c,0x6f,0x75,0x64,0x66,0x6c,0x61,0x72,0x65,
            0x2d,0x65,0x73,0x6e,0x69,0x2e,0x63,0x6f,0x6d,0x00,0x20,0x45,0xcb,0xde,0xe7,0xaf,
            0x19,0x26,0x20,0x82,0xc9,0x92,0x6f,0xc2,0xb2,0x31,0xd0,0x52,0x28,0x48,0x24,0x22,
            0x87,0x3b,0x1e,0xe4,0x42,0x4c,0xdf,0xab,0xfd,0xf0,0x17,0x00,0x20,0x00,0x10,0x00,
            0x01,0x00,0x01,0x00,0x01,0x00,0x03,0x00,0x02,0x00,0x01,0x00,0x02,0x00,0x03,0x00,
            0x00,0x00,0x00};

    size_t testlen=sizeof(testech);

    encodedchlen=testlen;
    encodedech=testech;
#endif
    
    hpke_suite_t suite = HPKE_SUITE_DEFAULT;
    int mode5869=0;
    size_t s1len=HPKE_MAXSIZE;
    unsigned char s1[HPKE_MAXSIZE];
    size_t s2len=8;
    unsigned char s2[8];
    
    int erv=1;

    erv=hpke_extract(
        suite, mode5869,
        (const unsigned char*) "", 0, //const unsigned char *salt, const size_t saltlen,
        ECH_CONFIG_ID_STRING, strlen(ECH_CONFIG_ID_STRING),
        encodedech, encodedechlen, // unsigned char *ikm, const size_t ikmlen,
        s1, &s1len);
    if (erv!=1) return 0;

    /*
     * It was not at all clear from the spec that the same label
     * should be provided to both calls, but no need to fix as 
     * the calculated config_id idea will go away.
     */
    erv=hpke_expand(
        suite, mode5869, 
        s1, s1len, // unsigned char *prk, size_t prklen,
        ECH_CONFIG_ID_STRING, strlen(ECH_CONFIG_ID_STRING), // const unsigned char *label, const size_t labellen,
        NULL, 0, // unsigned char *info, size_t infolen,
        8, // uint32_t L,
        s2, &s2len); 
    if (erv!=1) return 0;

    thecfg->config_id=OPENSSL_malloc(s2len);
    if (!thecfg->config_id) {
        return 0;
    }
    thecfg->config_id_len=s2len;
    memcpy(thecfg->config_id,s2,thecfg->config_id_len);

    ech_pbuf("calculated config id input",thecfg->encoding_start,thecfg->encoding_length);
    ech_pbuf("calculated config id",s2,s2len);

    return 1;
}

/**
 * @brief Decode the first ECHConfigs from a binary buffer (and say how may octets not consumed)
 *
 * @param binbuf is the buffer with the encoding
 * @param binblen is the length of binbunf
 * @param leftover is the number of unused octets from the input
 * @return NULL on error, or a pointer to an ECHConfigs structure 
 */
static ECHConfigs *ECHConfigs_from_binary(unsigned char *binbuf, size_t binblen, int *leftover)
{
    ECHConfigs *er=NULL; ///< ECHConfigs record
    ECHConfig  *te=NULL; ///< Array of ECHConfig to be embedded in that
    int rind=0; ///< record index
    size_t remaining=0;

    /* sanity check: version + checksum + KeyShareEntry have to be there - min len >= 10 */
    if (binblen < ECH_MIN_ECHCONFIG_LEN) {
        goto err;
    }
    if (binblen >= ECH_MAX_ECHCONFIG_LEN) {
        goto err;
    }
    if (leftover==NULL) {
        goto err;
    }
    if (binbuf==NULL) {
        goto err;
    }

    PACKET pkt={binbuf,binblen};

    /* 
     * Overall length of this ECHConfigs (olen) still could be
     * less than the input buffer length, (binblen) if the caller has been
     * given a catenated set of binary buffers, which could happen
     * and which we will support
     */
    unsigned int olen=0;
    unsigned int ooffset=0;
    if (!PACKET_get_net_2(&pkt,&olen)) {
        goto err;
    }
    if (olen < ECH_MIN_ECHCONFIG_LEN || olen > (binblen-2)) {
        goto err;
    }

    int not_to_consume=binblen-olen;

    remaining=PACKET_remaining(&pkt);
    while (remaining>not_to_consume) {
    

        te=OPENSSL_realloc(te,(rind+1)*sizeof(ECHConfig));
        if (!te) {
            goto err;
        }
        ECHConfig *ec=&te[rind];
        memset(ec,0,sizeof(ECHConfig));

        ec->encoding_length=olen;
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
         * don't support.
         */
        unsigned int ech_content_length;
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
            case ECH_DRAFT_09_VERSION:
            case ECH_DRAFT_10_VERSION:
                break;
            default: // skip over those octets in case we get something we can handle later
                {
                    unsigned char *foo=OPENSSL_malloc(ech_content_length);
                    if (!foo) goto err;
                    if (!PACKET_copy_bytes(&pkt, foo, ech_content_length)) {
                        OPENSSL_free(foo);
                        goto err;
                    }
                    OPENSSL_free(foo);
                    continue;
                }
        }

        if (ec->version==ECH_DRAFT_10_VERSION) {
            /*
             * read config_id
             */
            ec->config_id_len=1; // a bit hard-coded but there's a chance it may change later
	        ec->config_id=OPENSSL_malloc(ec->config_id_len+1);
	        if (ec->config_id==NULL) {
	            goto err;
	        }
	        if (!PACKET_copy_bytes(&pkt,ec->config_id,ec->config_id_len)) {
	            goto err;
	        }

	        /*
	         * Kem ID
	         */
	        if (!PACKET_get_net_2(&pkt,&ec->kem_id)) {
	            goto err;
	        }

	        /* 
	         * read HPKE public key - just a blob
	         */
	        PACKET pub_pkt;
	        if (!PACKET_get_length_prefixed_2(&pkt, &pub_pkt)) {
	            goto err;
	        }
	        ec->pub_len=PACKET_remaining(&pub_pkt);
	        ec->pub=OPENSSL_malloc(ec->pub_len);
	        if (ec->pub==NULL) {
	            goto err;
	        }
	        PACKET_copy_bytes(&pub_pkt,ec->pub,ec->pub_len);

		    /*
		     * List of ciphersuites - 2 byte len + 2 bytes per ciphersuite
		     * Code here inspired by ssl/ssl_lib.c:bytes_to_cipher_list
		     */
		    PACKET cipher_suites;
		    if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites)) {
		        goto err;
		    }
		    int suiteoctets=PACKET_remaining(&cipher_suites);
		    if (suiteoctets<=0 || (suiteoctets % 1)) {
		        goto err;
		    }
		    ec->nsuites=suiteoctets/ECH_CIPHER_LEN;
		    ec->ciphersuites=OPENSSL_malloc(ec->nsuites*sizeof(ech_ciphersuite_t));
		    if (ec->ciphersuites==NULL) {
		        goto err;
		    }
	        unsigned char cipher[ECH_CIPHER_LEN];
	        int ci=0;
	        while (PACKET_copy_bytes(&cipher_suites, cipher, ECH_CIPHER_LEN)) {
	            memcpy(ec->ciphersuites[ci++],cipher,ECH_CIPHER_LEN);
	        }
	        if (PACKET_remaining(&cipher_suites) > 0) {
	            goto err;
	        }
	        /*
	         * Maximum name length
	         */
	        if (!PACKET_get_net_2(&pkt,&ec->maximum_name_length)) {
	            goto err;
	        }

	        /* 
	         * read public_name 
	         */
	        PACKET public_name_pkt;
	        if (!PACKET_get_length_prefixed_2(&pkt, &public_name_pkt)) {
	            goto err;
	        }
	        ec->public_name_len=PACKET_remaining(&public_name_pkt);
	        if (ec->public_name_len<=1||ec->public_name_len>TLSEXT_MAXLEN_host_name) {
	            goto err;
	        }
	        ec->public_name=OPENSSL_malloc(ec->public_name_len+1);
	        if (ec->public_name==NULL) {
	            goto err;
	        }
	        PACKET_copy_bytes(&public_name_pkt,ec->public_name,ec->public_name_len);
	        ec->public_name[ec->public_name_len]='\0';

	        /*
	         * Extensions: we'll just store 'em for now and try parse any
	         * we understand a little later
	         */
	        PACKET exts;
	        if (!PACKET_get_length_prefixed_2(&pkt, &exts)) {
	            goto err;
	        }
	        while (PACKET_remaining(&exts) > 0) {
	            ec->nexts+=1;
	            /*
	             * a two-octet length prefixed list of:
	             * two octet extension type
	             * two octet extension length
	             * length octets
	             */
	            unsigned int exttype=0;
	            if (!PACKET_get_net_2(&exts,&exttype)) {
	                goto err;
	            }
	            unsigned int extlen=0;
	            if (extlen>=ECH_MAX_RRVALUE_LEN) {
	                goto err;
	            }
	            if (!PACKET_get_net_2(&exts,&extlen)) {
	                goto err;
	            }
	            unsigned char *extval=NULL;
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
	            unsigned int *tip=(unsigned int*)OPENSSL_realloc(ec->exttypes,ec->nexts*sizeof(ec->exttypes[0]));
	            if (tip==NULL) {
	                if (extval!=NULL) OPENSSL_free(extval);
	                goto err;
	            }
	            ec->exttypes=tip;
	            ec->exttypes[ec->nexts-1]=exttype;
	            unsigned int *lip=(unsigned int*)OPENSSL_realloc(ec->extlens,ec->nexts*sizeof(ec->extlens[0]));
	            if (lip==NULL) {
	                if (extval!=NULL) OPENSSL_free(extval);
	                goto err;
	            }
	            ec->extlens=lip;
	            ec->extlens[ec->nexts-1]=extlen;
	            unsigned char **vip=(unsigned char**)OPENSSL_realloc(ec->exts,ec->nexts*sizeof(unsigned char*));
	            if (vip==NULL) {
	                if (extval!=NULL) OPENSSL_free(extval);
	                goto err;
	            }
	            ec->exts=vip;
	            ec->exts[ec->nexts-1]=extval;
	        }
	
        } // END of ECH_DRAFT_10_VERSION

        if (ec->version==ECH_DRAFT_09_VERSION) {
            /*
             * Set config_id to zero - value will be calculated later
             */
            ec->config_id_len=0;
            ec->config_id=NULL;

	        /* 
	         * read public_name 
	         */
	        PACKET public_name_pkt;
	        if (!PACKET_get_length_prefixed_2(&pkt, &public_name_pkt)) {
	            goto err;
	        }
	        ec->public_name_len=PACKET_remaining(&public_name_pkt);
	        if (ec->public_name_len<=1||ec->public_name_len>TLSEXT_MAXLEN_host_name) {
	            goto err;
	        }
	        ec->public_name=OPENSSL_malloc(ec->public_name_len+1);
	        if (ec->public_name==NULL) {
	            goto err;
	        }
	        PACKET_copy_bytes(&public_name_pkt,ec->public_name,ec->public_name_len);
	        ec->public_name[ec->public_name_len]='\0';
	        /* 
	         * read HPKE public key - just a blob
	         */
	        PACKET pub_pkt;
	        if (!PACKET_get_length_prefixed_2(&pkt, &pub_pkt)) {
	            goto err;
	        }
	        ec->pub_len=PACKET_remaining(&pub_pkt);
	        ec->pub=OPENSSL_malloc(ec->pub_len);
	        if (ec->pub==NULL) {
	            goto err;
	        }
	        PACKET_copy_bytes(&pub_pkt,ec->pub,ec->pub_len);
	        /*
	         * Kem ID
	         */
	        if (!PACKET_get_net_2(&pkt,&ec->kem_id)) {
	            goto err;
	        }
		
		    /*
		     * List of ciphersuites - 2 byte len + 2 bytes per ciphersuite
		     * Code here inspired by ssl/ssl_lib.c:bytes_to_cipher_list
		     */
		    PACKET cipher_suites;
		    if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites)) {
		        goto err;
		    }
		    int suiteoctets=PACKET_remaining(&cipher_suites);
		    if (suiteoctets<=0 || (suiteoctets % 1)) {
		        goto err;
		    }
		    ec->nsuites=suiteoctets/ECH_CIPHER_LEN;
		    ec->ciphersuites=OPENSSL_malloc(ec->nsuites*sizeof(ech_ciphersuite_t));
		    if (ec->ciphersuites==NULL) {
		        goto err;
		    }
	        unsigned char cipher[ECH_CIPHER_LEN];
	        int ci=0;
	        while (PACKET_copy_bytes(&cipher_suites, cipher, ECH_CIPHER_LEN)) {
	            memcpy(ec->ciphersuites[ci++],cipher,ECH_CIPHER_LEN);
	        }
	        if (PACKET_remaining(&cipher_suites) > 0) {
	            goto err;
	        }
	        /*
	         * Maximum name length
	         */
	        if (!PACKET_get_net_2(&pkt,&ec->maximum_name_length)) {
	            goto err;
	        }
	        /*
	         * Extensions: we'll just store 'em for now and try parse any
	         * we understand a little later
	         */
	        PACKET exts;
	        if (!PACKET_get_length_prefixed_2(&pkt, &exts)) {
	            goto err;
	        }
	        while (PACKET_remaining(&exts) > 0) {
	            ec->nexts+=1;
	            /*
	             * a two-octet length prefixed list of:
	             * two octet extension type
	             * two octet extension length
	             * length octets
	             */
	            unsigned int exttype=0;
	            if (!PACKET_get_net_2(&exts,&exttype)) {
	                goto err;
	            }
	            unsigned int extlen=0;
	            if (extlen>=ECH_MAX_RRVALUE_LEN) {
	                goto err;
	            }
	            if (!PACKET_get_net_2(&exts,&extlen)) {
	                goto err;
	            }
	            unsigned char *extval=NULL;
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
	            unsigned int *tip=(unsigned int*)OPENSSL_realloc(ec->exttypes,ec->nexts*sizeof(ec->exttypes[0]));
	            if (tip==NULL) {
	                if (extval!=NULL) OPENSSL_free(extval);
	                goto err;
	            }
	            ec->exttypes=tip;
	            ec->exttypes[ec->nexts-1]=exttype;
	            unsigned int *lip=(unsigned int*)OPENSSL_realloc(ec->extlens,ec->nexts*sizeof(ec->extlens[0]));
	            if (lip==NULL) {
	                if (extval!=NULL) OPENSSL_free(extval);
	                goto err;
	            }
	            ec->extlens=lip;
	            ec->extlens[ec->nexts-1]=extlen;
	            unsigned char **vip=(unsigned char**)OPENSSL_realloc(ec->exts,ec->nexts*sizeof(unsigned char*));
	            if (vip==NULL) {
	                if (extval!=NULL) OPENSSL_free(extval);
	                goto err;
	            }
	            ec->exts=vip;
	            ec->exts[ec->nexts-1]=extval;
	        }
	
        } // END of ECH_DRAFT_09_VERSION

        rind++;
        remaining=PACKET_remaining(&pkt);
    }

    int lleftover=PACKET_remaining(&pkt);
    if (lleftover<0 || lleftover>binblen) {
        goto err;
    }

    /*
     * Success - make up return value
     */
    *leftover=lleftover;
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

    /*
     * Any additional checks/work to do
     * For now, only draft-09 config id
     */
    for (rind=0;rind!=er->nrecs;rind++) {
        if (er->recs[rind].version==ECH_DRAFT_09_VERSION) {
            /*
             * Caclculate config_id values - draft-09 only!!!
             */
            if (ech_calc_config_id(er,rind)!=1) {
                goto err;
            }
        }
    }

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
 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 * 
 * This does the real work, can be called to add to a context or a connection
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
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
    if (eklen==0 || !ekval || !num_echs) {
        SSLerr(SSL_F_SSL_ECH_ADD, SSL_R_BAD_VALUE);
        return(0);
    }
    if (eklen>=ECH_MAX_RRVALUE_LEN) {
        SSLerr(SSL_F_SSL_ECH_ADD, SSL_R_BAD_VALUE);
        return(0);
    }
    switch (ekfmt) {
        case ECH_FMT_GUESS:
            rv=ech_guess_fmt(eklen,ekval,&detfmt);
            if (rv==0)  {
                SSLerr(SSL_F_SSL_ECH_ADD, SSL_R_BAD_VALUE);
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
    unsigned char *outbuf = NULL;   /* a binary representation of a sequence of ECHConfigs */
    size_t declen=0;                /* length of the above */
    char *ekcpy=(char*)ekval;
    if (detfmt==ECH_FMT_HTTPSSVC) {
        ekcpy=strstr((char*)ekval,httpssvc_telltale);
        if (ekcpy==NULL) {
            SSLerr(SSL_F_SSL_ECH_ADD, SSL_R_BAD_VALUE);
            return(rv);
        }
        /* point ekcpy at b64 encoded value */
        if (strlen(ekcpy)<=strlen(httpssvc_telltale)) {
            SSLerr(SSL_F_SSL_ECH_ADD, SSL_R_BAD_VALUE);
            return(rv);
        }
        ekcpy+=strlen(httpssvc_telltale);
        detfmt=ECH_FMT_B64TXT; /* tee up next step */
    }
    if (detfmt==ECH_FMT_B64TXT) {
        /* need an int to get -1 return for failure case */
        int tdeclen = ech_base64_decode(ekcpy, &outbuf);
        if (tdeclen < 0) {
            SSLerr(SSL_F_SSL_ECH_ADD, SSL_R_BAD_VALUE);
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
     * Now try decode each binary encoding if we can
     */
    int done=0;
    unsigned char *outp=outbuf;
    int oleftover=declen;
    int nlens=0;
    SSL_ECH *retechs=NULL;
    SSL_ECH *newech=NULL;
    while (!done) {
        nlens+=1;
        SSL_ECH *ts=OPENSSL_realloc(retechs,nlens*sizeof(SSL_ECH));
        if (!ts) {
            goto err;
        }
        retechs=ts;
        newech=&retechs[nlens-1];
        memset(newech,0,sizeof(SSL_ECH));
    
        int leftover=oleftover;
        ECHConfigs *er=ECHConfigs_from_binary(outp,oleftover,&leftover);
        if (er==NULL) {
            goto err;
        }
        newech->cfg=er;
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
 * @brief decode the DNS name in a binary RData
 *
 * Encoding as defined in https://tools.ietf.org/html/rfc1035#section-3.1
 *
 * @param buf points to the buffer (in/out)
 * @param remaining points to the remaining buffer length (in/out)
 * @param dnsname returns the string form name on success
 * @return is 1 for success, error otherwise
 */
static int local_decode_rdata_name(unsigned char **buf,size_t *remaining,char **dnsname)
{
    if (!buf) return(0);
    if (!remaining) return(0);
    if (!dnsname) return(0);
    unsigned char *cp=*buf;
    size_t rem=*remaining;
    char *thename=NULL,*tp=NULL;
    unsigned char clen=0; /* chunk len */

    thename=OPENSSL_malloc(ECH_MAX_DNSNAME);
    if (thename==NULL) {
        return(0);
    }
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
        if (clen>rem) return(1);
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
int SSL_ech_add(
        SSL *con, 
        int ekfmt, 
        size_t eklen, 
        char *ekval, 
        int *num_echs)
{

    /*
     * Sanity checks on inputs
     */
    if (!con) {
        SSLerr(SSL_F_SSL_ECH_ADD, SSL_R_BAD_VALUE);
        return(0);
    }
    SSL_ECH *echs=NULL;
    int rv=local_ech_add(ekfmt,eklen,(unsigned char*)ekval,num_echs,&echs);
    if (rv!=1) {
        return(0);
    }
    con->ech=echs;
    con->nechs=*num_echs;
    return(1);

}

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
int SSL_CTX_ech_add(SSL_CTX *ctx, short ekfmt, size_t eklen, char *ekval, int *num_echs)
{
    /*
     * Sanity checks on inputs
     */
    if (!ctx) {
        SSLerr(SSL_F_SSL_CTX_ECH_ADD, SSL_R_BAD_VALUE);
        return(0);
    }
    SSL_ECH *echs=NULL;
    int rv=local_ech_add(ekfmt,eklen,(unsigned char*)ekval,num_echs,&echs);
    if (rv!=1) {
        SSLerr(SSL_F_SSL_CTX_ECH_ADD, SSL_R_BAD_VALUE);
        return(0);
    }
    ctx->ext.ech=echs;
    ctx->ext.nechs=*num_echs;
    return(1);
}

/**
 * @brief Try turn on ECH for an (upcoming) TLS session on a client
 * 
 * @param s is the SSL context
 * @param inner_name is the (to be) hidden service name
 * @param outer_name is the cleartext SNI name to use
 * @return 1 for success, error otherwise
 * 
 */
int SSL_ech_server_name(SSL *s, const char *inner_name, const char *outer_name)
{
    if (s==NULL) return(0);
    if (s->ech==NULL) return(0);
    if (inner_name==NULL) return(0);
    if (s->ech->inner_name!=NULL) OPENSSL_free(s->ech->inner_name);
    s->ech->inner_name=OPENSSL_strdup(inner_name);
    if (s->ech->outer_name!=NULL) OPENSSL_free(s->ech->outer_name);
    if (outer_name!=NULL) s->ech->outer_name=OPENSSL_strdup(outer_name);
    else s->ech->outer_name=NULL;

    s->ext.ech_attempted=1; 

    return 1;
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
 * @param in is the SSL session
 * @param out is the returned externally visible detailed form of the SSL_ECH structure
 * @param nindices is an output saying how many indices are in the ECH_DIFF structure 
 * @return 1 for success, error otherwise
 */
int SSL_ech_query(SSL *in, ECH_DIFF **out, int *nindices)
{
    return 1;
}

/** 
 * @brief free up memory for an ECH_DIFF
 *
 * @param in is the structure to free up
 * @param size says how many indices are in in
 */
void SSL_ECH_DIFF_free(ECH_DIFF *in, int size)
{
    return;
}

/**
 * @brief utility fnc for application that wants to print an ECH_DIFF
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param se is a pointer to an ECH_DIFF struture
 * @param count is the number of elements in se
 * @return 1 for success, error othewise
 */
int SSL_ECH_DIFF_print(BIO* out, ECH_DIFF *se, int count)
{
    return 1;
}

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
int SSL_ech_reduce(SSL *in, int index)
{
    return 1;
}

/**
 * Report on the number of ECH key RRs currently loaded
 *
 * @param s is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_key_status(SSL_CTX *s, int *numkeys)
{
    return 1;
}

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
int SSL_CTX_ech_server_flush_keys(SSL_CTX *s, int age)
{
    return 1;
}

/**
 * Turn on ECH server-side
 *
 * When this works, the server will decrypt any ECH seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 *
 * @param ctx is the SSL connection (can be NULL)
 * @param pemfile has the relevant ECHConfig(s) and private key in PEM format
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_enable(SSL_CTX *ctx, const char *pemfile)
{
    if (ctx==NULL || pemfile==NULL) {
        return(0);
    }

    /*
     * Check if we already loaded that one etc.
     */
    int index=-1;
    int fnamestat=ech_check_filenames(ctx,pemfile,&index);
    switch (fnamestat) {
        case ECH_KEYPAIR_UNMODIFIED:
            // nothing to do
            return(1);
        case ECH_KEYPAIR_ERROR:
            return(0);
    }

    /*
     * Load up the file content
     */
    SSL_ECH *sechs=NULL;
    int rv=ech_readpemfile(ctx,pemfile,&sechs);
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
        if (index<0 || index >=ctx->ext.nechs) {
            SSL_ECH_free(sechs);
            OPENSSL_free(sechs);
            return(0);
        }
        SSL_ECH *curr_ec=&ctx->ext.ech[index];
        SSL_ECH_free(curr_ec);
        memset(curr_ec,0,sizeof(SSL_ECH));
        *curr_ec=*sechs; // struct copy
        OPENSSL_free(sechs);
        return(1);
    } 
    if (fnamestat==ECH_KEYPAIR_NEW) {
        SSL_ECH *re_ec=OPENSSL_realloc(ctx->ext.ech,(ctx->ext.nechs+1)*sizeof(SSL_ECH));
        if (re_ec==NULL) {
            SSL_ECH_free(sechs);
            OPENSSL_free(sechs);
            return(0);
        }
        ctx->ext.ech=re_ec;
        SSL_ECH *new_ec=&ctx->ext.ech[ctx->ext.nechs];
        memset(new_ec,0,sizeof(SSL_ECH));
        *new_ec=*sechs;
        ctx->ext.nechs++;
        OPENSSL_free(sechs);
        return(1);
    } 

    return 0;
}

/** 
 * Print the content of an SSL_ECH
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param con is an SSL session strucutre
 * @param selector allows for picking all (ECH_SELECT_ALL==-1) or just one of the RR values in orig
 * @return 1 for success, anything else for failure
 * 
 */
int SSL_ech_print(BIO* out, SSL *s, int selector)
{
    /*
     * Ignore details for now and just print state
     */
    BIO_printf(out,"*** SSL_ech_print ***\n");
    BIO_printf(out,"s=%p\n",s);
    BIO_printf(out,"inner_s=%p\n",s->ext.inner_s);
    BIO_printf(out,"outer_s=%p\n",s->ext.outer_s);
    BIO_printf(out,"ech_attempted=%d\n",s->ext.ech_attempted);
    BIO_printf(out,"ech_done=%d\n",s->ext.ech_done);
    BIO_printf(out,"ech_grease=%d\n",s->ext.ech_grease);
    BIO_printf(out,"ech_success=%d\n",s->ext.ech_success);
    BIO_printf(out,"*** SSL_ech_print ***\n");


    return 1;
}

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
int SSL_ech_get_status(SSL *s, char **inner_sni, char **outer_sni)
{
    if (s==NULL || outer_sni==NULL || inner_sni==NULL) {
        return SSL_ECH_STATUS_BAD_CALL;
    }
    *outer_sni=NULL;
    *inner_sni=NULL;

    /*
     * set vars - note we may be pointing to NULL which is fine
     */
    char *sinner=NULL;
    if (s->ext.inner_s!=NULL) sinner=s->ext.inner_s->ext.hostname;
    else sinner=s->ext.hostname;
    char *souter=NULL;
    if (s->ext.outer_s!=NULL) souter=s->ext.outer_s->ext.hostname;
    else souter=s->ext.hostname;

    if (s->ech!=NULL && s->ext.ech_attempted==1) {

        long vr=X509_V_OK;
        vr=SSL_get_verify_result(s);
        *inner_sni=sinner;
        *outer_sni=souter;
        if (s->ext.ech_success==1) {
            if (vr == X509_V_OK ) {
                return SSL_ECH_STATUS_SUCCESS;
            } else {
                return SSL_ECH_STATUS_BAD_NAME;
            }
        } else {
            return SSL_ECH_STATUS_FAILED;
        }
    } else if (s->ext.ech_grease==ECH_IS_GREASE) {
        return SSL_ECH_STATUS_GREASE;
    } 
    return SSL_ECH_STATUS_NOT_TRIED;
}

/** 
 * @brief Representation of what goes in DNS
typedef struct ech_config_st {
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
} ECHConfig;

typedef struct ech_configs_st {
    unsigned int encoded_len; ///< length of overall encoded content
    unsigned char *encoded; ///< overall encoded content
    int nrecs; ///< Number of records 
    ECHConfig *recs; ///< array of individual records
} ECHConfigs;
*/

static int ECHConfig_dup(ECHConfig *old, ECHConfig *new)
{
    if (!new || !old) return 0;
    *new=*old; // shallow copy, followed by deep copies
    ECHFDUP(pub,pub_len);
    ECHFDUP(public_name,public_name_len);
    ECHFDUP(config_id,config_id_len);
    if (old->ciphersuites) {
        new->ciphersuites=OPENSSL_malloc(old->nsuites*sizeof(ech_ciphersuite_t));
        if (!new->ciphersuites) return(0);
        memcpy(new->ciphersuites,old->ciphersuites,old->nsuites*sizeof(ech_ciphersuite_t));
    }
    // TODO: more to come

    return 1;
}

static int ECHConfigs_dup(ECHConfigs *old, ECHConfigs *new)
{
    if (!new || !old) return 0;
    if (old->encoded_len!=0) {
        if (old->encoded_len!=0) {
            new->encoded=ech_len_field_dup((void*)old->encoded,old->encoded_len);
            if (new->encoded==NULL) return 0;
        }
        new->encoded_len=old->encoded_len;
    }
    new->recs=OPENSSL_malloc(old->nrecs*sizeof(ECHConfig)); 
    if (!new->recs) return(0);
    new->nrecs=old->nrecs;
    memset(new->recs,0,old->nrecs*sizeof(ECHConfig)); 
    int i=0;
    for (i=0;i!=old->nrecs;i++) {
        if (ECHConfig_dup(&old->recs[i],&new->recs[i])!=1) return(0);
    }
    return(1);
}

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
SSL_ECH* SSL_ECH_dup(SSL_ECH* orig, size_t nech, int selector)
{
    SSL_ECH *new_se=NULL;
    if ((selector != ECH_SELECT_ALL) && selector<0) return(0);
    int min_ind=0;
    int max_ind=nech;
    int i=0;

    if (selector!=ECH_SELECT_ALL) {
        if (selector>=nech) goto err;
        min_ind=selector;
        max_ind=selector+1;
    }
    new_se=OPENSSL_malloc((max_ind-min_ind)*sizeof(SSL_ECH));
    if (!new_se) goto err;
    memset(new_se,0,(max_ind-min_ind)*sizeof(SSL_ECH));

    for (i=min_ind;i!=max_ind;i++) {
        new_se[i]=orig[i]; // shallow
        new_se[i].cfg=OPENSSL_malloc(sizeof(ECHConfigs));
        if (new_se[i].cfg==NULL) goto err;
        if (ECHConfigs_dup(orig[i].cfg,new_se[i].cfg)!=1) goto err;
    }

    if (orig->inner_name!=NULL) {
        new_se->inner_name=OPENSSL_strdup(orig->inner_name);
    }
    if (orig->outer_name!=NULL) {
        new_se->outer_name=OPENSSL_strdup(orig->outer_name);
    }
    if (orig->pemfname!=NULL) {
        new_se->pemfname=OPENSSL_strdup(orig->pemfname);
    }
    if (orig->keyshare!=NULL) {
        new_se->keyshare=orig->keyshare;
        EVP_PKEY_up_ref(orig->keyshare);
    }
    if (orig->dns_alpns!=NULL) {
        new_se->dns_alpns=OPENSSL_strdup(orig->dns_alpns);
    }
    new_se->dns_no_def_alpn=orig->dns_no_def_alpn;

    return new_se;
err:
    if (new_se!=NULL) {
        SSL_ECH_free(new_se);
    }
    return NULL;
}

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
int SSL_CTX_svcb_add(SSL_CTX *ctx, short rrfmt, size_t rrlen, char *rrval, int *num_echs)
{
    /*
     * TODO: populate this and sort out the dup/free'ing so it works
     * and doesn't leak
     */
    return 0;
}

/**
 * @brief Decode/store SVCB/HTTPS RR value provided as (binary or ascii-hex encoded) 
 *
 * rrval may be the catenation of multiple encoded ECHConfigs.
 * We internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ECH_FMT_ASCII_HEX
 * Note that we "succeed" even if there is no ECHConfigs in the input - some
 * callers might download the RR from DNS and pass it here without looking 
 * inside, and there are valid uses of such RRs. The caller can check though
 * using the num_echs output.
 *
 * @param con is the SSL connection 
 * @param rrlen is the length of the rrval
 * @param rrval is the binary, base64 or ascii-hex encoded RData
 * @param num_echs says how many SSL_ECH structures are in the returned array
 * @return is 1 for success, error otherwise
 */
int SSL_svcb_add(SSL *con, int rrfmt, size_t rrlen, char *rrval, int *num_echs)
{
    /*
     * Sanity checks on inputs
     */
    if (!con) {
        SSLerr(SSL_F_SSL_SVCB_ADD, SSL_R_BAD_VALUE);
        return(0);
    }
    SSL_ECH *echs=NULL;
    /*
     * Extract eklen,ekval from RR if possible
     */
    int detfmt=ECH_FMT_GUESS;
    int rv=0;
    size_t binlen=0; /* the RData */
    unsigned char *binbuf=NULL;
    size_t eklen=0; /* the ECHConfigs, within the above */
    unsigned char *ekval=NULL;

    if (rrfmt==ECH_FMT_ASCIIHEX) {
        detfmt=rrfmt;
    } else if (rrfmt==ECH_FMT_BIN) {
        detfmt=rrfmt;
    } else {
        rv=ech_guess_fmt(rrlen,(unsigned char*)rrval,&detfmt);
        if (rv==0)  {
            SSLerr(SSL_F_SSL_SVCB_ADD, SSL_R_BAD_VALUE);
            return(rv);
        }
    }
    if (detfmt==ECH_FMT_ASCIIHEX) {
        rv=hpke_ah_decode(rrlen,rrval,&binlen,&binbuf);
        if (rv==0) {
            SSLerr(SSL_F_SSL_SVCB_ADD, SSL_R_BAD_VALUE);
            return(rv);
        }
    }

    /*
     * Now we have a binary encoded RData so we'll skip the
     * name, and then walk through the SvcParamKey binary
     * codes 'till we find what we want
     */
    unsigned char *cp=binbuf;
    size_t remaining=binlen;
    char *dnsname=NULL;
    int no_def_alpn=0;
    /* skip 2 octet priority */
    if (remaining<=2) goto err;
    cp+=2; remaining-=2;
    rv=local_decode_rdata_name(&cp,&remaining,&dnsname);
    if (rv!=1) {
        SSLerr(SSL_F_SSL_SVCB_ADD, SSL_R_BAD_VALUE);
        return(0);
    }
    // skipping this, we can free it
    OPENSSL_free(dnsname);
    size_t alpn_len=0;
    unsigned char *alpn_val=NULL;
    short pcode=0;
    short plen=0;
    int done=0;
    while (!done && remaining>=4) {
        pcode=(*cp<<8)+(*(cp+1)); cp+=2;
        plen=(*cp<<8)+(*(cp+1)); cp+=2;
        remaining-=4;
        if (pcode==ECH_PCODE_ECH) {
            eklen=(size_t)plen;
            ekval=cp;
            done=1;
        }
        if (pcode==ECH_PCODE_ALPN) {
            alpn_len=(size_t)plen;
            alpn_val=cp;
        }
        if (pcode==ECH_PCODE_NO_DEF_ALPN) {
            no_def_alpn=1;
        }
        if (plen!=0 && plen <= remaining) {
            cp+=plen;
            remaining-=plen;
        }
    } 
    if (no_def_alpn==1) {
        printf("Got no-def-ALPN\n");
    }
    if (alpn_len>0 && alpn_val!=NULL) {
        size_t aid_len=0;
        char aid_buf[255];
        unsigned char *ap=alpn_val;
        int ind=0;
        while (((alpn_val+alpn_len)-ap)>0) {
            ind++;
            aid_len=*ap++;
            if (aid_len>0 && aid_len<255) {
                memcpy(aid_buf,ap,aid_len);
                aid_buf[aid_len]=0x00;
                ap+=aid_len;
            }        
        }
    }
    if (!done) {
        *num_echs=0;
        return(1);
    }

    /*
     * Deposit ECHConfigs that we found
     */
    rv=local_ech_add(ECH_FMT_BIN,eklen,ekval,num_echs,&echs);
    if (rv!=1) {
        SSLerr(SSL_F_SSL_SVCB_ADD, SSL_R_BAD_VALUE);
        return(0);
    } 

    if (detfmt==ECH_FMT_ASCIIHEX) {
        OPENSSL_free(binbuf);
    }
    
    /*
     * Whack in ALPN info to ECHs
     */
    for (int i=0;i!=*num_echs;i++) {
        echs[i].dns_no_def_alpn=no_def_alpn;
    }

    con->ech=echs;
    con->nechs=*num_echs;
    return(1);

err:
    if (detfmt==ECH_FMT_ASCIIHEX) {
        OPENSSL_free(binbuf);
    }
    return(0);

}

/* 
 * When doing ECH, this array specifies which inner CH extensions (if 
 * any) are to be "compressed" using the (ickky) outer extensions
 * trickery.
 * Basically, we store a 0 for "don't" and a 1 for "do" and the index
 * is the same as the index of the extension itself. 
 *
 * This is likely to disappear before submitting a PR to upstream. If
 * anyone else implements the outer extension stuff, then I'll need to
 * test it on the server-side, so I'll need to be able to do various
 * tests of correct (and incorrect!) uses of that. In reality, when
 * or if this feature reaches upstream, my guess is there'll not be 
 * a need for such configuration flexibility on the client side at 
 * all, and if any such compression is needed that can be hard-coded
 * into the extension-specific ctos functions, if it really saves 
 * useful space (could do if we don't break an MTU as a result) or
 * helps somehow with not standing out (if it makes a reach use of
 * ECH look more like GREASEd ones).
 *
 * As with ext_defs in extensions.c: NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the
 * indexes ( TLSEXT_IDX_* ) defined in ssl_local.h.
 *
 * Lotsa notes, eh - that's because I'm not sure this is sane:-)
 */
int ech_outer_config[]={
     /*TLSEXT_IDX_renegotiate */ 0,
     /*TLSEXT_IDX_server_name */ 0,
#define DOCOMPRESS
#ifdef DOCOMPRESS
     /*TLSEXT_IDX_max_fragment_length */ 1,
     /*TLSEXT_IDX_srp */ 1,
     /*TLSEXT_IDX_ec_point_formats */ 1,
     /*TLSEXT_IDX_supported_groups */ 1,
#else
     /*TLSEXT_IDX_max_fragment_length */ 0,
     /*TLSEXT_IDX_srp */ 0,
     /*TLSEXT_IDX_ec_point_formats */ 0,
     /*TLSEXT_IDX_supported_groups */ 0,
#endif
     /*TLSEXT_IDX_session_ticket */ 0,
     /*TLSEXT_IDX_status_request */ 0,
     /*TLSEXT_IDX_next_proto_neg */ 0,
     /*TLSEXT_IDX_application_layer_protocol_negotiation */ 0,
     /*TLSEXT_IDX_use_srtp */ 0,
     /*TLSEXT_IDX_encrypt_then_mac */ 0,
     /*TLSEXT_IDX_signed_certificate_timestamp */ 0,
     /*TLSEXT_IDX_extended_master_secret */ 0,
     /*TLSEXT_IDX_signature_algorithms_cert */ 0,
     /*TLSEXT_IDX_post_handshake_auth */ 0,
     /*TLSEXT_IDX_signature_algorithms */ 0,
     /*TLSEXT_IDX_supported_versions */ 0,
     /*TLSEXT_IDX_psk_kex_modes */ 0,
     /*TLSEXT_IDX_key_share */ 0,
     /*TLSEXT_IDX_cookie */ 0,
     /*TLSEXT_IDX_cryptopro_bug */ 0,
     /*TLSEXT_IDX_early_data */ 0,
     /*TLSEXT_IDX_certificate_authorities */ 0,
#ifndef OPENSSL_NO_ESNI
     /*TLSEXT_IDX_esni */ 0,
#endif
#ifndef OPENSSL_NO_ECH
     /*TLSEXT_IDX_ech */ 0,
     /*TLSEXT_IDX_outer_extensions */ 0,
#endif
     /*TLSEXT_IDX_padding */ 0,
     /*TLSEXT_IDX_psk */ 0,
    }; 

/* 
 * When doing ECH, this array specifies whether, when we're not
 * compressing, to re-use the inner value in the outer CH  ("0")
 * or whether to generate an independently new value for the
 * outer ("1")
 *
 * As above this is likely to disappear before submitting a PR to 
 * upstream. 
 *
 * As with ext_defs in extensions.c: NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the
 * indexes ( TLSEXT_IDX_* ) defined in ssl_local.h.
 */
int ech_outer_indep[]={
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
#ifndef OPENSSL_NO_ESNI
     /*TLSEXT_IDX_esni */ 0,
#endif
#ifndef OPENSSL_NO_ECH
     /*TLSEXT_IDX_ech */ 0,
     /*TLSEXT_IDX_outer_extensions */ 0,
#endif
     /*TLSEXT_IDX_padding */ 0,
     /*TLSEXT_IDX_psk */ 0,
}; 

/**
 * @brief repeat extension value from inner ch in outer ch and handle outer compression
 * @param s is the SSL session
 * @param pkt is the packet containing extensions
 * @return 0: error, 1: copied existing and done, 2: ignore existing
 */
int ech_same_ext(SSL *s, WPACKET* pkt)
{

#undef DUPEMALL
#ifdef DUPEMALL
    /*
     * Setting this means no compression at all.
     */
    return(ECH_SAME_EXT_CONTINUE);
#endif
    if (!s->ech) return(ECH_SAME_EXT_CONTINUE); // nothing to do
    if (s->ext.ch_depth==0) return(ECH_SAME_EXT_CONTINUE); // nothing to do for outer
    SSL *inner=s->ext.inner_s;
    int type=s->ext.etype;
    int nexts=sizeof(ech_outer_config)/sizeof(int);
    int tind=ech_map_ext_type_to_ind(type);
    if (tind==-1) return(ECH_SAME_EXT_ERR);
    if (tind>=nexts) return(ECH_SAME_EXT_ERR);

    /*
     * When doing the inner CH, just note what will later be
     * compressed, if we want to compress
     */
    if (s->ext.ch_depth==1 && !ech_outer_config[tind]) {
        return(ECH_SAME_EXT_CONTINUE);
    }
    if (s->ext.ch_depth==1 && ech_outer_config[tind]) {
        if (s->ext.n_outer_only>=ECH_OUTERS_MAX) {
	        return ECH_SAME_EXT_ERR;
        }
        s->ext.outer_only[s->ext.n_outer_only]=type;
        s->ext.n_outer_only++;
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Marking ext type %x for compression\n",s->ext.etype);
        } OSSL_TRACE_END(TLS);
        return(ECH_SAME_EXT_CONTINUE);
    }

    /* 
     * From here on we're in 2nd call, meaning the outer CH 
     */
    if (!inner->clienthello) return(ECH_SAME_EXT_ERR); 
    if (!pkt) return(ECH_SAME_EXT_ERR);
    if (ech_outer_indep[tind]) {
        return(ECH_SAME_EXT_CONTINUE);
    } else {

	    int ind=0;
	    RAW_EXTENSION *myext=NULL;
	    RAW_EXTENSION *raws=inner->clienthello->pre_proc_exts;
	    if (raws==NULL) {
	        return ECH_SAME_EXT_ERR;
	    }
	    size_t nraws=inner->clienthello->pre_proc_exts_len;
	    for (ind=0;ind!=nraws;ind++) {
	        if (raws[ind].type==type) {
	            myext=&raws[ind];
	            break;
	        }
	    }
	    if (myext==NULL) {
	        /*
	         * This one wasn't in inner, so don't send
	         */
	        return ECH_SAME_EXT_CONTINUE;
	    }
	    if (myext->data.curr!=NULL && myext->data.remaining>0) {
	        if (!WPACKET_put_bytes_u16(pkt, type)
	            || !WPACKET_sub_memcpy_u16(pkt, myext->data.curr, myext->data.remaining)) {
	            return ECH_SAME_EXT_ERR;
	        }
	    } else {
	        /*
	         * empty extension
	         */
	        if (!WPACKET_put_bytes_u16(pkt, type)
	                || !WPACKET_put_bytes_u16(pkt, 0)) {
	            return ECH_SAME_EXT_ERR;
	        }
	    }
        return(ECH_SAME_EXT_DONE);
    }
}

/**
 * @brief After "normal" 1st pass CH is done, fix encoding as needed
 *
 * This will make up the ClientHelloInner and EncodedClientHelloInner buffers
 *
 * @param s is the SSL session
 * @return 1 for success, error otherwise
 */
int ech_encode_inner(SSL *s)
{
    /*
     * So we'll try a sort-of decode of s->ech->innerch into
     * s->ech->encoded_innerch, modulo s->ech->outers
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
    if (s->ech==NULL) return(0);
    
    /*
     * Go over the extensions, and check if we should include
     * the value or if this one's compressed in the inner
     * This depends on us having made the call to process
     * client hello before.
     */
    unsigned char *innerch_full=NULL;
    WPACKET inner; ///< "fake" pkt for inner
    BUF_MEM *inner_mem=NULL;
    int mt=SSL3_MT_CLIENT_HELLO;
    if ((inner_mem = BUF_MEM_new()) == NULL) {
        goto err;
    }
    if (!BUF_MEM_grow(inner_mem, SSL3_RT_MAX_PLAIN_LENGTH)) {
        goto err;
    }
    if (!WPACKET_init(&inner,inner_mem)
                || !ssl_set_handshake_header(s, &inner, mt)) {
        goto err;
    }
    /*
     * Add ver/rnd/sess-id/suites to buffer
     */
    if (!WPACKET_put_bytes_u16(&inner, s->client_version)
            || !WPACKET_memcpy(&inner, s->s3.client_random, SSL3_RANDOM_SIZE)) {
        goto err;
    }
    /* 
     * Session ID - forced to zero in the encoded inner as we
     * gotta re-use the value from outer
     */
    if (!WPACKET_start_sub_packet_u8(&inner)
            || !WPACKET_close(&inner)) {
        return 0;
    }

    /* Ciphers supported */
    if (!WPACKET_start_sub_packet_u16(&inner)) {
        return 0;
    }
    if (!ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), &inner)) {
        return 0;
    }
    if (!WPACKET_close(&inner)) {
        return 0;
    }
    /* COMPRESSION */
    if (!WPACKET_start_sub_packet_u8(&inner)) {
        return 0;
    }
    /* Add the NULL compression method */
    if (!WPACKET_put_bytes_u8(&inner, 0) || !WPACKET_close(&inner)) {
        return 0;
    }
    /*
     * Now mess with extensions
     */
    if (!WPACKET_start_sub_packet_u16(&inner)) {
        return 0;
    }
    RAW_EXTENSION *raws=s->clienthello->pre_proc_exts;
    size_t nraws=s->clienthello->pre_proc_exts_len;
    int ind=0;
    int compression_done=0;
    for (ind=0;ind!=nraws;ind++) {
        int present=raws[ind].present;
        if (!present) continue;
        int tobecompressed=0;
        int ooi=0;
        for (ooi=0;!tobecompressed && ooi!=s->ext.n_outer_only;ooi++) {
            if (raws[ind].type==s->ext.outer_only[ooi]) {
                tobecompressed=1;
                OSSL_TRACE_BEGIN(TLS) {
                    BIO_printf(trc_out,"Going to compress something\n");
                } OSSL_TRACE_END(TLS);
            }
        }
        if (!compression_done && tobecompressed) {
            if (!WPACKET_put_bytes_u16(&inner, TLSEXT_TYPE_outer_extensions) ||
                !WPACKET_put_bytes_u16(&inner, 2*s->ext.n_outer_only+1)) {
                goto err;
            }
            if (!WPACKET_put_bytes_u8(&inner, 2*s->ext.n_outer_only)) {
                goto err;
            }
            int iind=0;
            for (iind=0;iind!=s->ext.n_outer_only;iind++) {
                if (!WPACKET_put_bytes_u16(&inner, s->ext.outer_only[iind])) {
                    goto err;
                }
            }
            compression_done=1;
        } 
        if (!tobecompressed) {
            if (raws[ind].data.curr!=NULL) {
                if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                    || !WPACKET_sub_memcpy_u16(&inner, raws[ind].data.curr, raws[ind].data.remaining)) {
                    goto err;
                }
            } else {
                /*
                * empty extension
                */
                if (!WPACKET_put_bytes_u16(&inner, raws[ind].type)
                        || !WPACKET_put_bytes_u16(&inner, 0)) {
                    goto err;
                }
            }
        }
    }
    /*
     * close the exts sub packet
     */
    if (!WPACKET_close(&inner))  {
        goto err;
    }
    /*
     * close the inner CH
     */
    if (!WPACKET_close(&inner))  {
        goto err;
    }
    /*
     * Set pointer/len for inner CH 
     */
    size_t innerinnerlen=0;
    if (!WPACKET_get_length(&inner, &innerinnerlen)) {
        goto err;
    }

    innerch_full=OPENSSL_malloc(innerinnerlen);
    if (!innerch_full) {
        goto err;
    }
    /*
     * Finally ditch the type and 3-octet length
     */
    memcpy(innerch_full,inner_mem->data+4,innerinnerlen-4);
    s->ext.encoded_innerch=innerch_full;
    s->ext.encoded_innerch_len=innerinnerlen-4;

    WPACKET_cleanup(&inner);
    if (inner_mem) BUF_MEM_free(inner_mem);
    inner_mem=NULL;
    return(1);
err:
    WPACKET_cleanup(&inner);
    if (inner_mem) BUF_MEM_free(inner_mem);
    return(0);
}

/**
 * @brief After "normal" 1st pass CH receipt (of outer) is done, fix encoding as needed
 *
 * This will produce the ClientHelloInner from the EncodedClientHelloInner, which
 * is the result of successful decryption 
 *
 * @param s is the SSL session
 * @return 1 for success, error otherwise
 */
int ech_decode_inner(SSL *s)
{

    /*
     * So we'll try a sort-of decode of outer->ext.innerch into
     * s->ext.encoded_innerch, modulo s->ext.outers
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
    if (s->ext.inner_s!=NULL) return(0);
    SSL *outer=s->ext.outer_s;
    if (outer==NULL) return(0);
    if (outer->ext.encoded_innerch==NULL) return(0);
    if (!outer->clienthello) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return(0);
    }
    if (!outer->clienthello->extensions.curr) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return(0);
    }

    /*
     * add bytes for session ID and it's length (1)
     * minus the length of an empty session ID (1)
     */
    size_t initial_decomp_len=outer->ext.encoded_innerch_len;
    unsigned char *initial_decomp=NULL;
    initial_decomp_len+=outer->tmp_session_id_len+1-1;
    initial_decomp=OPENSSL_malloc(initial_decomp_len);
    if (!initial_decomp) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return(0);
    }
    s->ext.innerch_len=initial_decomp_len;
    s->ext.innerch=initial_decomp;

    unsigned char *startofmessage=outer->ext.encoded_innerch;
    /*
     * Jump over the ciphersuites and (MUST be NULL) compression to
     * the start of extensions
     * We'll start genoffset at the end of the session ID, just
     * before the ciphersuites
     */
    size_t offset2sessid=2+32; 
    size_t genoffset=offset2sessid+1; // 1 is the length of the session id itself
    size_t suiteslen=startofmessage[genoffset]*256+startofmessage[genoffset+1];
    size_t startofexts=genoffset+outer->tmp_session_id_len+2+suiteslen + 2; // the last +2 for the NULL compression

    memcpy(initial_decomp,outer->ext.encoded_innerch,offset2sessid);
    initial_decomp[offset2sessid]=outer->tmp_session_id_len;
    memcpy(initial_decomp+offset2sessid+1,
                outer->tmp_session_id,
                outer->tmp_session_id_len);
    memcpy(initial_decomp+offset2sessid+1+outer->tmp_session_id_len,
                outer->ext.encoded_innerch+offset2sessid+1,
                outer->ext.encoded_innerch_len-offset2sessid-1);

    /*
     * Initial decode of inner
     */
    ech_pbuf("Inner CH (session-id-added but no decompression)",initial_decomp,initial_decomp_len);
    if (startofexts>initial_decomp_len) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Oops - exts out of bounds\n");
        } OSSL_TRACE_END(TLS);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        return(0);
    }
    ech_pbuf("start of exts",&initial_decomp[startofexts],initial_decomp_len-startofexts);

    /*
     * Now skip over exts until we do/don't see outers
     */
    int found=0;
    int remaining=initial_decomp[startofexts]*256+initial_decomp[startofexts+1];
    genoffset=startofexts+2; // 1st ext type, skip the overall exts len
    uint16_t etype;
    size_t elen;
    while (!found && remaining>0) {
        etype=initial_decomp[genoffset]*256+initial_decomp[genoffset+1];
        elen=initial_decomp[genoffset+2]*256+initial_decomp[genoffset+3];
        if (etype==TLSEXT_TYPE_outer_extensions) {
            found=1;
        } else {
            remaining-=(elen+4);
            genoffset+=(elen+4);
        }
    }
    if (found==0) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"We had no compression\n");
        } OSSL_TRACE_END(TLS);
        /*
         * We still need to add msg type & 3-octet length
         */
        unsigned char *final_decomp=NULL;
        size_t final_decomp_len=initial_decomp_len+4;
        final_decomp=OPENSSL_malloc(final_decomp_len);
        if (!final_decomp) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            return(0);
        }
        final_decomp[0]=0x01;
        final_decomp[1]=((initial_decomp_len)>>16)%256;
        final_decomp[2]=((initial_decomp_len)>>8)%256;
        final_decomp[3]=(initial_decomp_len)%256;
        memcpy(final_decomp+4,initial_decomp,initial_decomp_len);
        s->ext.innerch=final_decomp;
        s->ext.innerch_len=final_decomp_len;
        return(1);
    }

    /*
     * At this point, we're pointing at the outer extensions in the
     * encoded_innerch
     */
    int n_outers=elen/2;
    size_t tot_outer_lens=0; // total length of outers (incl. type+len+val)
    uint16_t outers[ECH_OUTERS_MAX];
    size_t outer_sizes[ECH_OUTERS_MAX];
    int outer_offsets[ECH_OUTERS_MAX];
    uint8_t slen=initial_decomp[genoffset+4]; // the unnecessary internal length
    if (!ossl_assert(n_outers==slen/2)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    const unsigned char *oval_buf=&initial_decomp[genoffset+5];

    if (n_outers<=0 || n_outers>ECH_OUTERS_MAX) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    int i=0;
    for (i=0;i!=n_outers;i++) {
        outers[i]=oval_buf[2*i]*256+oval_buf[2*i+1];
    }
    OSSL_TRACE_BEGIN(TLS) {
        BIO_printf(trc_out,"We have %d outers compressed\n",n_outers);
    } OSSL_TRACE_END(TLS);
    if (n_outers<=0 || n_outers > ECH_OUTERS_MAX ) {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"So no real compression (or too much!)\n");
        } OSSL_TRACE_END(TLS);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * Got through outer exts and mark what we need
     */
    int iind=0;
    const unsigned char *exts_start=outer->clienthello->extensions.curr;
    size_t exts_len=outer->clienthello->extensions.remaining;
    remaining=exts_len;
    const unsigned char *ep=exts_start;
    int found_outers=0;
    while (remaining>0) {
        etype=*ep*256+*(ep+1);
        elen=*(ep+2)*256+*(ep+3);
        for (iind=0;iind<n_outers;iind++) {
            if (etype==outers[iind]) {
                outer_sizes[iind]=elen;
                outer_offsets[iind]=ep-exts_start;
                tot_outer_lens+=(outer_sizes[iind]+4);
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
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"Error found outers (%d) not same as claimed (%d)\n",found_outers,n_outers);
        } OSSL_TRACE_END(TLS);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * Now almost-finally package up the lot
     */
    unsigned char *final_decomp=NULL;
    size_t final_decomp_len=0;

    final_decomp_len=
        4 + // the type and 3-octet length 
        genoffset + // the start of the CH up to the start of the outers ext
        tot_outer_lens + // the cumulative length of the extensions to splice in
        (initial_decomp_len-genoffset-(n_outers*2+5)); // the rest
    final_decomp=OPENSSL_malloc(final_decomp_len);
    if (final_decomp==NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    size_t offset=genoffset;
    final_decomp[0]=0x01;
    final_decomp[1]=((final_decomp_len-4)>>16)%256;
    final_decomp[2]=((final_decomp_len-4)>>8)%256;
    final_decomp[3]=(final_decomp_len-4)%256;
    memcpy(final_decomp+4,initial_decomp,offset);offset+=4;
    for (iind=0;iind!=n_outers;iind++) {
        int ooffset=outer_offsets[iind]+4;
        size_t osize=outer_sizes[iind];
        final_decomp[offset]=(outers[iind]/256)&0xff; offset++;
        final_decomp[offset]=(outers[iind]%256)&0xff; offset++;
        final_decomp[offset]=(osize/256)&0xff; offset++;
        final_decomp[offset]=(osize%256)&0xff; offset++;
        memcpy(final_decomp+offset,exts_start+ooffset,osize); offset+=osize;
    }
    memcpy(final_decomp+offset,
            initial_decomp+genoffset+5+2*n_outers,
            initial_decomp_len-genoffset-(n_outers*2+5)); 

    size_t outer_exts_len=5+2*n_outers;
    size_t initial_oolen=final_decomp[startofexts+4]*256+final_decomp[startofexts+5];

    // the added 4 is for the type+3-octets len
    final_decomp[startofexts+4]=(initial_oolen+tot_outer_lens-outer_exts_len)/(256)%0xff;
    final_decomp[startofexts+5]=(initial_oolen+tot_outer_lens-outer_exts_len)%0xff;


    ech_pbuf("final_decomp",final_decomp,final_decomp_len);
    s->ext.innerch=final_decomp;
    s->ext.innerch_len=final_decomp_len;

    OPENSSL_free(initial_decomp);
    return(1);

err:
    if (initial_decomp!=NULL) OPENSSL_free(initial_decomp);
    return(0);

}

/**
 * @brief print a buffer nicely
 *
 * This is used in SSL_ESNI_print
 */
void ech_pbuf(const char *msg, const unsigned char *buf, const size_t blen)
{

    OSSL_TRACE_BEGIN(TLS) {

    if (msg==NULL) {
        BIO_printf(trc_out,"msg is NULL\n");
        return;
    }
    if (buf==NULL) {
        BIO_printf(trc_out,"%s: buf is NULL\n",msg);
        return;
    }
    if (blen==0) {
        BIO_printf(trc_out,"%s: blen is zero\n",msg);
        return;
    }
    BIO_printf(trc_out,"%s (%lu):\n    ",msg,(unsigned long)blen);
    size_t i;
    for (i=0;i<blen;i++) {
        if ((i!=0) && (i%16==0))
            BIO_printf(trc_out,"\n    ");
        BIO_printf(trc_out,"%02x:",(unsigned)(buf[i]));
    }
    BIO_printf(trc_out,"\n");

    } OSSL_TRACE_END(TLS);
    return;
}

/*
 * @brief reset the handshake buffer for transcript after ECH is good
 *
 * I can't believe this worked!
 * TODO: figure out why (and fix error handling)
 *
 * @param s is the session
 * @param buf is the data to put into the transcript (usuallhy inner CH)
 * @param blen is the length of buf
 * @return 1 for success
 */
int ech_reset_hs_buffer(SSL *s, unsigned char *buf, size_t blen)
{
    /*
     * On the off-chance it'll work we'll reset the handshake_buffer
     */
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
int ech_calc_accept_confirm(SSL *s, unsigned char *acbuf, const unsigned char *shbuf, const size_t shlen)
{
    // ech_ptranscript("calc (outer), b4",s->ext.outer_s);

    /*
     * First, find the right pointers/lengths
     */
    unsigned char *tbuf=NULL; // local transcript buffer
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    size_t tlen=0;
    unsigned char *chbuf=NULL;
    size_t chlen=0;
    size_t shoffset=6+24; // offset to "magic" bits in SH.random within shbuf
    const EVP_MD *md=NULL;

    chbuf=s->ext.innerch;
    chlen=s->ext.innerch_len;

    ech_pbuf("calc conf : innerch",chbuf,chlen);
    ech_pbuf("calc conf : SH",shbuf,shlen);

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
     * bolloxed at this point. We'll fix it so, but here and
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
        tbuf[chlen]=0x02; // ServerHello
        tbuf[chlen+1]=(shlen>>16)&0xff;
        tbuf[chlen+2]=(shlen>>8)&0xff;
        tbuf[chlen+3]=shlen&0xff;
        memcpy(tbuf+chlen+4,shbuf,shlen);
    }
    memset(tbuf+chlen+shoffset,0,8);
    /*
     * figure out  h/s hash
     */
    md=ssl_handshake_md(s);
    if (md==NULL) {
        const unsigned char *cipherchars=&tbuf[chlen+shoffset+8+1+32]; // the chosen ciphersuite
        const SSL_CIPHER *c=ssl_get_cipher_by_char(s, cipherchars, 0);
        md=ssl_md(s->ctx, c->algorithm2);
        if (md==NULL) {
            /*
            * TODO: FIXME: find the real h/s hash, sha256 will alomost always
            * but *not always* be correct
            */
            md=s->ctx->ssl_digest_methods[SSL_HANDSHAKE_MAC_SHA256];
        }
    }

    ech_pbuf("calc conf : tbuf",tbuf,tlen);

    /*
     * Next, zap the magic bits and do the keyed hashing
     */
    unsigned char *insecret=s->handshake_secret;
    char *label=ECH_ACCEPT_CONFIRM_STRING;
    size_t labellen=strlen(label);
    unsigned int hashlen=EVP_MD_size(md);
    unsigned char hashval[EVP_MAX_MD_SIZE];

    if (EVP_DigestInit_ex(ctx, md, NULL) <= 0
            || EVP_DigestUpdate(ctx, tbuf, tlen) <= 0
            || EVP_DigestFinal_ex(ctx, hashval, &hashlen) <= 0) {
        goto err;
    }
    ech_pbuf("calc conf : hashval",hashval,hashlen);
    ech_pbuf("calc conf : h/s secret",insecret,EVP_MAX_MD_SIZE);

    unsigned char hoval[32];
    if (!tls13_hkdf_expand(s, md, insecret,
                           (const unsigned char *)label,labellen,
                           hashval, hashlen, 
                           hoval, hashlen, 1)) {
        goto err;
    }
    ech_pbuf("calc conf : hoval",hoval,32);
    ech_reset_hs_buffer(s,chbuf,chlen);

    /*
     * Finally, set the output
     */
    memcpy(acbuf,hoval,8);
    ech_pbuf("calc conf : result",acbuf,8);

    if (tbuf) OPENSSL_free(tbuf);
    if (ctx) EVP_MD_CTX_free(ctx);

    return(1);

err:
    if (tbuf) OPENSSL_free(tbuf);
    if (ctx) EVP_MD_CTX_free(ctx);
    return(0);
}

void SSL_set_ech_callback(SSL *s, SSL_ech_cb_func f)
{
    s->ech_cb=f;
}

void SSL_CTX_set_ech_callback(SSL_CTX *s, SSL_ech_cb_func f)
{
    s->ext.ech_cb=f;
}

/*
 * Swap the inner and outer.
 * The only reason to make this a function is because it's
 * likely very brittle - if we need any other fields to be
 * handled specially (e.g. because of some so far untested
 * combination of extensions), then this may fail, so good
 * to keep things in one place as we find that out.
 *
 * @param s is the SSL session to swap about
 * @return 0 for error, 1 for success
 */
int ech_swaperoo(SSL *s)
{
    ech_ptranscript("ech_swaperoo, b4",s);

    /*
     * Make some checks 
     */
    if (s==NULL) return(0);
    if (s->ext.inner_s==NULL) return(0);
    if (s->ext.inner_s->ext.outer_s==NULL) return(0);
    SSL *inp=s->ext.inner_s;
    SSL *outp=s->ext.inner_s->ext.outer_s;
    if (!ossl_assert(outp==s))
        return(0);

    /*
     * Stash inner fields
     */
    SSL tmp_outer=*s;
    SSL tmp_inner=*s->ext.inner_s;

    /*
     * General field swap
     */
    *s=tmp_inner;
    *inp=tmp_outer;
    s->ext.outer_s=inp;
    s->ext.inner_s=NULL;
    s->ext.outer_s->ext.inner_s=s;
    s->ext.outer_s->ext.outer_s=NULL;

    /*
     * Copy read and writers
     */
    s->wbio=tmp_outer.wbio;
    s->rbio=tmp_outer.rbio;

    /*
     * Fields we (for now) need the same in both
     */
    s->rlayer=tmp_outer.rlayer;
    s->rlayer.s=s;
    s->init_buf=tmp_outer.init_buf;
    s->init_msg=tmp_outer.init_msg;
    s->init_off=tmp_outer.init_off;
    s->init_num=tmp_outer.init_num;

    s->ext.debug_cb=tmp_outer.ext.debug_cb;
    s->ext.debug_arg=tmp_outer.ext.debug_arg;
    s->statem=tmp_outer.statem;

    /*
     * Fix up the transcript to reflect the inner CH
     * If there's a cilent hello at the start of the buffer, then
     * it's likely that's the outer CH and we want to replace that
     * with the inner. We need to be careful that there could be a
     * server hello following and can't lose that.
     * I don't think the outer client hello can be anwhere except
     * at the start of the buffer.
     * TODO: consider HRR, early_data etc
     */
    unsigned char *curr_buf=NULL;
    size_t curr_buflen=0;
    unsigned char *new_buf=NULL;
    size_t new_buflen=0;
    size_t outer_chlen=0;
    size_t other_octets=0;

    curr_buflen = BIO_get_mem_data(tmp_outer.s3.handshake_buffer, &curr_buf);
    if (curr_buflen>0 && curr_buf[0]==SSL3_MT_CLIENT_HELLO) {
        /*
         * It's a client hello, presumably the outer
         */
        outer_chlen=1+curr_buf[1]*256*256+curr_buf[2]*256+curr_buf[3];
        if (outer_chlen>curr_buflen) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return(0);
        }
        other_octets=curr_buflen-outer_chlen;
        if (other_octets>0) {
            new_buflen=tmp_outer.ext.innerch_len+other_octets;
            new_buf=OPENSSL_malloc(new_buflen);
            memcpy(new_buf,tmp_outer.ext.innerch,tmp_outer.ext.innerch_len);
            memcpy(new_buf+tmp_outer.ext.innerch_len,&curr_buf[outer_chlen],other_octets);
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
     * Finally! Declare victory - in both contexts
     * The outer's ech_attempted will have been set already
     * but not the rest of 'em.
     */
    s->ext.outer_s->ext.ech_attempted=1; 
    s->ext.ech_attempted=1; 
    s->ext.outer_s->ext.ech_success=1; 
    s->ext.ech_success=1; 
    s->ext.outer_s->ext.ech_done=1; 
    s->ext.ech_done=1; 
    s->ext.outer_s->ext.ech_grease=0; 
    s->ext.ech_grease=0; 
    /*
     * Now do servername callback that we postponed earlier
     * in case ECH worked out well.
     */
    if (final_server_name(s,0,1)!=1) {
        s->ext.outer_s->ext.ech_success=0; 
        s->ext.ech_success=0; 
        return(0);
    }
    return(1);
}

/*
 * @brief if we had inner CH cleartext, try parse and process
 * that and then decide whether to swap it for the current 
 * SSL *s - if we decide to, the big swaperoo happens inside
 * here (for now)
 * 
 * @param s is the SSL session
 * @return 1 for success, 0 for failure
 */
int ech_process_inner_if_present(SSL *s) 
{
    SSL *new_se=NULL;
    /*
     * If we successfully decrypted an ECH then see if handling
     * that as a real inner CH makes sense and if so, do the
     * swaperoo
     */
    if (s->ext.ch_depth==0 && s->ext.ech_attempted==1 && s->ext.encoded_innerch) {
        /*
         * My try-and-see version of duplicating enough of
         * the outer context - TODO: make this waaay less
         * brittle somehow
         */
        new_se=SSL_new(s->ctx);
        new_se->ext.ech_attempted=1;
        new_se->ext.ch_depth=1;
        new_se->ext.outer_s=s;
        new_se->ext.inner_s=NULL;
        new_se->rlayer=s->rlayer;
        new_se->init_buf=s->init_buf;
        new_se->init_msg=s->init_msg;
        new_se->init_off=s->init_off;
        new_se->init_num=s->init_num;
        new_se->ext.debug_cb=s->ext.debug_cb;
        new_se->ext.debug_arg=s->ext.debug_arg;
        new_se->wbio=s->wbio;
        new_se->rbio=s->rbio;

        if (s->nechs && !s->ctx->ext.nechs) {
            new_se->nechs=s->nechs;
            new_se->ech=SSL_ECH_dup(s->ech,new_se->nechs,ECH_SELECT_ALL);
            if (!new_se->ech) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        /*
         * Parse the inner into new_se
         */
        /*
         * form up the full inner for processing
         */
        if (ech_decode_inner(new_se)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        ech_pbuf("Inner CH (decoded)",new_se->ext.innerch,new_se->ext.innerch_len);
        PACKET rpkt; // input packet - from new_se->ext.innerch
        /*
         * The +4 below is because tls_process_client_hello doesn't 
         * want to be given the message type & length, so the buffer should
         * start with the version octets (0x03 0x03)
         */
        if (PACKET_buf_init(&rpkt,new_se->ext.innerch+4,new_se->ext.innerch_len-4)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /*
         * process the decoded inner
         */
        MSG_PROCESS_RETURN rv=tls_process_client_hello(new_se, &rpkt);
        if (rv!=MSG_PROCESS_CONTINUE_PROCESSING) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        if (tls_post_process_client_hello(new_se,WORK_MORE_A)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }

        s->ext.inner_s=new_se;
        if (ech_swaperoo(s)!=1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    return(1);
err:
    return(0);
}

void ech_ptranscript(const char *msg, SSL *s)
{
    size_t hdatalen=0;
    unsigned char *hdata=NULL;
    hdatalen = BIO_get_mem_data(s->s3.handshake_buffer, &hdata);
    ech_pbuf(msg,hdata,hdatalen);
    //OPENSSL_free(hdata);
    unsigned char ddata[1000];
    size_t ddatalen;
    if (s->s3.handshake_dgst!=NULL) {
        ssl_handshake_hash(s,ddata,1000,&ddatalen);
        ech_pbuf(msg,ddata,ddatalen);
    } else {
        OSSL_TRACE_BEGIN(TLS) {
            BIO_printf(trc_out,"handshake_dgst is NULL\n");
        } OSSL_TRACE_END(TLS);
    }
    return;
}

/*
 * Send grease
 */
int SSL_ech_send_grease(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx)
{
    /*
     * Let's send some random stuff that looks like...
     *       struct {
     *          ECHCipherSuite cipher_suite;
     *          opaque config_id<0..255>;
     *          opaque enc<1..2^16-1>;
     *          opaque payload<1..2^16-1>;
     *       } ClientECH;
     *
     * Here's one such (len=266):
     *
     * 00010001 00025346 00208607 BCE0C3B1 
     * 1D1E5391 9BD5D99C C1CDB5F2 5F0F9EB3
     * F35E8359 2C810ADC 8A2F00DE 2AA118F9
     * 698530FB AA4BE33B C8704024 EFE4D6E1
     * AB676E73 E8F25D23 54B813A2 27C91784
     * B831915F 24914F0C 8C558883 725CA676
     * BC97A0A4 E2B55271 E15A86B2 86ED2C56
     * 2C69C833 9C01A85A 8ED8EC2D 3C37C223
     * 3B932715 C25361BF 01CB470A 370DDE46
     * C1B3458A 4CD88FC2 4C97DF3C 1AEB9E86
     * 4E04289F 3DF5A0EA D7FFBEEF 5DD2E30A
     * 9A8825EF 92239CD5 C1420BAF 7A33E7B4
     * 7BBF0813 BABF51B6 156A79B3 79E37A6C
     * 70DADF09 A4CA746E 1CAA79A1 D5EF5BA9
     * 69ACA1A6 ECCB6561 77C46F46 2860CAB1 
     * BFC6C1E4 26F4AFCF F597721F 33B89CCC
     * A9D63D4F 2591C945 AD0E
     */

    /*
     * Assign buffers of the right size, that we'll mostly randomly fill
     */
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    size_t cid_len=8;
    unsigned char cid[SSL_ECH_GREASE_BUFSIZ];
    size_t senderpub_len=32;
    unsigned char senderpub[SSL_ECH_GREASE_BUFSIZ];
    size_t cipher_len=206;
    unsigned char cipher[SSL_ECH_GREASE_BUFSIZ];
    if (s==NULL || s->ctx==NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((RAND_bytes_ex(s->ctx->libctx, cid, cid_len) <= 0) ||
        (RAND_bytes_ex(s->ctx->libctx, senderpub, senderpub_len) <= 0) ||
        (RAND_bytes_ex(s->ctx->libctx, cipher, cipher_len) <= 0) 
            ) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ech) 
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
        || !WPACKET_sub_memcpy_u8(pkt, cid, cid_len)
        || !WPACKET_sub_memcpy_u16(pkt, senderpub, senderpub_len)
        || !WPACKET_sub_memcpy_u16(pkt, cipher, cipher_len)
        || !WPACKET_close(pkt)
            ) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    OSSL_TRACE_BEGIN(TLS) { 
        BIO_printf(trc_out,"ECH - sending GREASE\n");
    } OSSL_TRACE_END(TLS);
    return 1;
}

int ech_make_enc_info(ECHConfig *tc,unsigned char *info,size_t *info_len) 
{
    unsigned char *ip=info;

    if (!tc || !info || !info_len) return 0;
    if (*info_len < (strlen(ECH_CONTEXT_STRING)+1+tc->encoding_length)) return 0;
    
    memcpy(ip,ECH_CONTEXT_STRING,strlen(ECH_CONTEXT_STRING)); ip+=strlen(ECH_CONTEXT_STRING);
    *ip++=0x00;
    memcpy(ip,tc->encoding_start,tc->encoding_length);
    *info_len= strlen(ECH_CONTEXT_STRING)+1+tc->encoding_length;
    return 1;
}

/*
 * Calc AAD and encrypt
 */
int ech_aad_and_encrypt(SSL *s, WPACKET *pkt)
{
    /*
     * So this is a PITA but let's try
     * TODO: For now, we'll leave the call to hpke_enc in the extension
     * handler, but that'll have to move in a bit.
     *
     * 1. Make up the AAD:
     *      - the HPKE suite
     *      - my HPKE ephemeral public key
     *      - the encoded outer, minus the ECH
     * 2. Do the encryption
     * 3. Put the ECH back into the encoding
     * 4. Encode the outer (again!)
     *
     * There'll be "fixing up lengths" involved at various places as we
     * go probaby.
     */ 

    int hpke_mode=HPKE_MODE_BASE;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;
    size_t cipherlen=HPKE_MAXSIZE; 
    unsigned char cipher[HPKE_MAXSIZE];
    unsigned char *aad=NULL;
    size_t aad_len=0;
    /*
     * My ephemeral key pair for HPKE encryption
     * Has to be externally generated so public can be part of AAD (sigh)
     */
    unsigned char mypub[HPKE_MAXSIZE];
    size_t mypub_len=HPKE_MAXSIZE;
    /*
     * For some reason the EVP variant here doesn't work
     * inside HPKE - check that out - TODO:
     */
    EVP_PKEY *mypriv_evp=NULL;

    /*
     * Pick a matching public key from the Config (if we can)
     * We'll just take the 1st matching.
     */
    unsigned char *peerpub=NULL;
    size_t peerpub_len=0;
    ECHConfig *tc=NULL;
    int cind=0;
    ECHConfigs *cfgs=s->ech->cfg;
    if (cfgs==NULL) {
        /*
         * Treating this as an error. Note there could be 
         * some corner case with SCVB that gets us here
         * but hopefully not
         */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
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
    int onlen=(s->ech->outer_name==NULL?0:strlen(s->ech->outer_name));
    int prefind=-1;
    ECHConfig *firstmatch=NULL;
    for (cind=0;cind!=cfgs->nrecs;cind++) {
        ECHConfig *ltc=&cfgs->recs[cind];
        if (s->ech->outer_name && (
                    ltc->public_name_len!=onlen ||
                    strncmp(s->ech->outer_name,(char*)ltc->public_name,onlen))) {
            prefind=cind;
        }
        hpke_suite.kem_id=ltc->kem_id;
        int csuite=0;
        for (csuite=0;csuite!=ltc->nsuites;csuite++) {
            unsigned char *es=(unsigned char*)&ltc->ciphersuites[csuite];
            hpke_suite.kdf_id=es[0]*256+es[1];
            hpke_suite.aead_id=es[2]*256+es[3];
            if (hpke_suite_check(hpke_suite)==1) {
                /*
                * success if both "fit"
                */
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
        OSSL_TRACE_BEGIN(TLS) { 
            BIO_printf(trc_out,"No matching ECHConfig sadly\n");
        } OSSL_TRACE_END(TLS);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (tc==NULL && firstmatch!=NULL) {
        tc=firstmatch;
    }
    /*
     * tc is our selected config
     */
    peerpub=tc->pub;
    peerpub_len=tc->pub_len;
    if (peerpub_len <=0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (s->ext.inner_s==NULL || s->ext.inner_s->ech==NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    ech_pbuf("EAAE: peer pub",peerpub,peerpub_len);
    ech_pbuf("EAAE: clear",s->ext.inner_s->ext.encoded_innerch, s->ext.inner_s->ext.encoded_innerch_len);


    if (hpke_kg_evp(hpke_mode, hpke_suite, &mypub_len, mypub, &mypriv_evp)!=1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (mypub_len>HPKE_MAXSIZE || mypriv_evp==NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    ech_pbuf("EAAE: my pub",mypub,mypub_len);

    unsigned char *config_id=tc->config_id;
    size_t config_id_len=tc->config_id_len;

    ech_pbuf("EAAE: config id input",tc->encoding_start,tc->encoding_length);
    ech_pbuf("EAAE: config_id",config_id,config_id_len);

    aad_len=4+1+config_id_len+2+mypub_len+3+pkt->written-4;
    aad=OPENSSL_malloc(aad_len);
    if (aad==NULL) {
        EVP_PKEY_free(mypriv_evp); mypriv_evp=NULL;
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    unsigned char *cp=aad;
    *cp++=((hpke_suite.kdf_id&0xffff)/256);
    *cp++=((hpke_suite.kdf_id&0xffff)%256);
    *cp++=((hpke_suite.aead_id&0xffff)/256);
    *cp++=((hpke_suite.aead_id&0xffff)%256);
    *cp++=((config_id_len&0xff)%256);
    if (config_id_len>0) {
        memcpy(cp,config_id,config_id_len); cp+=config_id_len;
    }
    *cp++=((mypub_len&0xffff)/256);
    *cp++=((mypub_len&0xffff)%256);
    memcpy(cp,mypub,mypub_len); cp+=mypub_len;
    *cp++=(((pkt->written-4)&0xffffff)/(256*256));
    *cp++=(((pkt->written-4)&0xffffff)/256);
    *cp++=((pkt->written-4)%256);
    memcpy(cp,pkt->buf->data+4,pkt->written-4);

    ech_pbuf("EAAE: aad",aad,aad_len);

    unsigned char info[HPKE_MAXSIZE];
    size_t info_len=HPKE_MAXSIZE;
    if (ech_make_enc_info(tc,info,&info_len)!=1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        EVP_PKEY_free(mypriv_evp); mypriv_evp=NULL;
        OPENSSL_free(aad);
        return 0; 
    }
    ech_pbuf("EAAE info",info,info_len);

    int rv=hpke_enc_evp(
        hpke_mode, hpke_suite, // mode, suite
        NULL, 0, NULL, // pskid, psk
        peerpub_len,peerpub,
        0, NULL, // priv
        s->ext.inner_s->ext.encoded_innerch_len, s->ext.inner_s->ext.encoded_innerch, // clear
        aad_len, aad, // aad 
        info_len, info, // info
        mypub_len, mypub, mypriv_evp,
        &cipherlen, cipher // cipher
        );
    if (rv!=1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        EVP_PKEY_free(mypriv_evp); mypriv_evp=NULL;
        OPENSSL_free(aad);
        return 0; 
    }

    ech_pbuf("EAAE: hpke mypub",mypub,mypub_len);
    ech_pbuf("EAAE: cipher",cipher,cipherlen);
    OPENSSL_free(aad);
    EVP_PKEY_free(mypriv_evp); mypriv_evp=NULL;

    ech_pbuf("EAAE pkt b4",(unsigned char*) pkt->buf->data,pkt->written);
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_ech) 
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.kdf_id)
        || !WPACKET_put_bytes_u16(pkt, hpke_suite.aead_id)
        || !WPACKET_sub_memcpy_u8(pkt, config_id, config_id_len)
        || !WPACKET_sub_memcpy_u16(pkt, mypub, mypub_len)
        || !WPACKET_sub_memcpy_u16(pkt, cipher, cipherlen)
        || !WPACKET_close(pkt)
            ) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
    }

    // length to include
    size_t newlen=6+2+2+3+config_id_len+mypub_len+cipherlen;
    /*
     * Jump over the ciphersuites and (MUST be NULL) compression to
     * the start of extensions
     * We'll start genoffset at the end of the session ID, just
     * before the ciphersuites
     */
    unsigned char *startofmessage=(unsigned char*)pkt->buf->data;
    size_t genoffset=6+32+1+s->tmp_session_id_len; 
    size_t suiteslen=startofmessage[genoffset]*256+startofmessage[genoffset+1];
    size_t startofexts=genoffset+suiteslen+2+2; // the 2 for the suites len

    size_t origextlens=startofmessage[startofexts]*256+startofmessage[startofexts+1];
    //size_t newextlens=origextlens+echval.written;
    size_t newextlens=origextlens+newlen;
    startofmessage[startofexts]=(newextlens&0xffff)/256; 
    startofmessage[startofexts+1]=(newextlens&0xffff)%256; 

    ech_pbuf("EAAE pkt to startofexts+2",(unsigned char*) pkt->buf->data,startofexts+2);
    ech_pbuf("EAAE pkt aftr",(unsigned char*) pkt->buf->data,pkt->written);

    return 1;
}

/*
 * Server figures out AAD from state
 */
int ech_srv_get_aad(SSL *s,
        size_t pub_len, unsigned char *pub,
        size_t config_id_len, unsigned char *config_id, 
        size_t de_len, unsigned char *de, 
        size_t *aad_len,unsigned char *aad)
{
    if (s==NULL || aad_len == NULL || aad==NULL) return 0;

    unsigned char *cp=aad;
    hpke_suite_t hpke_suite = HPKE_SUITE_DEFAULT;

    *cp++=((hpke_suite.kdf_id&0xffff)/256);
    if ((cp-aad)>*aad_len) return 0;
    *cp++=((hpke_suite.kdf_id&0xffff)%256);
    if ((cp-aad)>*aad_len) return 0;
    *cp++=((hpke_suite.aead_id&0xffff)/256);
    if ((cp-aad)>*aad_len) return 0;
    *cp++=((hpke_suite.aead_id&0xffff)%256);
    if ((cp-aad)>*aad_len) return 0;
    *cp++=((config_id_len&0xff)%256);
    if ((cp-aad)>*aad_len) return 0;
    if (config_id_len>0) {
        memcpy(cp,config_id,config_id_len); cp+=config_id_len;
    }
    *cp++=((pub_len&0xffff)/256);
    if ((cp-aad)>*aad_len) return 0;
    *cp++=((pub_len&0xffff)%256);
    if ((cp-aad)>*aad_len) return 0;
    memcpy(cp,pub,pub_len); cp+=pub_len;
    if ((cp-aad)>*aad_len) return 0;

    *cp++=((de_len&0xffffff)/(256*256));
    if ((cp-aad)>*aad_len) return 0;
    *cp++=((de_len&0xffff)/256);
    if ((cp-aad)>*aad_len) return 0;
    *cp++=((de_len&0xffff)%256);
    if ((cp-aad)>*aad_len) return 0;
    memcpy(cp,de,de_len); cp+=de_len;
    if ((cp-aad)>*aad_len) return 0;

    *aad_len=(cp-aad);

    ech_pbuf("SRV AAD:",aad,*aad_len);

    return 1;
}

/*
 * Given CH encoding, return CH minus the ECH value (if present)
 *
 * @param s: SSL session stuff
 * @param ch_len: length of original encoded CH 
 * @param ch: buffer with original encoded CH
 * @param de_len: zero if no ECH present, otherwise length of buffer with CH after ECH taken out
 * @param de: NULL or the above buffer (allocated internally, caller needs to free)
 */
int drop_ech_from_ch(SSL *s, const size_t ch_len, const unsigned char *ch,
        size_t *de_len, unsigned char *de) 
{

    /*
     * TODO: Total hack time!!! once this works, we'll fix
     */
    const unsigned char *startofmessage=ch;
    /*
     * Jump over the ciphersuites and (MUST be NULL) compression to
     * the start of extensions
     * We'll start genoffset at the end of the session ID, just
     * before the ciphersuites
     */
    //size_t genoffset=2+32+1+s->tmp_session_id_len;  // note 1st 2 here was 6 before
    size_t genoffset=2+32;
    size_t sessid_len=startofmessage[genoffset];
    genoffset+=(1+sessid_len);
    size_t suiteslen=startofmessage[genoffset]*256+startofmessage[genoffset+1];
    size_t startofexts=genoffset+suiteslen+2+2; // the 2 for the suites len

    size_t origextlens=startofmessage[startofexts]*256+startofmessage[startofexts+1];

    /* 
     * find ECH if it's there
     */
    size_t echlen=0; // length of ECH, including type & ECH-internal length
    size_t echoffset=0; // offset of ECH from start of CH

    if ((startofexts+2)>(ch_len-startofexts)) {
         return 0;
    }

    ech_pbuf("dropping orig CH",(unsigned char*) ch,ch_len);
    ech_pbuf("dropping orig to startofexts+2",(unsigned char*) ch,startofexts+2);

    const unsigned char *e_start=&startofmessage[startofexts+2];
    int extsremaining=origextlens-2;
    int found=0;
    uint16_t etype=0;
    size_t elen=0;

    while (!found && extsremaining>0) {
        etype=e_start[0]*256+e_start[1];
        elen=e_start[2]*256+e_start[3];
        if (etype==TLSEXT_TYPE_ech) {
            found=1;
            echlen=elen+4; // type and length included
            echoffset=(e_start-ch); // offset from start of outer CH
            break;
        }
        e_start+=(4+elen);
        extsremaining-=(4+elen);
    }

    if (!found) {
        *de_len=0;
        return 1;
    }

    size_t newextlens=origextlens-echlen;
    if ((startofexts+newextlens)>*de_len) {
        return 0;
    }

    /* 
     * assemble de
     */
    memcpy(de,ch,startofexts);
    de[startofexts]=(newextlens&0xffff)/256; 
    de[startofexts+1]=(newextlens&0xffff)%256; 
    size_t beforeECH=echoffset-startofexts-2;
    size_t afterECH=ch_len-startofexts-2-beforeECH-echlen;
    memcpy(de+startofexts+2,ch+startofexts+2,beforeECH);
    memcpy(de+startofexts+2+beforeECH,ch+startofexts+2+beforeECH+echlen,afterECH);

    *de_len=ch_len-echlen;

    ech_pbuf("CH minus ECH",de,*de_len);

    return (1);
}

#endif
