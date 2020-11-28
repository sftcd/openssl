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
 * Ancilliary functions
 */

/**
 * Try figure out ECHConfig encodng
 *
 * @param eklen is the length of rrval
 * @param rrval is encoded thing
 * @param guessedfmt is our returned guess at the format
 * @return 1 for success, 0 for error
 */
static int ech_guess_fmt(size_t eklen, 
                    char *rrval,
                    int *guessedfmt)
{
    if (!guessedfmt || eklen <=0 || !rrval) {
        return(0);
    }

    /*
     * Try from most constrained to least in that order
     */
    if (strstr(rrval,httpssvc_telltale)) {
        *guessedfmt=ECH_FMT_HTTPSSVC;
    } else if (eklen<=strspn(rrval,AH_alphabet)) {
        *guessedfmt=ECH_FMT_ASCIIHEX;
    } else if (eklen<=strspn(rrval,B64_alphabet)) {
        *guessedfmt=ECH_FMT_B64TXT;
    } else {
        // fallback - try binary
        *guessedfmt=ECH_FMT_BIN;
    }
    return(1);
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
    if (tbf->innerch) {
        OPENSSL_free(tbf->innerch);
    }
    if (tbf->encoded_innerch) {
        OPENSSL_free(tbf->encoded_innerch);
    }
    if (tbf->inner_name!=NULL) OPENSSL_free(tbf->inner_name);
    if (tbf->outer_name!=NULL) OPENSSL_free(tbf->outer_name);
    /*
     * More TODO
     */
    return;
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
    unsigned int olen;
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
        if (ec->version!=ECH_DRAFT_08_VERSION) {
            unsigned char *foo=OPENSSL_malloc(ech_content_length);
            if (!foo) goto err;
            if (!PACKET_copy_bytes(&pkt, foo, ech_content_length)) {
                OPENSSL_free(foo);
                goto err;
            }
            OPENSSL_free(foo);
            continue;
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
	    ec->nsuites=suiteoctets/2;
	    ec->ciphersuites=OPENSSL_malloc(ec->nsuites*sizeof(unsigned int));
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
    er->encoded_len=olen+2;
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
        char *ekval, 
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
    char *ekcpy=ekval;
    if (detfmt==ECH_FMT_HTTPSSVC) {
        ekcpy=strstr(ekval,httpssvc_telltale);
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
    int rv=local_ech_add(ekfmt,eklen,ekval,num_echs,&echs);
    if (rv!=1) {
        SSLerr(SSL_F_SSL_ECH_ADD, SSL_R_BAD_VALUE);
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
    int rv=local_ech_add(ekfmt,eklen,ekval,num_echs,&echs);
    if (rv!=1) {
        SSLerr(SSL_F_SSL_CTX_ECH_ADD, SSL_R_BAD_VALUE);
        return(0);
    }
    ctx->ext.ech=echs;
    ctx->ext.nechs=*num_echs;
    return(1);
}

/**
 * @brief Turn on SNI encryption for an (upcoming) TLS session
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
    if (outer_name==NULL) return(0);

    if (s->ech->inner_name!=NULL) OPENSSL_free(s->ech->inner_name);
    s->ech->inner_name=OPENSSL_strdup(inner_name);
    if (s->ech->outer_name!=NULL) OPENSSL_free(s->ech->outer_name);
    s->ech->outer_name=OPENSSL_strdup(outer_name);

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
int SSL_ech_alpns(SSL *s, const char *hidden_alpns, const char *public_alpns)
{
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
 * @param s is the SSL connection (can be NULL)
 * @param echcfgfile has the relevant ECHConfig(s) and private key in PEM format
 * @return 1 for success, other otherwise
 */
int SSL_CTX_ech_server_enable(SSL_CTX *s, const char *echcfgfile)
{
    return 1;
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
int SSL_ech_print(BIO* out, SSL *con, int selector)
{
    return 1;
}

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
int SSL_ech_get_status(SSL *s, char **hidden, char **clear_sni)
{
    return 1;
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

static int len_field_dup(void *old, void* new, unsigned int len)
{
    if (len==0) {
        new=NULL; 
        return 1; 
    }
    new=(void*)OPENSSL_malloc(len);
    if (!new) return 0;
    memcpy(new,old,len);
    return 1;
} 

static int ECHConfig_dup(ECHConfig *old, ECHConfig *new)
{
    if (!new || !old) return 0;
    *new=*old; // shallow copy
    if (len_field_dup((void*)old->pub,(void*)new->pub,old->pub_len)!=1) return 0;
    // TODO: more to come
    return 1;
}

static int ECHConfigs_dup(ECHConfigs *old, ECHConfigs *new)
{
    int i=0;
    if (old->encoded!=NULL) {
        if (len_field_dup((void*)old->encoded,(void*)new->encoded,old->encoded_len)!=1) return 0;
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
        new_se[i]=orig[i];
        if (ECHConfigs_dup(orig[i].cfg,new_se[i].cfg)!=1) goto err;
    }

    if (orig->inner_name!=NULL) {
        new_se->inner_name=OPENSSL_strdup(orig->inner_name);
    }
    if (orig->outer_name!=NULL) {
        new_se->inner_name=OPENSSL_strdup(orig->inner_name);
    }

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
        rv=ech_guess_fmt(rrlen,rrval,&detfmt);
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
                printf("ALPN id %d is %s\n",ind,aid_buf);
                ap+=aid_len;
            }        
        }
    }
    if (!done) {
        printf("Didn't get an ECHConfigs\n");
        *num_echs=0;
        return(1);
    }

    /*
     * Deposit ECHConfigs that we found
     */
    rv=local_ech_add(ECH_FMT_BIN,eklen,(char*)ekval,num_echs,&echs);
    if (rv!=1) {
        SSLerr(SSL_F_SSL_SVCB_ADD, SSL_R_BAD_VALUE);
        printf("Got but failed to parse an ECHConfigs\n");
        return(0);
    } else {
        printf("Got and parsed an ECHConfigs\n");
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
     /*TLSEXT_IDX_max_fragment_length */ 0,
     /*TLSEXT_IDX_srp */ 0,
     /*TLSEXT_IDX_ec_point_formats */ 0,
     /*TLSEXT_IDX_supported_groups */ 0,
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
     /*TLSEXT_IDX_signature_algorithms */ 1,
     /*TLSEXT_IDX_supported_versions */ 1,
     /*TLSEXT_IDX_psk_kex_modes */ 1,
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
     /*TLSEXT_IDX_server_name */ 0,
     /*TLSEXT_IDX_max_fragment_length */ 0,
     /*TLSEXT_IDX_srp */ 0,
     /*TLSEXT_IDX_ec_point_formats */ 0,
     /*TLSEXT_IDX_supported_groups */ 0,
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
    if (!s->ech) return(ECH_SAME_EXT_CONTINUE); // nothing to do
    int type=s->ech->etype;
    int nexts=sizeof(ech_outer_config)/sizeof(int);
    int tind=ech_map_ext_type_to_ind(type);
    if (tind==-1) return(ECH_SAME_EXT_ERR);
    if (tind>=nexts) return(ECH_SAME_EXT_ERR);

    /*
     * When doing the inner CH, just note what will later be
     * compressed, if we want to compress
     */
    if (s->ext.ch_depth==0 && !ech_outer_config[tind]) {
        printf("Not doing outer compressing for ext type %d\n",type);
        return(ECH_SAME_EXT_CONTINUE);
    }
    if (s->ext.ch_depth==0 && ech_outer_config[tind]) {
        printf("Will do outer compressing for ext type %d\n",type);
        if (s->ech->n_outer_only>=ECH_OUTERS_MAX) {
	        return ECH_SAME_EXT_ERR;
        }
        s->ech->outer_only[s->ech->n_outer_only]=type;
        s->ech->n_outer_only++;
        return(ECH_SAME_EXT_CONTINUE);
    }

    /* 
     * From here on we're in 2nd call, making the outer CH 
     */
    if (!s->clienthello) return(ECH_SAME_EXT_ERR); 
    if (!pkt) return(ECH_SAME_EXT_ERR);
    if (ech_outer_indep[tind]) {
        printf("New outer without compressing for ext type %d\n",type);
        return(ECH_SAME_EXT_CONTINUE);
    } else {
        printf("Re-using inner in outer without compressing for ext type %d\n",type);

	    int ind=0;
	    RAW_EXTENSION *myext=NULL;
	    RAW_EXTENSION *raws=s->clienthello->pre_proc_exts;
	    if (raws==NULL) {
	        return ECH_SAME_EXT_ERR;
	    }
	    size_t nraws=s->clienthello->pre_proc_exts_len;
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
            printf("Exiting at %d\n",__LINE__);
	        return ECH_SAME_EXT_CONTINUE;
	    }
	    if (myext->data.curr!=NULL && myext->data.remaining>0) {
	        if (!WPACKET_put_bytes_u16(pkt, type)
	            || !WPACKET_sub_memcpy_u16(pkt, myext->data.curr, myext->data.remaining)) {
                printf("Exiting at %d\n",__LINE__);
	            return ECH_SAME_EXT_ERR;
	        }
	    } else {
	        /*
	         * empty extension
	         */
	        if (!WPACKET_put_bytes_u16(pkt, type)
	                || !WPACKET_put_bytes_u16(pkt, 0)) {
                printf("Exiting at %d\n",__LINE__);
	            return ECH_SAME_EXT_ERR;
	        }
	    }
        printf("Exiting at %d\n",__LINE__);
        return(ECH_SAME_EXT_DONE);
    }
}

/**
 * @brief After "normal" 1st pass CH is done, fix encoding as needed
 *
 * This will make up the ClientHelloInner and EncodedClientHelloInner buffes
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
    
 #ifdef OLDWAY
    if (s->ech->innerch==NULL || s->ech->innerch_len==0) return(0);
    /* 
     * the input is longer than output by definition so allocate that much 
     * this'll be freed later when 's' is so no need to handle on exit
     */
    s->ech->encoded_innerch=OPENSSL_malloc(s->ech->innerch_len);
    if (s->ech->encoded_innerch==NULL) return(0);
    /*
     * Walk the input 'till we hit extensions
     * Bear in mind we're not (here) dealing with a
     * random client-hello from someone else but only
     * with one we just made. So we can assume a bit
     * more (modulo code evolution).
     */
    unsigned char *icb=s->ech->innerch;
    size_t skip2cs=76;
    /*
     * Sanity check index vs. length to check 
     */
    if ((skip2cs+2)>s->ech->innerch_len) return(0);
    size_t cslen=256*icb[skip2cs]+icb[skip2cs+1];
    /*
     * offset for exts is end of ciphersuites plus 
     * 2 for empty compression plus two for length
     * of encoded exts
     */
    size_t extoffset=2+skip2cs+cslen+2+2;
    if (extoffset>s->ech->innerch_len) return(0);
    /*
     * Might need two more here for decoding function, we'll see
     */
    /*
     * TODO: check clean up of extensions
     * Note sure why I made that call:-)
     */
    unsigned char *full_encoded_exts=&s->ech->innerch[extoffset];
    size_t fe_len=s->ech->innerch_len-extoffset;
    PACKET extensions;
    RAW_EXTENSION *rexts;
    size_t rexts_len;
    if (!PACKET_buf_init(&extensions, full_encoded_exts, fe_len)) {
        return(0);
    }
    if (!tls_collect_extensions(s, &extensions, SSL_EXT_CLIENT_HELLO,
                                &rexts,&rexts_len,1)) {
        return(0);
    }
#endif

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

    uint16_t *oo=s->ech->outer_only;
    int noo=s->ech->n_outer_only;
    RAW_EXTENSION *raws=s->clienthello->pre_proc_exts;
    size_t nraws=s->clienthello->pre_proc_exts_len;
    int ind=0;
    int compression_started=0;
    int compression_done=0;
    for (ind=0;ind!=nraws;ind++) {
        int present=raws[ind].present;
        if (!present) continue;
        int type=raws[ind].type;
        int do_compression=0;
        int ooi=0;
        for (ooi=0;ooi!=noo;ooi++) {
            if (type==oo[ooi]) {
                if (compression_done==1) {
                    /*
                     * Error - only allowed 1 run of contiguous exts
                     */
                    return(0);
                }
                do_compression=1;
                compression_started=1;
            }
        }
        if (do_compression && !compression_done) {
                if (!WPACKET_put_bytes_u16(&inner, type)
                    || !WPACKET_sub_memcpy_u16(&inner, oo, noo*2)) {
                    compression_done=1;
                    return (0);
                }
        } else if (!do_compression) {
            if (raws[ind].data.curr!=NULL) {
                if (!WPACKET_put_bytes_u16(&inner, type)
                    || !WPACKET_sub_memcpy_u16(&inner, raws[ind].data.curr, raws[ind].data.remaining)) {
                    return (0);
                }
            } else {
                /*
                 * empty extension
                 */
                if (!WPACKET_put_bytes_u16(&inner, type)
                        || !WPACKET_put_bytes_u16(&inner, 0)) {
                    return (0);
                }
            }
        }
    }

    /*
     * close the inner CH
     */
    if (!WPACKET_close(&inner))  {
        WPACKET_cleanup(&inner);
        goto err;
    }

    /*
     * Set pointer/len for inner CH 
     */
    size_t innerinnerlen=0;
    if (!WPACKET_get_length(&inner, &innerinnerlen)) {
        WPACKET_cleanup(&inner);
        goto err;
    }

    /* 
     * we need to prepend a few octets onto that to get the encoding 
     * we can decode
     */
    innerch_full=OPENSSL_malloc(innerinnerlen);
    if (!innerch_full) {
        goto err;
    }
    memcpy(innerch_full,inner_mem->data,innerinnerlen);
    s->ech->encoded_innerch=innerch_full;
    s->ech->encoded_innerch_len=innerinnerlen;

    return(1);
err:
    // TODO: free stuff
    return(0);
}

/**
 * @brief print a buffer nicely
 *
 * This is used in SSL_ESNI_print
 */
void ech_pbuf(char *msg,unsigned char *buf,size_t blen)
{
    if (msg==NULL) {
        printf("msg is NULL\n");
        return;
    }
    if (buf==NULL) {
        printf("%s: buf is NULL\n",msg);
        return;
    }
    if (blen==0) {
        printf("%s: blen is zero\n",msg);
        return;
    }
    printf("%s (%lu):\n    ",msg,(unsigned long)blen);
    size_t i;
    for (i=0;i<blen;i++) {
        if ((i!=0) && (i%16==0))
            printf("\n    ");
        printf("%02x:",buf[i]);
    }
    printf("\n");
    return;
}

/*
 * A stab at a "special" copy of the SSL struct
 * from inner to outer, so we can play with
 * changes
 */
int ech_inner2outer_dup(SSL *in)
{
    if (!in) return(0);
    /*
     * Mega-copy
     */
    SSL *new=OPENSSL_malloc(sizeof(SSL));
    if (!new) return(0);
    *new=*in; // struct copy
    in->ext.inner_s=new;
    /*
     * Note that we've not yet checked if server
     * successfully used the inner_s - this'll be
     * checked and fixed up after 1st EncryptedExtension
     * is rx'd. Code for that in ssl/record/ssl3_record_tls13.c:tls13_enc_esni
     */
    in->ext.inner_s_checked=0;
    in->ext.inner_s_shdone=0;
    in->ext.inner_s_ftd=0;
    return(1);
}

#endif
