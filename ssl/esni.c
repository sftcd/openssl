/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * File: esni.c - the core implementation of drat-ietf-tls-esni-02
 * Author: stephen.farrell@cs.tcd.ie
 * Date: 2018 December-ish
 */

#include <ctype.h>
#include <crypto/bio/bio_local.h>
#include "ssl_local.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/esni.h>
#include <openssl/esnierr.h>
#ifndef OPENSSL_NO_SSL_TRACE
/*
 * Optional (at build time) tracing of TLS stuff
 */
#include <openssl/trace.h>
#endif

#ifndef OPENSSL_NO_ESNI

/*
 * Needed to use stat for file status below in esni_check_filenames
 * TODO: figure out porting for that, it'll be work he predicts:-)
 * See crypto/rand/randfile.c for other code using fstat
 * that should help
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


/*
 * Purely debug
 */
#ifdef ESNI_CRYPT_INTEROP
unsigned char *lg_nonce=NULL;
size_t lg_nonce_len=0;
static void so_esni_pbuf(char *msg,unsigned char *buf,size_t blen);
#endif

#ifndef OPENSSL_NO_SSL_TRACE
/*
 * Do some OpenSSL tracing - you need a non-default build for
 * this to do anything other than a complex NOOP
 */
#define ENTRY_TRACE OSSL_TRACE_BEGIN(TLS) { BIO_printf(trc_out,"Entering %s at %d\n",__FUNCTION__,__LINE__); } OSSL_TRACE_END(TLS);
#define EXIT_TRACE OSSL_TRACE_BEGIN(TLS) { BIO_printf(trc_out,"Exiting %s at %d\n",__FUNCTION__,__LINE__); } OSSL_TRACE_END(TLS);
#else
#define ENTRY_TRACE
#define EXIT_TRACE
#endif

/**
 * Handle padding - the server needs to do padding in case the
 * certificate/key-size exposes the ESNI. But so can lots of 
 * the other application interactions, so to be at least a bit
 * cautious, we'll also pad the crap out of everything on the
 * client side (at least to see what happens:-)
 * This could be over-ridden by the client appication if it
 * wants by setting a callback via SSL_set_record_padding_callback
 * We'll try set to 486 bytes, so that 3 plaintexts are likely
 * to fit in a 1500 byte MTU. (That's a pretty arbitrary
 * decision:-)
 * TODO: test and see how this padding affects a real application
 * as soon as we've integrated with one
*/
#define ESNI_DEFAULT_PADDED 486  ///< We'll pad all TLS plaintext to this size

/*
 * Utility functions
 */

/**
 * @brief map 8 bytes in n/w byte order from PACKET to a 64-bit time value
 *
 * @todo TODO: there must be code for this somewhere - find it
 * 
 * @param buf is a bit of the PACKET with the 8 octets of interest
 * @return is the 64 bit value from those 8 octets
 */
static uint64_t uint64_from_bytes(unsigned char *buf)
{
    uint64_t rv=0;
    rv = ((uint64_t)(*buf)) << 56;
    rv |= ((uint64_t)(*(buf + 1))) << 48;
    rv |= ((uint64_t)(*(buf + 2))) << 40;
    rv |= ((uint64_t)(*(buf + 3))) << 32;
    rv |= ((uint64_t)(*(buf + 4))) << 24;
    rv |= ((uint64_t)(*(buf + 5))) << 16;
    rv |= ((uint64_t)(*(buf + 6))) << 8;
    rv |= *(buf + 7);
    return(rv);
}

/**
 * @brief decode ascii hex to a binary buffer
 *
 * @todo TODO: there should be an OPENSSL_* function somewhere for this I guess - find it
 * This assumes string is correctly ascii hex encoded
 *
 * @param ahlen is the ascii hex string length
 * @param ahstr is the ascii hex string
 * @param blen is a pointer to the returned binary length
 * @param buf is a pointer to the internally allocated binary buffer
 * @return zero for error, 1 for success 
 */
static int ah_decode(size_t ahlen, const char *ah, size_t *blen, unsigned char **buf)
{
    size_t lblen=0;
    unsigned char *lbuf=NULL;
    if (ahlen <=0 || ah==NULL || blen==NULL || buf==NULL) {
        return 0;
    }
    if (ahlen%1) {
        return 0;
    }
    lblen=ahlen/2;
    lbuf=OPENSSL_malloc(lblen);
    if (lbuf==NULL) {
        return 0;
    }
    int i=0;
    for (i=0;i!=lblen;i++) {
        lbuf[i]=ESNI_A2B(ah[2*i])*16+ESNI_A2B(ah[2*i+1]);
    }
    *blen=lblen;
    *buf=lbuf;
    return 1;
}

/**
 * @brief Decode from TXT RR to binary buffer
 *
 * This was the same as ct_base64_decode from crypto/ct/ct_b64.c
 * which function is declared static but could otherwise
 * have been be re-used. Returns -1 for error or length of decoded
 * buffer length otherwise (wasn't clear to me at first
 * glance). Possible future change: re-use the ct code by
 * exporting it.
 * With draft-03, we're extending to allow a set of 
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
static int esni_base64_decode(char *in, unsigned char **out)
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
        ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ERR_R_MALLOC_FAILURE);
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
            ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
            goto err;
        }

        /* Subtract padding bytes from |outlen|.  Any more than 2 is malformed. */
        i = 0;
        while (inp[thisfraglen-i-1] == '=') {
            if (++i > 2) {
                ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
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
    ESNIerr(ESNI_F_ESNI_BASE64_DECODE, ESNI_R_BASE64_DECODE_ERROR);
    return -1;
}

static const SSL_CIPHER *cs2sc(uint16_t ciphersuite)
{
    const SSL_CIPHER *new;
    unsigned char encoding[2];
    encoding[0]=ciphersuite/256;
    encoding[1]=ciphersuite%256;
    new=ssl3_get_cipher_by_char(encoding);
    return new;
}

/**
 * @brief Free up an ENSI_RECORD 
 *
 * ESNI_RECORD is our struct for what's in the DNS
 * 
 * @wparam er is a pointer to the record
 */
void ESNI_RECORD_free(ESNI_RECORD *er)
{
    int i; /* loop counter - android build doesn't like C99;-( */
    if (er==NULL) return;
    if (er->group_ids!=NULL) OPENSSL_free(er->group_ids);
    if (er->public_name!=NULL) OPENSSL_free(er->public_name);
    for (i=0;i!=er->nkeys;i++) {
        EVP_PKEY *pk=er->keys[i];
        EVP_PKEY_free(pk);
        if (er->encoded_keys[i]!=NULL) OPENSSL_free(er->encoded_keys[i]);
    }
    if (er->keys!=NULL) OPENSSL_free(er->keys);

#ifdef DEEP_COPY_EXTS
    /*
     * Extension-related values were shallow copied to above so don't free here
     */
    for (i=0;i!=er->nexts;i++) {
        if (er->exts && er->exts[i]!=NULL) OPENSSL_free(er->exts[i]);
    }
    if (er->exts!=NULL) OPENSSL_free(er->exts);
    if (er->exttypes!=NULL) OPENSSL_free(er->exttypes);
    if (er->extlens!=NULL) OPENSSL_free(er->extlens);
    for (i=0;i!=er->dnsnexts;i++) {
        if (er->dnsexts && er->dnsexts[i]!=NULL) OPENSSL_free(er->dnsexts[i]);
    }
    if (er->dnsexts!=NULL) OPENSSL_free(er->dnsexts);
    if (er->dnsexttypes!=NULL) OPENSSL_free(er->dnsexttypes);
    if (er->dnsextlens!=NULL) OPENSSL_free(er->dnsextlens);
#endif

    if (er->ciphersuites!=NULL) OPENSSL_free(er->ciphersuites);
    if (er->encoded_lens!=NULL) OPENSSL_free(er->encoded_lens);
    if (er->encoded_keys!=NULL) OPENSSL_free(er->encoded_keys);
    return;
}


/**
 * Free up an SSL_ESNI structure 
 *
 * Note that we don't free the top level, caller should do that
 * This will free the CLIENT_ESNI structure contained in here.
 *
 * @param esni a ptr to an SSL_ESNI str
 */
void SSL_ESNI_free(SSL_ESNI *deadesni)
{
    int j=0;
    int i=0;
    if (deadesni==NULL) return;
    int tofree=deadesni->num_esni_rrs;
    for (i=0;i!=tofree;i++) {
        SSL_ESNI *esni=&deadesni[i];
        if (esni==NULL) return;
        if (esni->the_esni != NULL) {
            /*
             * The CLIENT_ESNI structure (the_esni) doesn't have separately
             * allocated buffers on the client, but it does on the server.
             * So we check if they're pointers to other SSL_ESNI fields 
             * or need to be freed
             */
            CLIENT_ESNI *ce=esni->the_esni;
            if (ce->encoded_keyshare!= NULL && ce->encoded_keyshare!=esni->encoded_keyshare) OPENSSL_free(ce->encoded_keyshare);
            if (ce->record_digest != NULL && ce->record_digest!=esni->rd) OPENSSL_free(ce->record_digest);
            if (ce->encrypted_sni != NULL && ce->encrypted_sni!=esni->cipher) OPENSSL_free(ce->encrypted_sni);
            OPENSSL_free(esni->the_esni); 
        }
        if (esni->encservername!=NULL) OPENSSL_free(esni->encservername);
        if (esni->clear_sni!=NULL) OPENSSL_free(esni->clear_sni);
        if (esni->public_name!=NULL) OPENSSL_free(esni->public_name);
        if (esni->encoded_rr!=NULL) OPENSSL_free(esni->encoded_rr);
        if (esni->rd!=NULL) OPENSSL_free(esni->rd);
        if (esni->esni_peer_keyshare!=NULL) OPENSSL_free(esni->esni_peer_keyshare);
        if (esni->esni_peer_pkey!=NULL) EVP_PKEY_free(esni->esni_peer_pkey);
        if (esni->nonce!=NULL) OPENSSL_free(esni->nonce);
        if (esni->hs_cr!=NULL) OPENSSL_free(esni->hs_cr);
        if (esni->hs_kse!=NULL) OPENSSL_free(esni->hs_kse);
        if (esni->keyshare) EVP_PKEY_free(esni->keyshare);
        if (esni->encoded_keyshare) OPENSSL_free(esni->encoded_keyshare);
        if (esni->hi!=NULL) OPENSSL_free(esni->hi);
        if (esni->hash!=NULL) OPENSSL_free(esni->hash);
        if (esni->Z!=NULL) OPENSSL_free(esni->Z);
        if (esni->Zx!=NULL) OPENSSL_free(esni->Zx);
        if (esni->key!=NULL) OPENSSL_free(esni->key);
        if (esni->iv!=NULL) OPENSSL_free(esni->iv);
        if (esni->aad!=NULL) OPENSSL_free(esni->aad);
        if (esni->plain!=NULL) OPENSSL_free(esni->plain);
        if (esni->cipher!=NULL) OPENSSL_free(esni->cipher);
        if (esni->tag!=NULL) OPENSSL_free(esni->tag);
        if (esni->realSNI!=NULL) OPENSSL_free(esni->realSNI);
#ifdef ESNI_CRYPT_INTEROP
        if (esni->private_str!=NULL) OPENSSL_free(esni->private_str);
#endif
        /* the buffers below here were freed above if needed */
        if (esni->nexts!=0) {
            for (j=0;j!=esni->nexts;j++) {
                if (esni->exts && esni->exts[j]!=NULL) OPENSSL_free(esni->exts[j]);
            }
            if (esni->exts!=NULL) OPENSSL_free(esni->exts);
            if (esni->exttypes!=NULL) OPENSSL_free(esni->exttypes);
            if (esni->extlens!=NULL) OPENSSL_free(esni->extlens);
        }
        if (esni->dnsnexts!=0) {
            for (j=0;j!=esni->dnsnexts;j++) {
                if (esni->dnsexts && esni->dnsexts[j]!=NULL) OPENSSL_free(esni->dnsexts[j]);
            }
            if (esni->dnsexts!=NULL) OPENSSL_free(esni->dnsexts);
            if (esni->dnsexttypes!=NULL) OPENSSL_free(esni->dnsexttypes);
            if (esni->dnsextlens!=NULL) OPENSSL_free(esni->dnsextlens);
        }

        if (esni->naddrs!=0) {
            /*
             * Oddly, one free call here works
             */
            BIO_ADDR_free(esni->addrs);
        }
        if (esni->privfname!=NULL) {
            OPENSSL_free(esni->privfname);
        }
        if (esni->pubfname!=NULL) OPENSSL_free(esni->pubfname);
        esni->loadtime=0;

        // zap all of that to zero 
        memset(esni,0,sizeof(SSL_ESNI));
    }
    return;
}

/**
 * @brief Verify the SHA256 checksum that should be in the DNS record
 *
 * Fixed SHA256 hash in this case, we work on the offset here,
 * (bytes 2 bytes then 4 checksum bytes then rest) with no other 
 * knowledge of the encoding.
 *
 * @param buf is the buffer
 * @param buf_len is obvous
 * @return 1 for success, not 1 otherwise
 */
static int esni_checksum_check(unsigned char *buf, size_t buf_len)
{
    /* 
     * copy input with zero'd checksum, do SHA256 hash, compare with checksum, tedious but easy enough
     */
    unsigned char *buf_zeros=NULL;
    /*
     * Length has to be >6 to fit version and checksum
     */
    if (buf==NULL || buf_len <= 6 || buf_len >= ESNI_MAX_RRVALUE_LEN ) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    buf_zeros=OPENSSL_malloc(buf_len);
    if (buf_zeros==NULL) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(buf_zeros,buf,buf_len);
    memset(buf_zeros+2,0,4);
    unsigned char md[EVP_MAX_MD_SIZE];
    SHA256_CTX context;
    if(!SHA256_Init(&context)) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if(!SHA256_Update(&context, buf_zeros, buf_len)) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if(!SHA256_Final(md, &context)) {
        ESNIerr(ESNI_F_ESNI_CHECKSUM_CHECK, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    OPENSSL_free(buf_zeros);
    if (CRYPTO_memcmp(buf+2,md,4)) {
        /* non match - bummer */
        return 0;
    } else {
        return 1;
    }
err:
    if (buf_zeros!=NULL) OPENSSL_free(buf_zeros);
    return 0;
}

/**
 * @brief Hash the buffer as per the ciphersuite specified therein
 *
 * Note that this isn't quite what the I-D says - It seems that NSS uses the 
 * entire buffer, incl. the version, so I've also done that as it works!
 * Opened issue: https://github.com/tlswg/draft-ietf-tls-esni/issues/119
 * That got resolved just fine.
 * Draft-04 changed the input bytes here to exclude the dns_extensions
 * from the hash calculation, but that change was implemented in the
 * calling code.
 *
 * @param buf is the input buffer
 * @param blen is the input buffer length
 * @param md is the hash function
 * @param rd_len is (a ptr to) the output hash length
 * @return a pointer to the hash buffer allocated within the function or NULL on error
 */
static unsigned char *esni_make_rd(const unsigned char *buf,const size_t blen, const EVP_MD *md, size_t *rd_len)
{
    /*
     */
    EVP_MD_CTX *mctx = NULL;
    mctx = EVP_MD_CTX_new();
    size_t lc_rd_len=EVP_MD_size(md);
    unsigned char *rd=OPENSSL_malloc(lc_rd_len);
    if (rd==NULL) {
        goto err;
    }
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
            || EVP_DigestUpdate(mctx, buf, blen) <= 0
            || EVP_DigestFinal_ex(mctx, rd, NULL) <= 0) {
        ESNIerr(ESNI_F_ESNI_MAKE_RD, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(mctx);
    *rd_len=lc_rd_len;
    return rd;
err:
    return NULL;
}

/**
 * @brief wrap a "raw" key share in the relevant TLS presentation layer encoding
 *
 * Put the outer length and curve ID around a key share.
 * This just exists because we do it twice: for the ESNI
 * client keyshare and for handshake client keyshare.
 * The input keyshare is the e.g. 32 octets of a point
 * on curve 25519 as used in X25519.
 * There's no magic here, it's just that this code recurs
 * in handling ESNI. Theere might be some existing API to
 * use that'd be better.
 *
 * @param keyshare is the input keyshare which'd be 32 octets for x25519
 * @param keyshare_len is the length of the above (0x20 for x25519)
 * @param curve_id is the IANA registered value for the curve e.g. 0x1d for X25519
 * @param outlen is the length of the encoded version of the above
 * @return is NULL (on error) or a pointer to the encoded version buffer
 */
unsigned char *SSL_ESNI_wrap_keyshare(
                const unsigned char *keyshare,
                const size_t keyshare_len,
                const uint16_t curve_id,
                size_t *outlen)

{
    if (outlen==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_WRAP_KEYSHARE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    unsigned char *dest=NULL;
    size_t destlen=keyshare_len+6;
    dest=OPENSSL_zalloc(destlen);
    if (dest==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_WRAP_KEYSHARE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    dest[0]=(keyshare_len+4)/256;;
    dest[1]=(keyshare_len+4)%256;;
    dest[2]=curve_id/256;
    dest[3]=curve_id%256;
    dest[4]=keyshare_len/256;;
    dest[5]=keyshare_len%256;;
    memcpy(dest+6,keyshare,keyshare_len);
    *outlen=destlen;
    return dest;
}

/**
 * @brief Decode from binary to ESNI_RECORD
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param binbuf is the buffer with the encoding
 * @param binblen is the length of binbunf
 * @param leftover is the number of unused octets from the input
 * @return NULL on error, or an ESNI_RECORD structure 
 */
static ESNI_RECORD *SSL_ESNI_RECORD_new_from_binary(SSL_CTX *ctx, SSL *con, unsigned char *binbuf, size_t binblen, int *leftover)
{
    ESNI_RECORD *er=NULL;

    if (leftover==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    er=(ESNI_RECORD*)OPENSSL_malloc(sizeof(ESNI_RECORD));
    if (er==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memset(er,0,sizeof(ESNI_RECORD));

    PACKET pkt={binbuf,binblen};
    /* sanity check: version + checksum + KeyShareEntry have to be there - min len >= 10 */
    if (binblen < 10) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_BASE64_DECODE_ERROR);
        goto err;
    }
    /* version */
    if (!PACKET_get_net_2(&pkt,&er->version)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    /*
     * check version and fail early if failing 
     */
    switch (er->version) {
        case ESNI_DRAFT_02_VERSION:
        case ESNI_DRAFT_03_VERSION:
        case ESNI_DRAFT_04_VERSION:
            break;
        default:
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
    }
    /* checksum decode */
    if (er->version!=ESNI_DRAFT_04_VERSION) {
        if (!PACKET_copy_bytes(&pkt,er->checksum,4)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
    }
    if (er->version!=ESNI_DRAFT_02_VERSION) {
        /* 
         * read public_name 
         */
        PACKET public_name_pkt;
        if (!PACKET_get_length_prefixed_2(&pkt, &public_name_pkt)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->public_name_len=PACKET_remaining(&public_name_pkt);
        if (er->public_name_len<=4||er->public_name_len>TLSEXT_MAXLEN_host_name) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->public_name=OPENSSL_malloc(er->public_name_len+1);
        if (er->public_name==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        PACKET_copy_bytes(&public_name_pkt,er->public_name,er->public_name_len);
        er->public_name[er->public_name_len]='\0';
    }
    /* 
     * list of KeyShareEntry elements - 
     * inspiration: ssl/statem/extensions_srvr.c:tls_parse_ctos_key_share 
     */
    PACKET key_share_list;
    if (!PACKET_get_length_prefixed_2(&pkt, &key_share_list)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    uint16_t group_id;
    PACKET encoded_pt;
    int nkeys=0;
    uint16_t *group_ids=NULL;
    EVP_PKEY **keys=NULL;
    unsigned char **encoded_keys=NULL;
    size_t *encoded_lens=NULL;
    while (PACKET_remaining(&key_share_list) > 0) {
        unsigned int tmp;
        if (!PACKET_get_net_2(&key_share_list, &tmp)
                || !PACKET_get_length_prefixed_2(&key_share_list, &encoded_pt)
                || PACKET_remaining(&encoded_pt) == 0) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        if (tmp>ESNI_MAX_RRVALUE_LEN) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        group_id=(uint16_t)tmp;
        EVP_PKEY *kn=ssl_generate_param_group(con,group_id);
        if (kn==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        /* stash encoded public value for later */
        size_t thislen=PACKET_remaining(&encoded_pt);
        unsigned char *thisencoded=NULL;
        thisencoded=OPENSSL_malloc(PACKET_remaining(&encoded_pt));
        if (thisencoded==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        memcpy(thisencoded,PACKET_data(&encoded_pt),thislen);
        if (!EVP_PKEY_set1_tls_encodedpoint(kn,thisencoded,thislen)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        nkeys++;
        EVP_PKEY** tkeys=(EVP_PKEY**)OPENSSL_realloc(keys,nkeys*sizeof(EVP_PKEY*));
        if (tkeys == NULL ) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        keys=tkeys;
        keys[nkeys-1]=kn;
        group_ids=(uint16_t*)OPENSSL_realloc(group_ids,nkeys*sizeof(uint16_t));
        if (group_ids == NULL ) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        group_ids[nkeys-1]=group_id;
        encoded_lens=(size_t*)OPENSSL_realloc(encoded_lens,nkeys*sizeof(size_t));
        if (encoded_lens == NULL ) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        encoded_lens[nkeys-1]=thislen;
        encoded_keys=(unsigned char **)OPENSSL_realloc(encoded_keys,nkeys*sizeof(unsigned char **));
        if (encoded_keys==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        encoded_keys[nkeys-1]=thisencoded;
    }
    er->nkeys=nkeys;
    er->keys=keys;
    er->group_ids=group_ids;
    er->encoded_lens=encoded_lens;
    er->encoded_keys=encoded_keys;
    /*
     * List of ciphersuites - 2 byte len + 2 bytes per ciphersuite
     * Code here inspired by ssl/ssl_lib.c:bytes_to_cipher_list
     */
    PACKET cipher_suites;
    if (!PACKET_get_length_prefixed_2(&pkt, &cipher_suites)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    int nsuites=PACKET_remaining(&cipher_suites);
    er->nsuites=nsuites/2; /* local var is #bytes */
    er->ciphersuites=OPENSSL_malloc(er->nsuites*sizeof(uint16_t));
    if (er->ciphersuites==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    if (!nsuites || (nsuites % 1)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    unsigned char cipher[TLS_CIPHER_LEN];
    int ci=0;
    while (PACKET_copy_bytes(&cipher_suites, cipher, TLS_CIPHER_LEN)) {
        er->ciphersuites[ci++]=cipher[0]*256+cipher[1];
    }
    if (PACKET_remaining(&cipher_suites) > 0) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    if (!PACKET_get_net_2(&pkt,&er->padded_length)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }

    if (er->version!=ESNI_DRAFT_04_VERSION) {
        /*
        * note: not_before/not_after checking is done elsewhere/elsewhen
        */
        unsigned char nbs[8];
        if (!PACKET_copy_bytes(&pkt,nbs,8)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->not_before=uint64_from_bytes(nbs);
        if (!PACKET_copy_bytes(&pkt,nbs,8)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->not_after=uint64_from_bytes(nbs);
    } else {
        er->not_before=ESNI_NOTATIME;
        er->not_after=ESNI_NOTATIME;
    }

    /*
     * Extensions: we'll just store 'em for now and try parse any
     * we understand a little later
     */
    PACKET exts;
    if (!PACKET_get_length_prefixed_2(&pkt, &exts)) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
        goto err;
    }
    while (PACKET_remaining(&exts) > 0) {
        er->nexts+=1;
        /*
         * a two-octet length prefixed list of:
         * two octet extension type
         * two octet extension length
         * length octets
         */
        unsigned int exttype=0;
        if (!PACKET_get_net_2(&exts,&exttype)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        unsigned int extlen=0;
        if (extlen>=ESNI_MAX_RRVALUE_LEN) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        if (!PACKET_get_net_2(&exts,&extlen)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        unsigned char *extval=NULL;
        if (extlen != 0 ) {
            extval=(unsigned char*)OPENSSL_malloc(extlen);
            if (extval==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
            if (!PACKET_copy_bytes(&exts,extval,extlen)) {
                OPENSSL_free(extval);
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
        }
        /* assign fields to lists, have to realloc */
        unsigned int *tip=(unsigned int*)OPENSSL_realloc(er->exttypes,er->nexts*sizeof(er->exttypes[0]));
        if (tip==NULL) {
            if (extval!=NULL) OPENSSL_free(extval);
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->exttypes=tip;
        er->exttypes[er->nexts-1]=exttype;
        size_t *lip=(size_t*)OPENSSL_realloc(er->extlens,er->nexts*sizeof(er->extlens[0]));
        if (lip==NULL) {
            if (extval!=NULL) OPENSSL_free(extval);
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->extlens=lip;
        er->extlens[er->nexts-1]=extlen;
        unsigned char **vip=(unsigned char**)OPENSSL_realloc(er->exts,er->nexts*sizeof(unsigned char*));
        if (vip==NULL) {
            if (extval!=NULL) OPENSSL_free(extval);
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        er->exts=vip;
        er->exts[er->nexts-1]=extval;
    }

    /*
     * Remember the offset of the start of the dns_extensions (if any)
     * so we can calculate a record_digest later (don't do now, as hash
     * alg could vary if >1 key/ciphersuite option existed here, for 
     * some silly reason)
     */
    er->dnsext_offset=binblen-PACKET_remaining(&pkt);

    /*
     * DNS Extensions: same drill - we'll just store 'em for now and try parse any
     * we understand a little later
     */
    if (er->version==ESNI_DRAFT_04_VERSION) {

        PACKET dnsexts;
        if (!PACKET_get_length_prefixed_2(&pkt, &dnsexts)) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
            goto err;
        }
        while (PACKET_remaining(&dnsexts) > 0) {
            er->dnsnexts+=1;
            /*
            * a two-octet length prefixed list of:
            * two octet extension type
            * two octet extension length
            * length octets
            */
            unsigned int dnsexttype=0;
            if (!PACKET_get_net_2(&dnsexts,&dnsexttype)) {
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
            unsigned int dnsextlen=0;
            if (dnsextlen>=ESNI_MAX_RRVALUE_LEN) {
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
            if (!PACKET_get_net_2(&dnsexts,&dnsextlen)) {
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
            unsigned char *dnsextval=NULL;
            if (dnsextlen != 0 ) {
                dnsextval=(unsigned char*)OPENSSL_malloc(dnsextlen);
                if (dnsextval==NULL) {
                    ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                    goto err;
                }
                if (!PACKET_copy_bytes(&dnsexts,dnsextval,dnsextlen)) {
                    OPENSSL_free(dnsextval);
                    ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                    goto err;
                }
            }
            /* assign fields to lists, have to realloc */
            unsigned int *dnstip=(unsigned int*)OPENSSL_realloc(er->dnsexttypes,er->dnsnexts*sizeof(er->dnsexttypes[0]));
            if (dnstip==NULL) {
                if (dnsextval!=NULL) OPENSSL_free(dnsextval);
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
            er->dnsexttypes=dnstip;
            er->dnsexttypes[er->dnsnexts-1]=dnsexttype;
            size_t *dnslip=(size_t*)OPENSSL_realloc(er->dnsextlens,er->dnsnexts*sizeof(er->dnsextlens[0]));
            if (dnslip==NULL) {
                if (dnsextval!=NULL) OPENSSL_free(dnsextval);
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
            er->dnsextlens=dnslip;
            er->dnsextlens[er->dnsnexts-1]=dnsextlen;
            unsigned char **dnsvip=(unsigned char**)OPENSSL_realloc(er->dnsexts,er->dnsnexts*sizeof(unsigned char*));
            if (dnsvip==NULL) {
                if (dnsextval!=NULL) OPENSSL_free(dnsextval);
                ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ESNI_R_RR_DECODE_ERROR);
                goto err;
            }
            er->dnsexts=dnsvip;
            er->dnsexts[er->dnsnexts-1]=dnsextval;
        }
 
    } 

    int lleftover=PACKET_remaining(&pkt);
    if (lleftover<0 || lleftover>binblen) {
        ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (er->version!=ESNI_DRAFT_04_VERSION) {
        int cksum_ok=esni_checksum_check(binbuf,binblen-lleftover);
        if (cksum_ok!=1) {
            ESNIerr(ESNI_F_SSL_ESNI_RECORD_NEW_FROM_BINARY, ERR_R_INTERNAL_ERROR);
             goto err;
        }
    }

    *leftover=lleftover;
    return er;

err:
    if (er!=NULL) {
        ESNI_RECORD_free(er);
        OPENSSL_free(er);
    }
    return NULL;
}

/**
 * @brief parse an AddressSet extension value into an SSL_ESNI structure
 *
 * @param evl is the length of the encoded extension
 * @param ev is the encoded extension value
 * @param se is the SSL_ESNI structure
 * @return 1 for ok, otherwise error
 */
static int esni_parse_address_set(size_t evl, unsigned char *ev, SSL_ESNI *se)
{
    if (evl<=4 || ev==NULL) {
        /* 
         * note this could happen as we've only done generic extension decoding so far
         */
        return(0);
    }

    int nips=0;
    BIO_ADDR *ips=NULL;
    int rv=0;
    unsigned char *evp=ev;
    while (evl>(evp-ev)) {
        /*
         * The switch statement is a bit tricksy here
         */
        int fam=AF_INET;
        int alen=4;
        switch (*evp) {
            case 0x06:
                fam=AF_INET6;
                alen=16;
            case 0x04:
                if ((evl-(evp-ev))<(alen+1)) {
                    return(0);
                }
                nips++;
                BIO_ADDR *tips=(BIO_ADDR*)OPENSSL_realloc(ips,nips*sizeof(BIO_ADDR));
                if (tips==NULL) {
                    return(0);
                }
                ips=tips;
                rv=BIO_ADDR_rawmake(&ips[nips-1],fam,evp+1,alen,0);
                if (rv!=1) {
                    return(0);
                }
                evp+=alen+1;
                break;

            default:
                return(0);
        }
    }

    /*
     * Zap any previous addrs in se
     */
    BIO_ADDR_free(se->addrs);
    /*
     * Value is a list of [0x04+4-octets|0x06+16-octets]
     */
    se->naddrs=nips;
    se->addrs=ips;
    return(1);
}

/**
 * @brief populate an SSL_ESNI from an ESNI_RECORD
 *
 * This is used by both client and server in (almost) identical ways.
 * Note that se->encoded_rr and se->encodded_rr_len must be set before
 * calling this, but that's usually fine.
 *
 * @todo TODO: handle >1 of the many things that can 
 * have >1 instance (maybe at a higher layer)
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param er is the ESNI_RECORD
 * @param se is the SSL_ESNI
 * @param server is 1 if we're a TLS server, 0 otherwise, (just in case there's a difference)
 * @return 1 for success, not 1 otherwise
 */
static int esni_make_se_from_er(SSL_CTX *ctx, SSL *con, ESNI_RECORD* er, SSL_ESNI *se, int server)
{
    unsigned char *tmp=NULL;
    size_t tlen=0;
    /* 
     * zap as needed
     */
    //SSL_ESNI_free(se);
    //memset(se,0,sizeof(*se));
    /*
     * Fixed bits of RR to use
     */
    se->version=er->version;
    se->not_before=er->not_before;
    se->not_after=er->not_after;
    se->padded_length=er->padded_length;
    if (er->public_name && er->public_name_len>0) {
        se->public_name=OPENSSL_malloc(er->public_name_len+1);
        if (se->public_name==NULL) {
            ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(se->public_name,er->public_name,er->public_name_len);
        se->public_name[er->public_name_len]='\0';
    }

    /* 
     * now decide which bits of er we like and remember those 
     * pick the 1st key/group/ciphersutie that works
     */
    int rec2pick=0;
    se->ciphersuite=er->ciphersuites[rec2pick];
    se->group_id=er->group_ids[rec2pick];
    se->esni_peer_pkey=ssl_generate_param_group(con,se->group_id);
    if (se->esni_peer_pkey==NULL) {
        ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(se->esni_peer_pkey,
                er->encoded_keys[rec2pick],er->encoded_lens[rec2pick])) {
            ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ESNI_R_RR_DECODE_ERROR);
            goto err;
    }
    tlen = EVP_PKEY_get1_tls_encodedpoint(se->esni_peer_pkey,&tmp); 
    if (tlen == 0) {
        ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* the public value goes in different places for client and server */
    if (server) {
        se->encoded_keyshare=SSL_ESNI_wrap_keyshare(tmp,tlen,se->group_id,&se->encoded_keyshare_len);
        if (se->encoded_keyshare==NULL) {
            ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        se->esni_peer_keyshare=SSL_ESNI_wrap_keyshare(tmp,tlen,se->group_id,&se->esni_peer_keyshare_len);
        if (se->esni_peer_keyshare==NULL) {
            ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    OPENSSL_free(tmp); tmp=NULL;
    const SSL_CIPHER *sc=cs2sc(se->ciphersuite);
    const EVP_MD *md=ssl_md(ctx,sc->algorithm2);
    if (er->version==ESNI_DRAFT_04_VERSION) {
        /*
         * Draft-04 changed this to exclude the dns_extensions from the 
         * hash calculation. Sadly we didn't have those in the er struct
         * ... well, not until now:-)
         */
        se->rd=esni_make_rd(se->encoded_rr,er->dnsext_offset,md,&se->rd_len);
    } else {
        se->rd=esni_make_rd(se->encoded_rr,se->encoded_rr_len,md,&se->rd_len);
    }
    if (se->rd==NULL) {
        ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Handle extensions. Initially shallow copy, maybe deeper later
     * Then when copied, parse known extensions.
     */
    if (er->nexts>0) {

        se->nexts=er->nexts;
        se->exttypes=er->exttypes;
        se->extlens=er->extlens;
        se->exts=er->exts;
        /*
         * try parse extensions we know about
         */
        if (er->version!=ESNI_DRAFT_04_VERSION) {
            int en=0;
            for (en=0;en!=se->nexts;en++) {
                if (se->exttypes[en]==ESNI_ADDRESS_SET_EXT) {
                    int rv=0;
                    rv=esni_parse_address_set(se->extlens[en],se->exts[en],se);
                    if (rv!=1) {
                        ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
                        goto err;
                    }
                }
            }
        }

    }

    /* 
     * We only did the address parsing above for draft-02/draft-03
     * and below for draft-04, so esni_parse_address_set is fine
     * to write the addrs field as that'll only happen once. If
     * someone ever wanted addresses in either place, we'd need to
     * handle that as the current code would then be leaky
     */
    if (er->version==ESNI_DRAFT_04_VERSION) {
        se->dnsnexts=er->dnsnexts;
        se->dnsexttypes=er->dnsexttypes;
        se->dnsextlens=er->dnsextlens;
        se->dnsexts=er->dnsexts;
        /*
         * try parse extensions we know about
         */
        int en=0;
        for (en=0;en!=se->dnsnexts;en++) {
            if (se->dnsexttypes[en]==ESNI_ADDRESS_SET_EXT) {
                int rv=0;
                rv=esni_parse_address_set(se->dnsextlens[en],se->dnsexts[en],se);
                if (rv!=1) {
                    ESNIerr(ESNI_F_ESNI_MAKE_SE_FROM_ER, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
            }
        }
    }
    //se->num_esni_rrs=1;
    return 1;
err:
    if (tmp!=NULL) {
        OPENSSL_free(tmp);
    }
    return 0;
}

/**
 * Try figure out ESNIKeys encodng
 *
 * @param eklen is the length of esnikeys
 * @param esnikeys is encoded ESNIKeys structure
 * @param guessedfmt is our returned guess at the format
 * @return 1 for success, 0 for error
 */
static int esni_guess_fmt(const size_t eklen, 
                    const char *esnikeys,
                    short *guessedfmt)
{
    if (!guessedfmt || eklen <=0 || !esnikeys) {
        return(0);
    }
    /* asci hex is easy:-) either case allowed*/
    const char *AH_alphabet="0123456789ABCDEFabcdef";
    /* we actually add a semi-colon here as we accept multiple semi-colon separated values */
    const char *B64_alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=;";
    /*
     * Try from most constrained to least in that order
     */
    if (eklen<=strspn(esnikeys,AH_alphabet)) {
        *guessedfmt=ESNI_RRFMT_ASCIIHEX;
    } else if (eklen<=strspn(esnikeys,B64_alphabet)) {
        *guessedfmt=ESNI_RRFMT_B64TXT;
    } else {
        // fallback - try binary
        *guessedfmt=ESNI_RRFMT_BIN;
    }
    return(1);
} 


/**
 * Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
 *
 * The esnnikeys value here may be the catenation of multiple encoded ESNIKeys RR values 
 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
 * use whichever is relevant/best. The fmt parameter can be e.g. ESNI_RRFMT_ASCII_HEX
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param ekfmt specifies the format of the input text string
 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
 * @param esnikeys is the binary, base64 or ascii-hex encoded value from DNS
 * @param num_esnis says how many SSL_ESNI structures are in the returned array
 * @return is an SSL_ESNI structure
 */
SSL_ESNI* SSL_ESNI_new_from_buffer(SSL_CTX *ctx, SSL *con, const short ekfmt, const size_t eklen, const char *esnikeys, int *num_esnis)
{
    short detfmt=ESNI_RRFMT_GUESS;
    int nlens=0;                    ///< number of values detected
    SSL_ESNI *retesnis=NULL;        ///< output array
    ESNI_RECORD *er=NULL;           ///< individual public value structure (initial decoding)
    SSL_ESNI *newesni=NULL;         ///< individual public value structure (after more decoding)
    /*
     * To keep arm build happy
     */
    int j=0;
    int i=0;

    switch (ekfmt) {
        case ESNI_RRFMT_GUESS:
            break;
        case ESNI_RRFMT_ASCIIHEX:
        case ESNI_RRFMT_B64TXT:
            detfmt=ekfmt;
            break;
        default:
            return(NULL);
    }

    if (eklen==0 || esnikeys==NULL) {
        return(NULL);
    }

    if (num_esnis==NULL) {
        return(NULL);
    }

    char *ekcpy=NULL;
    ekcpy=OPENSSL_malloc(eklen+1);
    if (ekcpy==NULL) {
        return(NULL);
    }
    memcpy(ekcpy,esnikeys,eklen);
    ekcpy[eklen]=0;

    /*
     * try decode to binary form
     */
    if (detfmt==ESNI_RRFMT_GUESS) {
        int rv=esni_guess_fmt(eklen,ekcpy,&detfmt);
        if (rv!=1) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ESNI_R_BASE64_DECODE_ERROR);
            goto err;
        }
    }

    unsigned char *outbuf = NULL;   /* a binary representation of an ESNIKeys */
    size_t declen=0;                /* a length of binary representation of an ESNIKeys */
    if (detfmt==ESNI_RRFMT_B64TXT) {
        /* need an int to get -1 return for failure case */
        int tdeclen = esni_base64_decode(ekcpy, &outbuf);
        if (tdeclen < 0) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ESNI_R_BASE64_DECODE_ERROR);
            goto err;
        }
        declen=tdeclen;
        OPENSSL_free(ekcpy);
        ekcpy=NULL;
    }

    if (detfmt==ESNI_RRFMT_ASCIIHEX) {
        /* Yay AH */
        int adr=ah_decode(eklen,ekcpy,&declen,&outbuf);
        if (adr==0) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ESNI_R_ASCIIHEX_DECODE_ERROR);
            goto err;
        }
        OPENSSL_free(ekcpy);
        ekcpy=NULL;
    }
    if (detfmt==ESNI_RRFMT_BIN) {
        /* just copy over the input to where we'd expect it */
        declen=eklen;
        outbuf=OPENSSL_malloc(declen);
        if (outbuf==NULL){
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ESNI_R_BASE64_DECODE_ERROR);
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
    while (!done) {
        nlens+=1;
        SSL_ESNI *ts=OPENSSL_realloc(retesnis,nlens*sizeof(SSL_ESNI));
        if (!ts) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        retesnis=ts;
        newesni=&retesnis[nlens-1];
        memset(newesni,0,sizeof(SSL_ESNI));
    
        int leftover=oleftover;
        er=SSL_ESNI_RECORD_new_from_binary(ctx,con,outp,oleftover,&leftover);
        //so_esni_pbuf("BINBUF:",outp,oleftover);
        if (er==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (leftover<=0) {
           done=1;
        }
        newesni->encoded_rr_len=oleftover-leftover;
        if (newesni->encoded_rr_len <=0 || newesni->encoded_rr_len>ESNI_MAX_RRVALUE_LEN) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        newesni->encoded_rr=OPENSSL_malloc(newesni->encoded_rr_len);
        if (newesni->encoded_rr==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        memcpy(newesni->encoded_rr,outp,newesni->encoded_rr_len);
        oleftover=leftover;
        outp+=newesni->encoded_rr_len;

        if (esni_make_se_from_er(ctx, con, er,newesni,0)!=1) {
            ESNIerr(ESNI_F_SSL_ESNI_NEW_FROM_BUFFER, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ESNI_RECORD_free(er);
        OPENSSL_free(er);
        er=NULL;
    }
    for (i=0;i!=nlens;i++) {
        retesnis[i].num_esni_rrs=nlens;
    }
    
    if (outbuf!=NULL) {
        OPENSSL_free(outbuf);
    }

    *num_esnis=nlens;

    return(retesnis);
err:
    /*
     * May need to fix up nlens if error happened before we normally do that
     */
    for (j=0;j!=nlens;j++) {
        retesnis[j].num_esni_rrs=nlens;
    }
    if (ekcpy!=NULL) {
        OPENSSL_free(ekcpy);
    }
    if (outbuf!=NULL) {
        OPENSSL_free(outbuf);
    }
    if (er!=NULL) {
        ESNI_RECORD_free(er);
        OPENSSL_free(er);
    }
    if (retesnis!=NULL) {
        SSL_ESNI_free(retesnis);
        OPENSSL_free(retesnis);
    }
    return(NULL);
}

/**
 * @brief print a buffer nicely
 *
 * This is used in SSL_ESNI_print
 */
static void esni_pbuf(BIO *out,char *msg,unsigned char *buf,size_t blen)
{
    if (out==NULL) {
        /*
         * Can't do much here as nowhere to print to
         */ 
        return;
    }
    if (msg==NULL) {
        BIO_printf(out,"msg is NULL\n");
        return;
    }
    if (buf==NULL) {
        BIO_printf(out,"%s: buf is NULL\n",msg);
        return;
    }
    if (blen==0) {
        BIO_printf(out,"%s: blen is zero\n",msg);
        return;
    }
    BIO_printf(out,"%s (%lu):\n    ",msg,(unsigned long)blen);
    size_t i;
    for (i=0;i<blen;i++) {
        if ((i!=0) && (i%16==0))
            BIO_printf(out,"\n    ");
        BIO_printf(out,"%02x:",buf[i]);
    }
    BIO_printf(out,"\n");
    return;
}

#ifdef ESNI_CRYPT_INTEROP
/**
 * @brief stdout version of esni_pbuf - just for odd/occasional debugging
 */
static void so_esni_pbuf(char *msg,unsigned char *buf,size_t blen) 
{
    if (buf==NULL) {
        printf("so: %s is NULL\n",msg);
        return;
    }
    printf("so: %s (%lu):\n    ",msg,(unsigned long)blen);
    int i;
    for (i=0;i!=blen;i++) {
        if ((i!=0) && (i%16==0))
            printf("\n    ");
        printf("%02x:",buf[i]);
    }
    printf("\n");
    return;
}
#endif

/**
 * @brief Print out an array of SSL_ESNI structures 
 *
 * This is called via callback
 *
 * @param out is the BIO* 
 * @param esniarr is an array of SSL_ESNI structures
 * @return 1 is good
 */
int SSL_ESNI_print(BIO* out, SSL_ESNI *esniarr, int selector)
{
    SSL_ESNI *esni=NULL;
    int nesnis=0;
    if (esniarr==NULL) {
        BIO_printf(out,"ESNI is NULL!\n");
        return 0;
    }

    /*
     * Check selector is reasonable
     */
    nesnis=esniarr->num_esni_rrs;
    if (nesnis==0) {
        BIO_printf(out,"ESNI Array has no RRs, assuming just one array element.\n");
        nesnis=1;
    } else {
        if (selector!=ESNI_SELECT_ALL) {
            BIO_printf(out,"ESNI Array has %d RRs, printing the %d-th.\n",nesnis,selector);
        } else {
            BIO_printf(out,"ESNI Array has %d RRs, printing all of 'em.\n",nesnis);
        }
    }
    if (selector!=ESNI_SELECT_ALL) {
        if (selector < 0 || selector >=nesnis) {
            BIO_printf(out,"SSL_ESNI_print error- selector (%d) out of range (%d)\n",selector,nesnis);
            return 0;
        } else {
            BIO_printf(out,"ESNI Array has %d RRs, printing the %d-th.\n",nesnis,selector);
        }
    }

    int bf=BIO_flush(out);
    if (bf!=1) {
        /*
         * not much point trying to write out an error I guess, could make things
         * worse, but we'll give it one more shot.
         */
        BIO_printf(out,"BIO_flush returned %d - things may get dodgy!\n",bf);
    }

    int i=0;
    for (i=0;i!=nesnis;i++) {

        if (selector!=ESNI_SELECT_ALL && selector != i) {
            continue;
        }

        esni=&esniarr[i];

        BIO_printf(out,"\nPrinting SSL_ESNI structure number %d of %d\n",i+1,nesnis);
        if (esni->version==ESNI_GREASE_VERSION) {
            BIO_printf(out,"ESNI Version is GREASE!: %x\n",esni->version);
        } else {
            BIO_printf(out,"ESNI Version: %x\n",esni->version);
        }

        if (esni->encoded_rr==NULL) {
            BIO_printf(out,"ESNI has no RRs!\n");
        } 
        // carefully print these - might be attack content
        if (esni->encservername==NULL) {
            BIO_printf(out, "ESNI encservername is NULL\n");
        } else {
            BIO_printf(out, "ESNI encservername: \"");
            const char *cp=esni->encservername;
            unsigned char uc;
            while ((uc = *cp++) != 0)
                BIO_printf(out, isascii(uc) && isprint(uc) ? "%c" : "\\x%02x", uc);
            BIO_printf(out, "\"\n");
        }
        if (esni->clear_sni==NULL) {
            BIO_printf(out, "ESNI clear sni is NULL\n");
        } else {
            BIO_printf(out, "ESNI clear sni: \"");
            const char *cp=esni->clear_sni;
            unsigned char uc;
            while ((uc = *cp++) != 0)
                BIO_printf(out, isascii(uc) && isprint(uc) ? "%c" : "\\x%02x", uc);
            BIO_printf(out, "\"\n");
        }
        if (esni->public_name==NULL) {
            BIO_printf(out, "ESNI public_name is NULL\n");
        } else {
            BIO_printf(out, "ESNI public_name: \"");
            const char *cp=esni->public_name;
            unsigned char uc;
            while ((uc = *cp++) != 0)
                BIO_printf(out, isascii(uc) && isprint(uc) ? "%c" : "\\x%02x", uc);
            BIO_printf(out, "\"\n");
        }

        esni_pbuf(out,"ESNI Encoded ESNIRecord RR",esni->encoded_rr,esni->encoded_rr_len);
        esni_pbuf(out,"ESNI ESNIKeys record_digest", esni->rd,esni->rd_len);
        esni_pbuf(out,"ESNI Peer KeyShare:",esni->esni_peer_keyshare,esni->esni_peer_keyshare_len);
        BIO_printf(out,"ESNI Server groupd Id: %04x\n",esni->group_id);
        BIO_printf(out,"ENSI Server Ciphersuite is %04x\n",esni->ciphersuite);
        BIO_printf(out,"ESNI Server padded_length: %lu\n",(unsigned long)esni->padded_length);
        if (esni->not_before==ESNI_NOTATIME) {
            BIO_printf(out,"ESNI Server not_before: unset\n");
        } else {
            BIO_printf(out,"ESNI Server not_before: %ju\n",esni->not_before);
        }
        if (esni->not_after==ESNI_NOTATIME) {
            BIO_printf(out,"ESNI Server not_after: unset\n");
        } else {
            BIO_printf(out,"ESNI Server not_after: %ju\n",esni->not_after);
        }

        if (esni->nexts!=0) {
            int j=0;
            BIO_printf(out,"ESNI Server number of extensions: %d\n",esni->nexts);
            for (j=0;j!=esni->nexts;j++) {
                BIO_printf(out,"ESNI Extension type %d\n",esni->exttypes[j]);
                esni_pbuf(out,"ESNI Extension value",esni->exts[j],esni->extlens[j]);
            }
        } else {
            BIO_printf(out,"ESNI no extensions\n");
        }

        if (esni->dnsnexts!=0) {
            int j=0;
            BIO_printf(out,"ESNI Server number of DNS extensions: %d\n",esni->dnsnexts);
            for (j=0;j!=esni->dnsnexts;j++) {
                BIO_printf(out,"ESNI DNS Extension type %d\n",esni->dnsexttypes[j]);
                esni_pbuf(out,"ESNI DNS Extension value",esni->dnsexts[j],esni->dnsextlens[j]);
            }
        } else {
            BIO_printf(out,"ESNI no DNS extensions\n");
        }

        if (esni->naddrs!=0) {
            int j=0;
            BIO_printf(out,"ESNI Addresses\n");
            for (j=0;j!=esni->naddrs;j++) {
                char *foo= BIO_ADDR_hostname_string(&esni->addrs[j], 1);
                BIO_printf(out,"\tAddress(%d): %s\n",j,foo);
                OPENSSL_free(foo);
            }
        } else {
            BIO_printf(out,"ESNI no addresses\n");
        }
        if (esni->crypto_started==0) {
            BIO_printf(out,"ESNI crypto wasn't yet started\n");
        } else {
            BIO_printf(out,"ESNI crypto was started (%d)\n",esni->crypto_started);
        }
        BIO_printf(out,"ESNI HRR or not (%d)\n",esni->hrr_swap);
        esni_pbuf(out,"ESNI Nonce",esni->nonce,esni->nonce_len);
        esni_pbuf(out,"ESNI H/S Client Random",esni->hs_cr,esni->hs_cr_len);
        esni_pbuf(out,"ESNI H/S Client KeyShare",esni->hs_kse,esni->hs_kse_len);
        if (esni->keyshare!=NULL) {
            BIO_printf(out,"ESNI Client ESNI KeyShare: ");
            EVP_PKEY_print_public(out, esni->keyshare, 0, NULL);
        } else {
            BIO_printf(out,"ESNI Client ESNI KeyShare is NULL\n");
        }
        esni_pbuf(out,"ESNI Encoded ESNIContents (hash input)",esni->hi,esni->hi_len);
        esni_pbuf(out,"ESNI Encoded ESNIContents (hash output)",esni->hash,esni->hash_len);
        esni_pbuf(out,"ESNI Padded SNI",esni->realSNI, esni->realSNI_len);
        BIO_printf(out,"ESNI Cryptovars group id: %04x\n",esni->group_id);
        esni_pbuf(out,"ESNI Cryptovars Z",esni->Z,esni->Z_len);
        esni_pbuf(out,"ESNI Cryptovars Zx",esni->Zx,esni->Zx_len);
        esni_pbuf(out,"ESNI Cryptovars key",esni->key,esni->key_len);
        esni_pbuf(out,"ESNI Cryptovars iv",esni->iv,esni->iv_len);
        esni_pbuf(out,"ESNI Cryptovars aad",esni->aad,esni->aad_len);
        esni_pbuf(out,"ESNI Cryptovars plain",esni->plain,esni->plain_len);
        esni_pbuf(out,"ESNI Cryptovars tag",esni->tag,esni->tag_len);
        esni_pbuf(out,"ESNI Cryptovars cipher",esni->cipher,esni->cipher_len);
        if (esni->the_esni) {
            BIO_printf(out,"ESNI CLIENT_ESNI structure (repetitive on client):\n");
            BIO_printf(out,"CLIENT_ESNI Ciphersuite is %04x\n",esni->the_esni->ciphersuite);
            esni_pbuf(out,"CLIENT_ESNI encoded_keyshare",esni->the_esni->encoded_keyshare,esni->the_esni->encoded_keyshare_len);
            esni_pbuf(out,"CLIENT_ESNI record_digest",esni->the_esni->record_digest,esni->the_esni->record_digest_len);
            esni_pbuf(out,"CLIENT_ESNI encrypted_sni",esni->the_esni->encrypted_sni,esni->the_esni->encrypted_sni_len);
        } else {
            BIO_printf(out,"ESNI CLIENT_ESNI is NULL\n");
        }
        if (esni->privfname!=NULL) {
            BIO_printf(out,"ESNI private key file name: %s\n",esni->privfname);
        } else {
            BIO_printf(out,"ESNI private key file not set\n");
        }
        if (esni->pubfname!=NULL) {
            BIO_printf(out,"ESNI public key file name: %s\n",esni->pubfname);
        } else {
            BIO_printf(out,"ESNI public key file not set\n");
        }
        BIO_printf(out,"ESNI key pair load time: %lu\n",esni->loadtime);
    }

    bf=BIO_flush(out);
    if (bf!=1) {
        /*
         * not much point trying to write out an error I guess, could make things
         * worse, but we'll give it one more shot.
         */
        BIO_printf(out,"BIO_flush returned %d - things may get dodgy!\n",bf);
    }
    return(1);
}

/**
 * @brief Make a 16 octet nonce for ESNI
 */
static unsigned char *esni_nonce(size_t nl)
{
#ifdef ESNI_CRYPT_INTEROP
    if (lg_nonce_len==0) {
        unsigned char *ln=OPENSSL_malloc(nl);
        RAND_bytes(ln,nl);
        return ln;
    } else {
        // hope nl <= lg_nonce_len :-)
        unsigned char *ln=OPENSSL_malloc(nl);
        memset(ln,0,nl);
        memcpy(ln,lg_nonce,lg_nonce_len);
        return ln;
    }
#else
    unsigned char *ln=OPENSSL_malloc(nl);
    RAND_bytes(ln,nl);
    return ln;
#endif
}

/**
 * @brief Pad an SNI before encryption with zeros on the right to the required length
 */
static unsigned char *esni_pad(char *name, unsigned int padded_len, int version)
{
    /*
     * usual function is statem/extensions_clnt.c:tls_construct_ctos_server_name
     * encoding is 2 byte overall length, 0x00 for hostname, 2 byte length of name, name
     */
    size_t nl=OPENSSL_strnlen(name,padded_len);
    size_t oh=5; /* total encoding overhead */
    if (version==ESNI_DRAFT_04_VERSION) {
        oh=2;
    } 
    if ((nl+oh)>=padded_len) return(NULL);
    unsigned char *buf=OPENSSL_malloc(padded_len);
    memset(buf,0,padded_len);
    if (version!=ESNI_DRAFT_04_VERSION) {
        buf[0]=((nl+oh-2)/256);
        buf[1]=((nl+oh-2)%256);
        buf[2]=0x00;
        buf[3]=(nl/256);
        buf[4]=(nl%256);
        memcpy(buf+5,name,nl);
    } else {
        buf[0]=(nl/256);
        buf[1]=(nl%256);
        memcpy(buf+2,name,nl);
    }
    return buf;
}

/**
 * @brief Local wrapper for HKDF-Extract(salt,IVM)=HMAC-Hash(salt,IKM) according to RFC5689
 *
 */
static unsigned char *esni_hkdf_extract(unsigned char *secret,size_t slen,size_t *olen, const EVP_MD *md)
{
    int ret=1;
    unsigned char *outsecret=NULL;
    size_t tmpolen=0;
    if (secret==NULL || olen == NULL || md==NULL ) {
        return NULL;
    }
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx==NULL) {
        return NULL;
    }
    ret = EVP_PKEY_derive_init(pctx);
    if (ret==1) 
        ret=EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY);
    if (ret==1) 
        ret=EVP_PKEY_CTX_set_hkdf_md(pctx, md);
    if (ret==1) 
        ret=EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, slen);
    if (ret==1) 
        ret=EVP_PKEY_CTX_set1_hkdf_salt(pctx, NULL, 0);
    if (ret!=1)
        return NULL;

    /*
     * TODO: The EVP_MAX_MD_SIZE here may not be generally correct, 
     * so could check what's better...
     */
    //tmpolen=EVP_MAX_MD_SIZE; 
    tmpolen = EVP_MD_size(md);
    outsecret=OPENSSL_zalloc(tmpolen);
    if (outsecret==NULL) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if (ret==1) 
        ret=EVP_PKEY_derive(pctx, outsecret, &tmpolen);

    EVP_PKEY_CTX_free(pctx);

    if (ret!=1) {
        OPENSSL_free(outsecret);
        return NULL;
    }
    *olen=tmpolen;
    return outsecret;
}


/**
 * @brief expand a label as per the I-D
 *
 * @todo TODO: this and esni_hkdf_extract should be better integrated
 * There are functions that can do this that require an ```SSL *s```
 * input and we should move to use those.
 */
static unsigned char *esni_hkdf_expand_label(
            SSL *s,
            unsigned char *Zx, size_t Zx_len,
            const char *label,
            unsigned char *hash, size_t hash_len,
            size_t *expanded_len,
            const EVP_MD *md)
{
    /*
     * This is a "dummy" SSL structure - the implementation of
     * tls13_hkdf_expand doesn't even refer to s except for an
     * error
     */
    unsigned char *out=OPENSSL_malloc(*expanded_len);
    int rv=tls13_hkdf_expand(s, md, Zx, 
                            (const unsigned char*)label, strlen(label),
                            hash, hash_len,
                            out, *expanded_len,0);
    if (rv!=1) {
        return NULL;
    }
    return out;
}

/**
 * @brief do the AEAD encryption as per the I-D
 *
 * Note: The tag output isn't really needed but was useful when I got
 * the aad wrong at one stage to keep it for now.
 * Most parameters obvious but...
 *
 * @param cipher_Len is an output
 * @returns NULL (on error) or pointer to alloced buffer for ciphertext
 */
static unsigned char *esni_aead_enc(
            unsigned char *key, size_t key_len,
            unsigned char *iv, size_t iv_len,
            unsigned char *aad, size_t aad_len,
            unsigned char *plain, size_t plain_len,
            unsigned char *tag, size_t tag_len, 
            size_t *cipher_len,
            uint16_t ciph)
{
    /*
     * From https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
     */
    EVP_CIPHER_CTX *ctx=NULL;
    int len;
    size_t ciphertext_len;
    unsigned char *ciphertext=NULL;

    const SSL_CIPHER *sc=cs2sc(ciph);
    if (sc==NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (SSL_CIPHER_is_aead(sc)!=1) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * We'll allocate this much extra for ciphertext and check the AEAD doesn't require more
     * If it does, we'll fail.
     */
    size_t alloced_oh=64;

    if (tag_len > alloced_oh) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ciphertext=OPENSSL_malloc(plain_len+alloced_oh);
    if (ciphertext==NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc=EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(sc));
    if (enc == NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if(1 != EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))  {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plain_len)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))  {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    ciphertext_len += len;

    /*
     * Get the tag
     * This isn't a duplicate so needs to be added to the ciphertext
     *
     * So I had a problem with this code when built with optimisation
     * turned on ("-O3" or even "-g -O1" when I manually edited the
     * Makefile). Valgrind reports use of uninitialised memory
     * related to the tag (when it was later printed in SSL_ESNI_print).
     * When I was just passing in the tag directly, I got a couple
     * of valgrind errors from within SSL_ESNI_print and then loads
     * (>1000) other uninitialised memory errors later on from all
     * sorts of places in code I've not touched for ESNI.
     * For now, building with "no-asm" is a workaround that works
     * around:-)
     * I mailed the openssl-users list:
     * https://mta.openssl.org/pipermail/openssl-users/2019-November/011503.html
     * TODO(ESNI): follow up on this
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag)) {
        ESNIerr(ESNI_F_ESNI_AEAD_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(ciphertext+ciphertext_len,tag,tag_len);
    ciphertext_len += tag_len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    *cipher_len=ciphertext_len;

    return ciphertext;

err:
    EVP_CIPHER_CTX_free(ctx);
    if (ciphertext!=NULL) OPENSSL_free(ciphertext);
    return NULL;
}

/**
 * @brief do the AEAD decryption as per the I-D
 *
 * Note: The tag output isn't really needed but was useful when I got
 * the aad wrong at one stage to keep it for now.
 * @param cipher_Len is an output
 * @returns NULL (on error) or pointer to alloced buffer for plaintext
 */
static unsigned char *esni_aead_dec(
            unsigned char *key, size_t key_len,
            unsigned char *iv, size_t iv_len,
            unsigned char *aad, size_t aad_len,
            unsigned char *cipher, size_t cipher_len,
            size_t *plain_len,
            uint16_t ciph)
{
    ENTRY_TRACE;
    /*
     * From https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
     */
    EVP_CIPHER_CTX *ctx=NULL;
    int len=0;
    size_t plaintext_len=0;
    unsigned char *plaintext=NULL;
    const SSL_CIPHER *sc=cs2sc(ciph);
    if (SSL_CIPHER_is_aead(sc)!=1) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    /*
     * We'll allocate this much extra for plaintext and check the AEAD doesn't require more later
     * If it does, we'll fail.
     */
    size_t alloced_oh=64;
    plaintext=OPENSSL_malloc(cipher_len+alloced_oh);
    if (plaintext==NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    /* Initialise the encryption operation. */
    const EVP_CIPHER *enc=EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(sc));
    if (enc == NULL) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if(1 != EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))  {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, cipher, cipher_len-16)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, cipher+cipher_len-16)) {
        ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }

    /* 
     * Finalise the decryption. 
     */
    int decrypt_res=EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if(decrypt_res<=0)  {
        /*
         * No longer print an error, as a) an attacker could cause
         * that to be generated and b) now we're allowing trial 
         * decryption, this could be v. common and hence misleading
         * ESNIerr(ESNI_F_ESNI_AEAD_DEC, ERR_R_INTERNAL_ERROR);
         */
        EXIT_TRACE;
        goto err;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    *plain_len=plaintext_len;
    EXIT_TRACE;
    return plaintext;
err:
    EVP_CIPHER_CTX_free(ctx);
    if (plaintext!=NULL) OPENSSL_free(plaintext);
    EXIT_TRACE;
    return NULL;
}

/**
 * @brief given an SSL_ESNI create ESNIContent and hash that
 *
 * encode up TLS client's ESNI public keyshare (in a different
 * part of the SSL_ESNI for client and server) and other parts
 * of ESNIContents, and hash those
 *
 * @param ctx is the parent SSL_CTX
 * @param esni is the SSL_ESNI structure 
 * @param server is 1 if on the server, 0 for client
 * @return 1 for success, other otherwise
 */
static int makeesnicontenthash(SSL_CTX *ctx, SSL_ESNI *esnikeys,
                    int server)
{
    unsigned char *tmp=NULL;
    size_t tlen=0;
    size_t kslen=0;
    EVP_MD_CTX *mctx = NULL;

    if (esnikeys==NULL) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (server && esnikeys->the_esni==NULL) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!server) {
        tlen = EVP_PKEY_get1_tls_encodedpoint(esnikeys->keyshare,&tmp); 
        if (tlen == 0) {
            ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        esnikeys->encoded_keyshare=SSL_ESNI_wrap_keyshare(tmp,tlen,esnikeys->group_id,&esnikeys->encoded_keyshare_len);
        if (esnikeys->encoded_keyshare==NULL) {
            ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        OPENSSL_free(tmp); tmp=NULL;
        kslen=esnikeys->encoded_keyshare_len;
    } else {
        kslen=esnikeys->the_esni->encoded_keyshare_len;
    }
    // drop top two bytes from this version of encoded_keyshare (sigh!)
    esnikeys->hi_len=2+esnikeys->rd_len+kslen-2+esnikeys->hs_cr_len;
    if (esnikeys->hi!=NULL) OPENSSL_free(esnikeys->hi);
    esnikeys->hi=OPENSSL_malloc(esnikeys->hi_len);
    if (esnikeys->hi==NULL) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    unsigned char *ecp=esnikeys->hi;
    *ecp++=esnikeys->rd_len/256;
    *ecp++=esnikeys->rd_len%256;
    memcpy(ecp,esnikeys->rd,esnikeys->rd_len);ecp+=esnikeys->rd_len;
    if (!server) {
        memcpy(ecp,esnikeys->encoded_keyshare+2,esnikeys->encoded_keyshare_len-2);ecp+=esnikeys->encoded_keyshare_len-2;
    } else {
        memcpy(ecp,esnikeys->the_esni->encoded_keyshare+2,esnikeys->the_esni->encoded_keyshare_len-2);
        ecp+=esnikeys->the_esni->encoded_keyshare_len-2;
    }
    memcpy(ecp,esnikeys->hs_cr,esnikeys->hs_cr_len);ecp+=esnikeys->hs_cr_len;

    /*
     * now hash it
     */
    const SSL_CIPHER *sc=cs2sc(esnikeys->ciphersuite);
    const EVP_MD *md=ssl_md(ctx,sc->algorithm2);
    mctx = EVP_MD_CTX_new();
    esnikeys->hash_len = EVP_MD_size(md);
    if (esnikeys->hash!=NULL) OPENSSL_free(esnikeys->hash);
    esnikeys->hash=OPENSSL_malloc(esnikeys->hash_len);
    if (esnikeys->hash==NULL) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (mctx == NULL
            || EVP_DigestInit_ex(mctx, md, NULL) <= 0
            || EVP_DigestUpdate(mctx, esnikeys->hi, esnikeys->hi_len) <= 0
            || EVP_DigestFinal_ex(mctx, esnikeys->hash, NULL) <= 0) {
        ESNIerr(ESNI_F_MAKEESNICONTENTHASH, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_MD_CTX_free(mctx);
    return 1;
err:
    if (mctx!=NULL) EVP_MD_CTX_free(mctx);
    if (tmp!=NULL) OPENSSL_free(tmp);
    return 0;
}

/**
 * @brief from Zx and ESNIContent, derive key, iv and aad
 * 
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param esni is the SSL_ESNI structure
 * @return 1 for success, other otherwise
 */
static int esni_key_derivation(SSL_CTX *ctx, SSL *con, SSL_ESNI *esnikeys)
{

    /* prepare nid and EVP versions for later checks */
    uint16_t cipher_nid = esnikeys->ciphersuite;
    const SSL_CIPHER *sc=cs2sc(cipher_nid);
    const EVP_MD *md=ssl_md(ctx,sc->algorithm2);
    const EVP_CIPHER *e_ciph=EVP_get_cipherbynid(SSL_CIPHER_get_cipher_nid(sc));
    if (e_ciph==NULL) {
        ESNIerr(ESNI_F_ESNI_KEY_DERIVATION, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
    * TODO(ESNI): test label swapping when handling HRR - the 2nd time the
    * labels should go from "esni key" to "hrr esni key" and "esni iv" to
    * "hrr esni iv"
    * I suspect this crypto primitive will switch to use of
    * whatever ends up from https://tools.ietf.org/html/draft-barnes-cfrg-hpke
    */
    const char *initkey="esni key";
    const char *initiv="esni iv";
    const char *hrrkey="hrr esni key";
    const char *hrriv="hrr esni iv";
    const char *ks2use=initkey;
    const char *iv2use=initiv;
    if (esnikeys->hrr_swap!=0 && esnikeys->version==ESNI_DRAFT_04_VERSION) {
        ks2use=hrrkey;
        iv2use=hrriv;
    }
    esnikeys->key_len=EVP_CIPHER_key_length(e_ciph);
    if (esnikeys->key!=NULL) OPENSSL_free(esnikeys->key);
    esnikeys->key=esni_hkdf_expand_label(con,esnikeys->Zx,esnikeys->Zx_len,ks2use,
                esnikeys->hash,esnikeys->hash_len,&esnikeys->key_len,md);
    if (esnikeys->key==NULL) {
        ESNIerr(ESNI_F_ESNI_KEY_DERIVATION, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->iv_len=EVP_CIPHER_iv_length(e_ciph);
    if (esnikeys->iv!=NULL) OPENSSL_free(esnikeys->iv);
    esnikeys->iv=esni_hkdf_expand_label(con,esnikeys->Zx,esnikeys->Zx_len,iv2use,
                    esnikeys->hash,esnikeys->hash_len,&esnikeys->iv_len,md);
    if (esnikeys->iv==NULL) {
        ESNIerr(ESNI_F_ESNI_KEY_DERIVATION, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (esnikeys->aad!=NULL) OPENSSL_free(esnikeys->aad);
    esnikeys->aad=OPENSSL_malloc(esnikeys->hs_kse_len);
    if (esnikeys->aad == NULL) {
        ESNIerr(ESNI_F_ESNI_KEY_DERIVATION, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memcpy(esnikeys->aad,esnikeys->hs_kse,esnikeys->hs_kse_len);
    esnikeys->aad_len=esnikeys->hs_kse_len;
    return 1;
err:
    return 0;
}

/**
 * @brief Do the client-side SNI encryption during a TLS handshake
 *
 * This is an internal API called as part of the state machine
 * dealing with this extension.
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param esnikeys_in is an array of SSL_ESNI structures:w
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return 1 for success, other otherwise
 */
int SSL_ESNI_enc(SSL_CTX *ctx, 
            SSL *con,
            SSL_ESNI *esnikeys_in, 
            size_t  client_random_len,
            unsigned char *client_random,
            uint16_t curve_id,
            size_t  client_keyshare_len,
            unsigned char *client_keyshare,
            CLIENT_ESNI **the_esni)
{
    
    /* 
     * First, we'll pick which public key to use
     *
     * First cut - pick first one with hrr_swap set in case
     * we're dealing with an HRR
     */
    int i;
    int latestindex=0;
    for (i=0;i!=esnikeys_in->num_esni_rrs;i++) {
        if (esnikeys_in[i].hrr_swap!=0) {
            latestindex=i;
        }
    }
    
    SSL_ESNI *esnikeys=&esnikeys_in[latestindex];
    
    /*
     * Now mark that one as having been touched
     */
    esnikeys->crypto_started=1;
    
    /* 
     * encrypt the actual SNI based on shared key, Z - the I-D says:
     *    Zx = HKDF-Extract(0, Z)
     *    key = HKDF-Expand-Label(Zx, "esni key", Hash(ESNIContents), key_length)
     *    iv = HKDF-Expand-Label(Zx, "esni iv", Hash(ESNIContents), iv_length)
     *
     *    struct {
     *        opaque record_digest<0..2^16-1>;
     *        KeyShareEntry esni_key_share;
     *        Random client_hello_random;
     *    } ESNIContents;
     *
     */
    EVP_PKEY_CTX *pctx=NULL;
    
    /*
     * checking and copying
     */
    
    if (esnikeys==NULL || esnikeys->esni_peer_pkey==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (esnikeys->hs_cr==NULL) {
        esnikeys->hs_cr_len=client_random_len;
        esnikeys->hs_cr=OPENSSL_malloc(esnikeys->hs_cr_len);
        if (esnikeys->hs_cr == NULL ) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(esnikeys->hs_cr,client_random,esnikeys->hs_cr_len);
    }
    if (esnikeys->encservername==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * There is no point in doing this if SNI and ESNI payloads
     * are the same!!!
     */
    if (esnikeys->clear_sni!=NULL && esnikeys->encservername!=NULL) {
        if (OPENSSL_strnlen(esnikeys->clear_sni,TLSEXT_MAXLEN_host_name)==
            OPENSSL_strnlen(esnikeys->encservername,TLSEXT_MAXLEN_host_name)) {
            if (!CRYPTO_memcmp(esnikeys->clear_sni,esnikeys->encservername,
                OPENSSL_strnlen(esnikeys->clear_sni,TLSEXT_MAXLEN_host_name))) {
                /*
                 * Shit - same names, that's silly
                 */
                ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    if (esnikeys->public_name!=NULL && esnikeys->encservername!=NULL) {
        if (OPENSSL_strnlen(esnikeys->public_name,TLSEXT_MAXLEN_host_name)==
            OPENSSL_strnlen(esnikeys->encservername,TLSEXT_MAXLEN_host_name)) {
            if (!CRYPTO_memcmp(esnikeys->public_name,esnikeys->encservername,
                OPENSSL_strnlen(esnikeys->public_name,TLSEXT_MAXLEN_host_name))) {
                /*
                 * Shit - same names, that's silly
                 */
                ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
    }
    
    #define FANDZ(x) { if (x!=NULL) OPENSSL_free(x); x=NULL; x##_len=0; }
    
    if (esnikeys->hrr_swap==1) {
        /*
         * Free up old stuff
         */
        if (esnikeys->keyshare) {
            EVP_PKEY_free(esnikeys->keyshare);
            esnikeys->keyshare=NULL;
        }
        FANDZ(esnikeys->encoded_keyshare);
        FANDZ(esnikeys->hi);
        FANDZ(esnikeys->hash);
        FANDZ(esnikeys->realSNI);
        FANDZ(esnikeys->hs_kse);
        FANDZ(esnikeys->Z);
        FANDZ(esnikeys->Zx);
        FANDZ(esnikeys->key);
        FANDZ(esnikeys->iv);
        FANDZ(esnikeys->aad);
        FANDZ(esnikeys->cipher);
        FANDZ(esnikeys->plain);
        FANDZ(esnikeys->tag);
    }
    
    if (esnikeys->hs_kse==NULL) {
        esnikeys->hs_kse=OPENSSL_malloc(client_keyshare_len);
        if (esnikeys->hs_kse==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        memcpy(esnikeys->hs_kse,client_keyshare,client_keyshare_len);
        esnikeys->hs_kse_len=client_keyshare_len;
    }
    
    /*
     * - make my private key
     * - generate shared secret
     * - encrypt encservername
     * - encode packet and return
     */
    
#ifdef ESNI_CRYPT_INTEROP
    
    if (esnikeys->private_str==NULL) {
        esnikeys->keyshare = ssl_generate_pkey(con,esnikeys->esni_peer_pkey);
        if (esnikeys->keyshare == NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        /*
         * fixed sizes are ok here - it's just for NSS interop
         */
        int i; /* loop counter - android build doesn't like C99;-( */
        unsigned char binpriv[64];
        size_t bp_len=32;
        for (i=0;i!=32;i++) {
            binpriv[i]=ESNI_A2B(esnikeys->private_str[2*i])*16+ESNI_A2B(esnikeys->private_str[(2*i)+1]);
        }
        so_esni_pbuf("CRYPTO_INTEROP  private",binpriv,bp_len);
    
        /*
         * Group number is in 3rd & 4th octets kse
         * int foo=EVP_PKEY_X25519;
         */
        if (client_keyshare_len < 3) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        int foo=client_keyshare[3];
        foo += ((client_keyshare[2]&0xff)<<8);
        esnikeys->keyshare=EVP_PKEY_new_raw_private_key(foo,NULL,binpriv,bp_len);
        if (esnikeys->keyshare == NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
#else
    // random new private
    if (esnikeys->hrr_swap==1 && esnikeys->keyshare==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    } else {
        esnikeys->keyshare = ssl_generate_pkey(ctx,esnikeys->esni_peer_pkey);
        if (esnikeys->keyshare == NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
#endif
    
    /* generate new values */
    pctx = EVP_PKEY_CTX_new(esnikeys->keyshare,NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, esnikeys->esni_peer_pkey) <= 0 ) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &esnikeys->Z_len) <= 0) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->Z=OPENSSL_malloc(esnikeys->Z_len);
    if (esnikeys->Z == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_derive(pctx, esnikeys->Z, &esnikeys->Z_len) <= 0) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    
    if (makeesnicontenthash(ctx,esnikeys,0)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    
    /*
     * Form up the inner SNI stuff
     * I don't think the draft-04 change from ServerNameList to opaque
     * has any effect here as we only support one name anyway
     */
    esnikeys->realSNI_len=esnikeys->padded_length;
    esnikeys->realSNI=esni_pad(esnikeys->encservername,esnikeys->realSNI_len,esnikeys->version);
    if (esnikeys->realSNI==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (esnikeys->nonce==NULL) {
        esnikeys->nonce_len=16;
        esnikeys->nonce=esni_nonce(esnikeys->nonce_len);
        if (!esnikeys->nonce) {
            ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    
    /*
     * encode into our plaintext
     */
    esnikeys->plain_len=esnikeys->nonce_len+esnikeys->realSNI_len;
    esnikeys->plain=OPENSSL_malloc(esnikeys->plain_len);
    if (esnikeys->plain == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    unsigned char *pip=esnikeys->plain;
    memcpy(pip,esnikeys->nonce,esnikeys->nonce_len); pip+=esnikeys->nonce_len;
    memcpy(pip,esnikeys->realSNI,esnikeys->realSNI_len); pip+=esnikeys->realSNI_len;
    
    /*
     * Derive key and encrypt
     * encrypt the actual SNI based on shared key, Z - the I-D says:
     *    Zx = HKDF-Extract(0, Z)
     *    key = HKDF-Expand-Label(Zx, "esni key", Hash(ESNIContents), key_length)
     *    iv = HKDF-Expand-Label(Zx, "esni iv", Hash(ESNIContents), iv_length)
     */
    const SSL_CIPHER *sc=cs2sc(esnikeys->ciphersuite);
    const EVP_MD *md=ssl_md(ctx,sc->algorithm2);
    if (md==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    esnikeys->Zx_len=0;
    esnikeys->Zx=esni_hkdf_extract(esnikeys->Z,esnikeys->Z_len,&esnikeys->Zx_len,md);
    if (esnikeys->Zx==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    
    /* 
     * derive key and iv length from suite
     */
    if (esni_key_derivation(ctx,con,esnikeys)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    
    
    /*
     * The actual encryption... from the I-D:
     *     encrypted_sni = AEAD-Encrypt(key, iv, ClientHello.KeyShareClientHello, ClientESNIInner)
     */
    
    /*
     * Tag is in ciphertext anyway, but sure may as well keep it
     */
    esnikeys->tag_len=EVP_GCM_TLS_TAG_LEN;
    esnikeys->tag=OPENSSL_malloc(esnikeys->tag_len);
    if (esnikeys->tag == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memset(esnikeys->tag,0,esnikeys->tag_len);
    
    esnikeys->cipher=esni_aead_enc(esnikeys->key, esnikeys->key_len,
            esnikeys->iv, esnikeys->iv_len,
            esnikeys->aad, esnikeys->aad_len,
            esnikeys->plain, esnikeys->plain_len,
            esnikeys->tag, esnikeys->tag_len,
            &esnikeys->cipher_len,
            esnikeys->ciphersuite);
    if (esnikeys->cipher==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    
    if (esnikeys->cipher_len>SSL_MAX_SSL_ENCRYPTED_SNI_LENGTH) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx=NULL;
    
    /* 
     * finish up
     */
    
    if (esnikeys->hrr_swap!=0 && esnikeys->the_esni!=NULL) {
        OPENSSL_free(esnikeys->the_esni);
        esnikeys->the_esni=NULL;
    }
    CLIENT_ESNI *tc=OPENSSL_malloc(sizeof(CLIENT_ESNI));
    if (tc==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_ENC, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memset(tc,0,sizeof(CLIENT_ESNI));
    tc->ciphersuite=esnikeys->ciphersuite;
    tc->encoded_keyshare=esnikeys->encoded_keyshare;
    tc->encoded_keyshare_len=esnikeys->encoded_keyshare_len;
    tc->record_digest=esnikeys->rd;
    tc->record_digest_len=esnikeys->rd_len;
    tc->encrypted_sni=esnikeys->cipher;
    tc->encrypted_sni_len=esnikeys->cipher_len;
    *the_esni=tc;
    esnikeys->the_esni=tc;
    return 1;
err:
    /*
     * Everything else should be pointed to via esnikeys, and should
     * be freed elsewhen, so this is all we need to explictly handle
     */
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    return 0;
}

/**
 * @brief Attempt/do the serveri-side decryption during a TLS handshake
 *
 * This is the internal API called as part of the state machine
 * dealing with this extension.
 * 
 * Note that the decrypted server name is just a set of octets - there
 * is no guarantee it's a DNS name or printable etc. (Same as with
 * SNI generally.)
 *
 * @param ctx is the parent SSL_CTX
 * @param con is the SSL connection
 * @param esni is the SSL_ESNI structure
 * @param client_random_len is the number of bytes of
 * @param client_random being the TLS h/s client random
 * @param curve_id is the curve_id of the client keyshare
 * @param client_keyshare_len is the number of bytes of
 * @param client_keyshare is the h/s client keyshare
 * @return NULL for error, or the decrypted servername when it works
 */
unsigned char *SSL_ESNI_dec(SSL_CTX *ctx,
            SSL *con,
            SSL_ESNI *esni,
            size_t    client_random_len,
            unsigned char *client_random,
            uint16_t curve_id,
            size_t    client_keyshare_len,
            unsigned char *client_keyshare,
            size_t *encservername_len)
{
    ENTRY_TRACE;
    EVP_PKEY_CTX *pctx=NULL;
    if (!esni) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (!esni->the_esni) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (!client_random || !client_random_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (!client_keyshare || !client_keyshare_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (!encservername_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    
    /*
     * The plan
     * - check what we can before doing crypto
     *       - record_digest esni vs. ESNIKeys
     *       - ciphersuite/curve IDs
     * - do key derivation
     * - try decrypt
     * - compare what we can after crypto
     * - try extract and return SNI
     */
    CLIENT_ESNI *er=esni->the_esni;
    
    #ifdef DONTCHECKRD
    /*
     * Check record_digest TODO: draft-04 changes
     * Actually, this check is not needed really as it'd have
     * been successfully done already if there's a match or
     * else it'd have failed already in which case we only
     * get here when trial decrypting, so it's ok in either
     * case 
     */
    if (esni->rd_len!=er->record_digest_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (CRYPTO_memcmp(esni->rd,er->record_digest,er->record_digest_len)) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    #endif
    
    if (er->ciphersuite!=esni->ciphersuite) {
        /*
         * No longer print an error, as a) an attacker could cause
         * that to be generated and b) now we're allowing trial 
         * decryption, this could be v. common and hence misleading
         * ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
         */
        EXIT_TRACE;
        goto err;
    }
    
    /*
     * Stuff starts happening now, so mark it thusly
     */
    esni->crypto_started=1;
    
    /*
     * copy inputs to state, if we're trial decrypting then we
     * may need to free up previous values - TODO(ESNI) when 
     * removing the overcomplex state (after final interop)
     * be more careful about zapping any intermediate values
     * due to trial decryption
     */
    esni->hs_cr_len=client_random_len;
    if (esni->hs_cr!=NULL) OPENSSL_free(esni->hs_cr);
    esni->hs_cr=OPENSSL_malloc(esni->hs_cr_len);
    if (esni->hs_cr==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    memcpy(esni->hs_cr,client_random,esni->hs_cr_len);
    
    esni->hs_kse_len=client_keyshare_len;
    if (esni->hs_kse!=NULL) OPENSSL_free(esni->hs_kse);
    esni->hs_kse=OPENSSL_malloc(esni->hs_kse_len);
    if (esni->hs_kse==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    memcpy(esni->hs_kse,client_keyshare,esni->hs_kse_len);
    
    esni->cipher_len=esni->the_esni->encrypted_sni_len;
    if (esni->cipher!=NULL) OPENSSL_free(esni->cipher);
    esni->cipher=OPENSSL_malloc(esni->cipher_len);
    if (esni->cipher==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    memcpy(esni->cipher,esni->the_esni->encrypted_sni,esni->cipher_len);
    
    /*
     * Ok, let's go for Z
     */
    
    pctx = EVP_PKEY_CTX_new(esni->keyshare,NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0 ) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    /* mao er.encoded_keyshare to esni.esni_peer_pkey */
    if (esni->esni_peer_pkey!=NULL) {
        EVP_PKEY_free(esni->esni_peer_pkey);
        esni->esni_peer_pkey=NULL;
    }
    esni->esni_peer_pkey=ssl_generate_param_group(con,curve_id);
    if (esni->esni_peer_pkey==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (!EVP_PKEY_set1_tls_encodedpoint(esni->esni_peer_pkey,
                er->encoded_keyshare+6,er->encoded_keyshare_len-6)) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ESNI_R_RR_DECODE_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (EVP_PKEY_derive_set_peer(pctx, esni->esni_peer_pkey) <= 0 ) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (EVP_PKEY_derive(pctx, NULL, &esni->Z_len) <= 0) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (esni->Z!=NULL) OPENSSL_free(esni->Z);
    esni->Z=OPENSSL_malloc(esni->Z_len);
    if (esni->Z == NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    if (EVP_PKEY_derive(pctx, esni->Z, &esni->Z_len) <= 0) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    
    const SSL_CIPHER *sc=cs2sc(esni->ciphersuite);
    const EVP_MD *md=ssl_md(ctx,sc->algorithm2);
    esni->Zx_len=0;
    if (esni->Zx!=NULL) OPENSSL_free(esni->Zx);
    esni->Zx=esni_hkdf_extract(esni->Z,esni->Z_len,&esni->Zx_len,md);
    if (esni->Zx==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    
    if (makeesnicontenthash(ctx,esni,1)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    
    /* 
     * derive key and iv length from suite
     */
    if (esni_key_derivation(ctx,con,esni)!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }

    if (esni->plain!=NULL) OPENSSL_free(esni->plain);
    esni->plain=esni_aead_dec(esni->key, esni->key_len,
            esni->iv, esni->iv_len,
            esni->aad, esni->aad_len,
            esni->cipher, esni->cipher_len,
            &esni->plain_len,
            esni->ciphersuite);
    if (esni->plain==NULL) {
        /*
         * No longer print an error, as a) an attacker could cause
         * that to be generated and b) now we're allowing trial 
         * decryption, this could be v. common and hence misleading
         * ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
         */
        EXIT_TRACE;
        goto err;
    }

    esni->nonce_len=16;
    if (esni->nonce!=NULL) OPENSSL_free(esni->nonce);
    esni->nonce=OPENSSL_malloc(esni->nonce_len);
    if (esni->nonce==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    memcpy(esni->nonce,esni->plain,esni->nonce_len);

    size_t outer_es_len=esni->plain[16]*256+esni->plain[17];
    size_t inner_es_len=outer_es_len-3;
    size_t overhead=21;
    if (esni->version==ESNI_DRAFT_04_VERSION) {
        /*
         * switch from ServerNamList to opaque means less overhead
         */
        inner_es_len=outer_es_len;
        overhead=18;
    }
    if ((inner_es_len+overhead)>esni->plain_len) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    unsigned char *result=OPENSSL_malloc(inner_es_len+1);
    if (result==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DEC, ERR_R_INTERNAL_ERROR);
        EXIT_TRACE;
        goto err;
    }
    memcpy(result,esni->plain+overhead,inner_es_len);
    result[inner_es_len]=0x00; /* make it a safe-ish string */
    esni->encservername=(char*)result;

    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    *encservername_len=inner_es_len;
    EXIT_TRACE;
    return result;

err:
    if (pctx!=NULL) EVP_PKEY_CTX_free(pctx);
    EXIT_TRACE;
    return NULL;
}

int SSL_esni_checknames(const char *encservername, const char *clear_sni)
{
    int elen=0;
    int flen=0;
    if (encservername==NULL) {
        /*
         * Makes no sense
         */
        return 0;
    }
    elen=strlen(encservername);
    if (clear_sni!=NULL) {
        flen=strlen(clear_sni);
    }
    if (elen >= TLSEXT_MAXLEN_host_name) {
        return(0);
    }
    if (flen >= TLSEXT_MAXLEN_host_name) {
        return(0);
    }
    if (elen==flen && !CRYPTO_memcmp(encservername,clear_sni,elen)) {
        /*
         * Silly!
         */
        return(0);
    }
    /*
     * Possible checks:
     * - If no clear_sni, then send no (clear) SNI, so allow that
     * - Check same A/AAAA exists for both names, if we have both
     *       - could be a privacy leak though
     *       - even if using DoT/DoH (but how'd we know for sure?)
     * - check/retrive RR's from DNS if not already in-hand and
     *   if (sufficiently) privacy preserving
     */
    return(1);
}


/**
 * @brief: Turn on SNI encryption for an (upcoming) TLS session
 *
 * FIXME: Rationalise the handling of arrays of SSL_ESNI structs. As
 * of now, we sometimes set the number of those as a parameter (as
 * in this case), whereas other bits of code use the num_esni_rrs field 
 * inside the first array element to know how many we're dealing with.
 * 
 * @param s is the SSL context
 * @param hidden is the hidden service name
 * @param clear_sni is the cleartext SNI name to use
 * @param esni is an array of SSL_ESNI structures
 * @param nesnis says how many structures are in the esni array
 * @param require_hidden_match say whether to require (==1) the TLS server cert matches the hidden name
 * @return 1 for success, other otherwise
 * 
 */
int SSL_esni_enable(SSL *s, const char *hidden, const char *clear_sni, SSL_ESNI *esni, int nesnis, int require_hidden_match)
{
    int i; /* loop counter - android build doesn't like C99;-( */
    if (nesnis==0 || s==NULL || esni==NULL || hidden==NULL) {
        return 0;
    }
    /*
     * If there was an earlier SSL_ESNI structure loaded, we'll just
     * zap that first and use the one presented here.
     * We'll select which of the ESNIKeys included in the SSL_ESNI data
     * structure to use at this point on the client side. Selection 
     * criteria are: 1) most recent ESNIKeys version first, 2) the
     * most recently created based on not_before. We do not care 
     * about not_after. Originally, I planned to care about that
     * but now it's a gonner in draft-04, I'm happy to not bother
     * and let the application handle it as it sees fit.
     */
    if (s->esni!=NULL) {
        for (i=0;i!=s->nesni;i++) {
            SSL_ESNI_free(&s->esni[i]);
        }
        OPENSSL_free(s->esni);
        s->esni=NULL;
    }
    s->esni=esni;
    s->nesni=nesnis;
    for (i=0;i!=nesnis;i++) {
        s->esni[i].require_hidden_match=require_hidden_match;
        s->esni[i].encservername=OPENSSL_strndup(hidden,TLSEXT_MAXLEN_host_name);
        s->esni[i].clear_sni=NULL;
        if (clear_sni != NULL) {
            s->esni[i].clear_sni=OPENSSL_strndup(clear_sni,TLSEXT_MAXLEN_host_name);
        }
    }
    if (s->ext.hostname!=NULL) {
        OPENSSL_free(s->ext.hostname);
        s->ext.hostname=NULL;
    }
    if (s->ext.kse!=NULL) {
        OPENSSL_free(s->ext.kse);
        s->ext.kse=NULL;
        s->ext.kse_len=0;
    }
    /*
     * the chosen index into the set of ESNIKeys in this SSL_ESNI
     */
    int keysind=0; 
    int most_recent=0;
    for (i=0;i!=nesnis;i++) {
        if (esni[i].not_before>most_recent) {
            most_recent=esni[i].not_before;
            keysind=i;
        }
    }

    /* 
     * We prefer a supplied clear_sni over the draft-03/draft-04 public_name 
     */
    if (clear_sni!=NULL) {
        s->ext.hostname=OPENSSL_strndup(clear_sni,TLSEXT_MAXLEN_host_name);
    } else if (s->esni[keysind].public_name!=NULL) {
        s->ext.hostname=OPENSSL_strndup(s->esni[keysind].public_name,TLSEXT_MAXLEN_host_name);
    } 

    /*
     * Set to 1 when nonce returned
     * Checked for 0 when final_esni called
     */
    s->esni_done=0;
    s->esni_attempted=0;
    /*
     * Optionally enable hostname checking 
     */
    if (require_hidden_match==1) {
        if (SSL_set1_host(s,hidden)!=1) {
            return 0;
        }
    }

    /*
     * Handle padding - the server needs to do padding in case the
     * certificate/key-size exposes the ESNI. But so can lots of 
     * the other application interactions, so to be at least a bit
     * cautious, we'll also pad the crap out of everything on the
     * client side (at least to see what happens:-)
     * This could be over-ridden by the client appication if it
     * wants by setting a callback via SSL_set_record_padding_callback
     * We'll try set to 512 bytes, minus the 16 overhead so that
     * wireshark shows us nice round numbers and we're less
     * likely to go beyond an MTU (1550)
     */

    if (SSL_set_block_padding(s,ESNI_DEFAULT_PADDED)!=1) {
        return 0;
    }
    return 1;
}

/**
 * Report on the number of ESNI key RRs currently loaded
 *
 * @param s is the SSL server context
 * @param numkeys returns the number currently loaded
 * @return 1 for success, other otherwise
 */
int SSL_CTX_esni_server_key_status(SSL_CTX *s, int *numkeys)
{
    if (s==NULL) return 0;
    if (s->ext.esni==NULL) {
        *numkeys=0;
        return 1;
    }
    *numkeys=s->ext.nesni;
    return 1;
}

/**
 * Zap the set of stored ESNI Keys to allow a re-load without hogging memory
 *
 * Supply a zero or negative age to delete all keys. Providing age=3600 will
 * keep keys loaded in the last hour.
 *
 * @param s is the SSL server context
 * @param age don't flush keys loaded in the last age seconds
 * @return 1 for success, other otherwise
 */
int SSL_CTX_esni_server_flush_keys(SSL_CTX *s, int age)
{
    if (s==NULL) return 0;
    if (s->ext.esni==NULL) return 1;

    if (age<=0) {
        SSL_ESNI_free(s->ext.esni);
        OPENSSL_free(s->ext.esni);
        s->ext.esni=NULL;
        return 1;
    }
    /*
     * Otherwise go through them and delete as needed
     */
    time_t now=time(0);
    int i=0;
    int deleted=0; // number deleted
    for (i=0;i!=s->ext.nesni;i++) {
        SSL_ESNI *ep=&s->ext.esni[i];
        if ((ep->loadtime + age) <= now ) {
            SSL_ESNI_free(ep);
            deleted++;
            continue;
        } 
        s->ext.esni[i-deleted]=s->ext.esni[i]; // struct copy!
    }
    s->ext.nesni -= deleted;
    return 1;
}
 
#define ESNI_KEYPAIR_ERROR          0
#define ESNI_KEYPAIR_NEW            1
#define ESNI_KEYPAIR_UNMODIFIED     2
#define ESNI_KEYPAIR_MODIFIED       3

/**
 * Check if key pair needs to be (re-)loaded or not
 *
 * We go through the keys we have and see what we find
 *
 * @param ctx is the SSL server context
 * @param privfname is the private key filename
 * @param pubfname is the public key filename (can be NULL sometimes)
 * @param index is the index if we find a match
 * @return negative for error, otherwise one of: ESNI_KEYPAIR_UNMODIFIED ESNI_KEYPAIR_MODIFIED ESNI_KEYPAIR_NEW
 */
static int esni_check_filenames(SSL_CTX *ctx, const char *privfname,const char *pubfname,int *index)
{
    struct stat privstat,pubstat;

    // if bad input, crap out
    if (ctx==NULL || privfname==NULL || index==NULL) return(ESNI_KEYPAIR_ERROR);

    // if we have none, then it is new
    if (ctx->ext.esni==NULL || ctx->ext.nesni==0) return(ESNI_KEYPAIR_NEW);

    // if no file info, crap out
    if (stat(privfname,&privstat) < 0) return(ESNI_KEYPAIR_ERROR);
    if (pubfname && stat(pubfname,&pubstat) < 0) return(ESNI_KEYPAIR_ERROR);

    // check the time info - we're only gonna do 1s precision on purpose
#if defined(__APPLE__)
    time_t privmod=pubstat.st_mtimespec.tv_sec;
    time_t pubmod=(pubfname?pubstat.st_mtimespec.tv_sec:0);
#elif defined(OPENSSL_SYS_WINDOWS)
    time_t privmod=pubstat.st_mtime;
    time_t pubmod=(pubfname?pubstat.st_mtime:0);
#else
    time_t privmod=pubstat.st_mtim.tv_sec;
    time_t pubmod=(pubfname?pubstat.st_mtim.tv_sec:0);
#endif
    time_t rectime=(privmod>pubmod?privmod:pubmod);

    // now search list of existing key pairs to see if we have that one already
    int ind=0;
    size_t privlen=strlen(privfname);
    size_t publen=(pubfname?strlen(pubfname):0);
    for(ind=0;ind!=ctx->ext.nesni;ind++) {
        if (!strncmp(ctx->ext.esni[ind].privfname,privfname,privlen) &&
            (!pubfname || !strncmp(ctx->ext.esni[ind].pubfname,pubfname,publen))) {
            // matching files!
            if (ctx->ext.esni[ind].loadtime<rectime) {
                // aha! load it up so
                *index=ind;
                return(ESNI_KEYPAIR_MODIFIED);
            } else {
                // tell caller no need to bother
                *index=-1; // just in case:->
                return(ESNI_KEYPAIR_UNMODIFIED);
            }
        }
    }

    *index=-1; // just in case:->
    return ESNI_KEYPAIR_NEW;
}

/**
 * Turn on SNI Encryption, server-side
 *
 * When this works, the server will decrypt any ESNI seen in ClientHellos and
 * subsequently treat those as if they had been send in cleartext SNI.
 *
 * @param ctx is the SSL server context
 * @param con is the SSL connection
 * @param esnikeyfile has the relevant (X25519) private key in PEM format, or both keys
 * @param esnipubfile has the relevant (binary encoded, not base64) ESNIKeys structure, or is NULL
 * @return 1 for success, other otherwise
 */
int SSL_CTX_esni_server_enable(SSL_CTX *ctx, SSL *con, const char *esnikeyfile, const char *esnipubfile)
{
    /*
     * open and parse files (private key is PEM, public is binary/ESNIKeys)
     * and store in context
     */
    BIO *priv_in=NULL;
    BIO *pub_in=NULL;
    EVP_PKEY *pkey=NULL;
    SSL_ESNI *the_esni=NULL;
    unsigned char *inbuf=NULL;
    int leftover=0;
    ESNI_RECORD *er=NULL;
    char *pname=NULL;
    char *pheader=NULL;
    unsigned char *pdata=NULL;
    long plen;
    if (ctx==NULL || esnikeyfile==NULL) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    /*
     * Check if we already have that key pair and if it needs to be 
     * reloaded or not
     */
    int kpindex=0; /* will return with index of key to update, if relevant */
    int fnamecheckrv=esni_check_filenames(ctx,esnikeyfile,esnipubfile,&kpindex);
    switch (fnamecheckrv) {
        case ESNI_KEYPAIR_UNMODIFIED:
            if (kpindex<0 || kpindex>=ctx->ext.nesni) {
                ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
                goto err;
            } 
            /* update the loadtime to note it was refreshed now */
            ctx->ext.esni[kpindex].loadtime=time(0);
            /* and with that we're done reloading this key */
            return 1;
        case ESNI_KEYPAIR_MODIFIED:
            if (kpindex<0 || kpindex>=ctx->ext.nesni) {
                ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
                goto err;
            } 
            break; // hey, we coulda fallen through, but meh... :-)
        case ESNI_KEYPAIR_NEW:
            break;
        case ESNI_KEYPAIR_ERROR:
        default:
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
    }

    /*
     * Now check and parse inputs
     */
    priv_in = BIO_new(BIO_s_file());
    if (priv_in==NULL) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (BIO_read_filename(priv_in,esnikeyfile)<=0) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (!PEM_read_bio_PrivateKey(priv_in,&pkey,NULL,NULL)) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    inbuf=OPENSSL_malloc(ESNI_MAX_RRVALUE_LEN);
    size_t inblen=0;
    if (inbuf==NULL) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (esnipubfile!=NULL) {
        BIO_free(priv_in);
        priv_in=NULL;
        pub_in = BIO_new(BIO_s_file());
        if (pub_in==NULL) {
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (BIO_read_filename(pub_in,esnipubfile)<=0) {
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        inblen=BIO_read(pub_in,inbuf,ESNI_MAX_RRVALUE_LEN);
        if (inblen<=0) {
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        BIO_free(pub_in);
        pub_in=NULL;
    } else {
        pub_in=priv_in;
        priv_in=NULL;
        if (PEM_read_bio(pub_in,&pname,&pheader,&pdata,&plen)<=0) {
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (!pheader) {
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (strncmp(PEM_STRING_ESNIKEY,pheader,strlen(pheader))) {
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        OPENSSL_free(pheader); pheader=NULL;
        if (pname) {
            OPENSSL_free(pname);  pname=NULL;
        }
        if (plen>=ESNI_MAX_RRVALUE_LEN) {
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        inblen=plen;
        memcpy(inbuf,pdata,plen);
        OPENSSL_free(pdata); pdata=NULL;
        BIO_free(pub_in);
        pub_in=NULL;
    }

    er=SSL_ESNI_RECORD_new_from_binary(ctx,con,inbuf,inblen,&leftover);
    if (er==NULL) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * store in context 
     */
    SSL_ESNI* latest_esni=NULL;
    if (ctx->ext.esni==NULL) {
        ctx->ext.nesni=1;
        the_esni=(SSL_ESNI*)OPENSSL_malloc(sizeof(SSL_ESNI));
        if (the_esni==NULL) {
            ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ctx->ext.esni=the_esni;
        latest_esni=&ctx->ext.esni[0];
    } else {
        if (fnamecheckrv==ESNI_KEYPAIR_MODIFIED) {
            the_esni=&ctx->ext.esni[kpindex];
            latest_esni=&ctx->ext.esni[kpindex];
        } else if (fnamecheckrv==ESNI_KEYPAIR_NEW) {
            ctx->ext.nesni+=1;
            the_esni=(SSL_ESNI*)OPENSSL_realloc(ctx->ext.esni,ctx->ext.nesni*sizeof(SSL_ESNI));
            if (the_esni==NULL) {
                ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            ctx->ext.esni=the_esni;
            latest_esni=&ctx->ext.esni[ctx->ext.nesni-1];
        }
    }
    memset(latest_esni,0,sizeof(SSL_ESNI));
    latest_esni->encoded_rr=inbuf;
    latest_esni->encoded_rr_len=inblen;
    if (esni_make_se_from_er(ctx,con, er,latest_esni,1)!=1) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    // add my private key in there, the public was handled above
    latest_esni->keyshare=pkey;
    /* handle file names and indexing */
    latest_esni->privfname=OPENSSL_strndup(esnikeyfile,strlen(esnikeyfile));
    if (latest_esni->privfname==NULL) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    latest_esni->pubfname=(esnipubfile?OPENSSL_strndup(esnipubfile,strlen(esnipubfile)):NULL);
    if (esnipubfile && latest_esni->pubfname==NULL) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    latest_esni->loadtime=time(0);
    // update the numbers in the array (FIXME: this array handling is a bit dim)
    int i=0;
    for (i=0;i!=ctx->ext.nesni;i++) {
        ctx->ext.esni[i].num_esni_rrs=ctx->ext.nesni;
    }
    /*
     * Handle padding - we need to pad the Certificate and CertificateVerify
     * messages as those can expose the ESNI value due to differing sizes.
     * We might want to make this cleverer, e.g. by checking the sizes of
     * the certificates/public keys involved, but for now, we'll try to 
     * use the standard record padding scheme via SSL_CTX_set_block_padding
     * to set padding to 486 sized blocks and see what happens.
     * This can be over-ridden by the appication if it wants by setting a 
     * callback via SSL_CTX_set_record_padding_callback
     */
    if (SSL_CTX_set_block_padding(ctx,ESNI_DEFAULT_PADDED)!=1) {
        ESNIerr(ESNI_F_SSL_CTX_ESNI_SERVER_ENABLE, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ESNI_RECORD_free(er);
    OPENSSL_free(er);
    return 1;

err:

    /*
     * For these we want to clean up intermediate values but not
     * affect the set of previously ok ESNI keys 
     */
    if (er!=NULL) {
        ESNI_RECORD_free(er);
        OPENSSL_free(er);
    }
    if (inbuf!=NULL) {
        OPENSSL_free(inbuf);
        if (the_esni!=NULL && the_esni->encoded_rr==inbuf) {
            /*
             * don't double free
             */
            the_esni->encoded_rr=NULL;
        }
    }
    if (pkey!=NULL) {
        EVP_PKEY_free(pkey);
    }
    if (priv_in!=NULL) {
        BIO_free(priv_in);
    }
    if (pub_in!=NULL) {
        BIO_free(pub_in);
    }
    /* PEM stuff */
    if (pheader) {
        OPENSSL_free(pheader);
    }
    if (pname) {
        OPENSSL_free(pname);
    }
    if (pdata) {
        OPENSSL_free(pdata);
    }
    return 0;

};

int SSL_get_esni_status(SSL *s, char **hidden, char **clear_sni)
{
    if (s==NULL || clear_sni==NULL || hidden==NULL) {
        return SSL_ESNI_STATUS_BAD_CALL;
    }
    *clear_sni=NULL;
    *hidden=NULL;
    if (s->esni!=NULL && s->esni_attempted) {
        /*
         * Need to pick correct array element 
         * For now we'll do that based on matching the session vs. esni
         */
        int matchind=-1;
        int ind=0;
        int nesnis=s->esni->num_esni_rrs;
        for (ind=0;ind!=nesnis;ind++) {
            if (s->esni[ind].crypto_started!=0) {
                /*
                 * this one's active 
                 */
                if (matchind==-1) {
                    /*
                     * found it
                     */
                    matchind=ind;
                } else {
                    /*
                     * crap - >1 active, error out for now
                     */
                    return SSL_ESNI_STATUS_TOOMANY;
                }
            }
        }
        if (matchind==-1) {
            return SSL_ESNI_STATUS_NOT_TRIED;
        }
        if (matchind!=-1 && s->esni[matchind].version==ESNI_GREASE_VERSION) {
            return SSL_ESNI_STATUS_GREASE;
        }
        if (matchind!=-1 && s->esni[matchind].nonce==NULL) {
            return SSL_ESNI_STATUS_FAILED;
        }
        long vr=X509_V_OK;
        if (s->esni[matchind].require_hidden_match) {
            vr=SSL_get_verify_result(s);
        } 
        /*
         * *hidden may end up as NULL here, but that's correct (if ESNI failed)
         */
        *hidden=s->esni[matchind].encservername;
        /*
         * Prefer clear_sni (if supplied) to draft-03/draft-04 public_name 
         */
        if (s->esni[matchind].clear_sni) {
            *clear_sni=s->esni[matchind].clear_sni;
        } else {
            *clear_sni=s->esni[matchind].public_name;
        }
        if (s->esni_done==1) {
            if (vr == X509_V_OK ) {
                return SSL_ESNI_STATUS_SUCCESS;
            } else {
                return SSL_ESNI_STATUS_BAD_NAME;
            }
        } else {
            return SSL_ESNI_STATUS_FAILED;
        }
    } else if (s->esni_attempted==1) {
        return SSL_ESNI_STATUS_GREASE;
    } 
    return SSL_ESNI_STATUS_NOT_TRIED;
}

void SSL_set_esni_callback(SSL *s, SSL_esni_cb_func f)
{
    s->esni_cb=f;
}

void SSL_CTX_set_esni_callback(SSL_CTX *s, SSL_esni_cb_func f)
{
    s->ext.esni_cb=f;
}

int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni)
{
    if (s==NULL || esni==NULL) {
        return 0;
    }
    *esni=s->esni;
    return 1;
}
 
int SSL_CTX_get_esni(SSL_CTX *s, SSL_ESNI **esni){
    if (s==NULL || esni==NULL) {
        return 0;
    }
    *esni=s->ext.esni;
    return s->ext.nesni;
}

int SSL_ESNI_set_private(SSL_ESNI *esni, char *private_str)
{
#ifdef ESNI_CRYPT_INTEROP
    esni->private_str=private_str;
#endif
    return 1;
}

int SSL_ESNI_set_nonce(SSL_ESNI *esni, unsigned char *nonce, size_t nlen)
{
#ifdef ESNI_CRYPT_INTEROP
    lg_nonce=nonce;
    lg_nonce_len=nlen;
#endif
    return 1;
}

SSL_ESNI* SSL_ESNI_dup(SSL_ESNI* orig, size_t nesni, int selector)
{

/*
 * Macro for more terse copying below. Only odd thing
 * here is that this has to be defined inside this 
 * function's scope as there's a "make update" target
 * that, among other things, checks that the ESNI_F_SSL_ESNI_DUP
 * string only occurs within the scope of this function.
 * I'm not sure why that's useful but whatever...
 */
#define SSL_ESNI_dup_one(FIELD,len_FIELD) \
        newi->len_FIELD=origi->len_FIELD; \
        if (origi->FIELD) { \
            newi->FIELD=OPENSSL_malloc(newi->len_FIELD); \
            if (newi->FIELD==NULL) { \
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR); \
                goto err; \
            } \
            memcpy(newi->FIELD,origi->FIELD,newi->len_FIELD); \
        }

    if (orig==NULL) return NULL;

    SSL_ESNI *new=NULL;
    int num_selected=nesni;

    /*
     * Check selector is reasonable
     */
    if (selector!=ESNI_SELECT_ALL) {
        if (selector < 0 || selector >=nesni) {
            ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        num_selected=1;
    } else {
        num_selected=nesni;
    }

    new=OPENSSL_malloc(num_selected*sizeof(SSL_ESNI));
    if (new==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memset(new,0,num_selected*sizeof(SSL_ESNI));

    int i; /* loop counter - android build doesn't like C99;-( */
    for (i=0;i!=nesni;i++) {

        SSL_ESNI *origi=&orig[i];
        SSL_ESNI *newi=NULL;

        if (selector!=ESNI_SELECT_ALL && i!=selector) {
            continue;
        } else if (selector!=ESNI_SELECT_ALL && i==selector) {
            newi=new;
        } else if (selector==ESNI_SELECT_ALL) {
            newi=&new[i];
        } else {
            /* shouldn't happen, but who knows... */
            ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
            goto err;
        }


        /*
         * Copying field by field allowing for NULLs etc.
         * These are in the order presented in ../include/openssl/esni.h
         * Try keep that the same if new fields are added, otherwise it
         * may get hard to track what's what.
         */
        newi->version=origi->version;
        if (origi->encservername!=NULL) newi->encservername=OPENSSL_strdup(origi->encservername);
        if (origi->clear_sni!=NULL) newi->clear_sni=OPENSSL_strdup(origi->clear_sni);
        if (origi->public_name!=NULL) newi->public_name=OPENSSL_strdup(origi->public_name);
        newi->require_hidden_match=origi->require_hidden_match;
        if (selector==ESNI_SELECT_ALL) {
            //newi->num_esni_rrs=origi->num_esni_rrs;
            newi->num_esni_rrs=nesni;
        } else {
            newi->num_esni_rrs=1;
        }

        SSL_ESNI_dup_one(encoded_rr,encoded_rr_len)
        SSL_ESNI_dup_one(rd,rd_len)

        newi->ciphersuite=origi->ciphersuite;
        newi->group_id=origi->group_id;

        SSL_ESNI_dup_one(esni_peer_keyshare,esni_peer_keyshare_len)

        newi->esni_peer_pkey=origi->esni_peer_pkey;
        if (origi->esni_peer_pkey!=NULL) {
            if (EVP_PKEY_up_ref(origi->esni_peer_pkey)!=1) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        newi->padded_length=origi->padded_length;
        newi->not_before=origi->not_before;
        newi->not_after=origi->not_after;

        newi->nexts=origi->nexts;
        if (origi->exttypes) {
            newi->exttypes=OPENSSL_malloc(newi->nexts*sizeof(unsigned int));
            if (newi->exttypes==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(newi->exttypes,origi->exttypes,newi->nexts*sizeof(unsigned int));
        }
        if (origi->extlens) {
            newi->extlens=OPENSSL_malloc(newi->nexts*sizeof(size_t));
            if (newi->extlens==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(newi->extlens,origi->extlens,newi->nexts*sizeof(size_t));
        }
        if (origi->exts) {
            newi->exts=OPENSSL_malloc(newi->nexts*sizeof(unsigned char*));
            if (newi->exts==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            int j;
            for (j=0;j!=newi->nexts;j++) {
                if (newi->extlens[j]==0) {
                    newi->exts[j]=NULL;
                } else {
                    newi->exts[j]=OPENSSL_malloc(newi->extlens[j]);
                    if (newi->exts[j]==NULL) {
                        ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                        goto err;
                    }
                    memcpy(newi->exts[j],origi->exts[j],newi->extlens[j]);
                }
            }
        }

        newi->dnsnexts=origi->dnsnexts;
        if (origi->dnsexttypes) {
            newi->dnsexttypes=OPENSSL_malloc(newi->dnsnexts*sizeof(unsigned int));
            if (newi->dnsexttypes==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(newi->dnsexttypes,origi->dnsexttypes,newi->dnsnexts*sizeof(unsigned int));
        }
        if (origi->dnsextlens) {
            newi->dnsextlens=OPENSSL_malloc(newi->dnsnexts*sizeof(size_t));
            if (newi->dnsextlens==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(newi->dnsextlens,origi->dnsextlens,newi->dnsnexts*sizeof(size_t));
        }
        if (origi->dnsexts) {
            newi->dnsexts=OPENSSL_malloc(newi->dnsnexts*sizeof(unsigned char*));
            if (newi->dnsexts==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            int j;
            for (j=0;j!=newi->dnsnexts;j++) {
                if (newi->dnsextlens[j]==0) {
                    newi->dnsexts[j]=NULL;
                } else {
                    newi->dnsexts[j]=OPENSSL_malloc(newi->dnsextlens[j]);
                    if (newi->dnsexts[j]==NULL) {
                        ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                        goto err;
                    }
                    memcpy(newi->dnsexts[j],origi->dnsexts[j],newi->dnsextlens[j]);
                }
            }
        }

        newi->naddrs=origi->naddrs;
        
        if (origi->addrs) {
            newi->addrs=OPENSSL_malloc(newi->naddrs*sizeof(BIO_ADDR));
            if (newi->addrs==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            memcpy(newi->addrs,origi->addrs,newi->naddrs*sizeof(BIO_ADDR));
        }

        SSL_ESNI_dup_one(nonce,nonce_len)
        SSL_ESNI_dup_one(hs_cr,hs_cr_len)
        SSL_ESNI_dup_one(hs_kse,hs_kse_len)

        newi->keyshare=origi->keyshare;
        if (origi->keyshare!=NULL) {
            if (EVP_PKEY_up_ref(origi->keyshare)!=1) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }
        SSL_ESNI_dup_one(encoded_keyshare,encoded_keyshare_len)
        SSL_ESNI_dup_one(hi,hi_len)
        SSL_ESNI_dup_one(hash,hash_len)
        SSL_ESNI_dup_one(realSNI,realSNI_len)
        SSL_ESNI_dup_one(Z,Z_len)
        SSL_ESNI_dup_one(Zx,Zx_len)
        SSL_ESNI_dup_one(key,key_len)
        SSL_ESNI_dup_one(iv,iv_len)
        SSL_ESNI_dup_one(aad,aad_len)
        SSL_ESNI_dup_one(plain,plain_len)
        SSL_ESNI_dup_one(cipher,cipher_len)
        SSL_ESNI_dup_one(tag,tag_len)
#ifdef ESNI_CRYPT_INTEROP
        if (origi->private_str) newi->private_str=OPENSSL_strdup(origi->private_str);
#endif

        /* 
         * Handle file names
         */
        if (origi->privfname!=NULL) newi->privfname=OPENSSL_strdup(origi->privfname);
        if (origi->pubfname!=NULL) newi->pubfname=OPENSSL_strdup(origi->pubfname);
        newi->loadtime=origi->loadtime;

        /*
         * Special case - pointers here are shallow to ones above
         */
        if (origi->the_esni) {
            newi->the_esni=OPENSSL_malloc(sizeof(CLIENT_ESNI));
            if (newi->the_esni==NULL) {
                ESNIerr(ESNI_F_SSL_ESNI_DUP, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            newi->the_esni->ciphersuite=origi->the_esni->ciphersuite;
            newi->the_esni->encoded_keyshare_len=origi->the_esni->encoded_keyshare_len;
            newi->the_esni->encoded_keyshare=newi->encoded_keyshare;
            newi->the_esni->record_digest_len=origi->the_esni->record_digest_len;
            newi->the_esni->record_digest=newi->rd;
            newi->the_esni->encrypted_sni_len=origi->the_esni->encrypted_sni_len;
            newi->the_esni->encrypted_sni=newi->cipher;
        }

    }

    return new;
err:
    if (new!=NULL) {
        SSL_ESNI_free(new);
        OPENSSL_free(new);
    }
    return NULL;
}

/* 
 * Optional functions for applications to use below here
 */

/**
 * @brief query the content of an SSL_ESNI structure
 *
 * This function allows the application to examine some internals
 * of an SSL_ESNI structure so that it can then down-select some
 * options. In particular, the caller can see the public_name and
 * IP address related information associated with each ESNIKeys
 * RR value (after decoding and initial checking within the
 * library), and can then choose which of the RR value options
 * the application would prefer to use.
 *
 * @param in is the internal form of SSL_ESNI structure
 * @param out is the returned externally array of visible detailed forms of the SSL_ESNI structure
 * @param nindices is an output saying how many indices are in the SSL_ESNI_ext structure 
 * @return 1 for success, error otherwise
 */
int SSL_esni_query(SSL_ESNI *in, SSL_ESNI_ext **out, int *nindices)
{
    if (in==NULL || out==NULL || nindices==NULL) {
        return(0);
    }
    SSL_ESNI_ext *se=NULL;
    int i=0;
    for (i=0;i!=in->num_esni_rrs;i++) {
        SSL_ESNI_ext *tse=OPENSSL_realloc(se,(i+1)*sizeof(SSL_ESNI_ext));
        if (tse==NULL) {
            ESNIerr(ESNI_F_SSL_ESNI_QUERY, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        se=tse;
        memset(&se[i],0,sizeof(SSL_ESNI_ext));
        se[i].index=i;
        se[i].not_before=in[i].not_before;
        se[i].not_after=in[i].not_after;
        if (in[i].public_name!=NULL) se[i].public_name= OPENSSL_strdup(in[i].public_name);
        if (in[i].naddrs>0) {
            int j;
            char *prefstr=NULL;
            size_t plen=0;
            for (j=0;j!=in[i].naddrs;j++) {
                char *foo=BIO_ADDR_hostname_string(&in[i].addrs[j], 1);
                size_t newlen=plen+1+strlen(foo)+1;
                char *bar=OPENSSL_malloc(newlen);
                if (bar==NULL) {
                    ESNIerr(ESNI_F_SSL_ESNI_QUERY, ERR_R_INTERNAL_ERROR);
                    goto err;
                }
                if (prefstr==NULL) {
                    snprintf(bar,newlen,"%s",foo);
                } else {
                    snprintf(bar,newlen,"%s;%s",prefstr,foo);
                }
                OPENSSL_free(prefstr);
                OPENSSL_free(foo);
                prefstr=bar;
                plen=strlen(prefstr);
            }
            se[i].prefixes=prefstr;
        }
    }
    *out=se;
    *nindices=in->num_esni_rrs;
    return(1);
err:
    if (se!=NULL) {
       SSL_ESNI_ext_free(se,i);
       OPENSSL_free(se);
    }
    return(0);
}

/** 
 * @brief free up memory for an SSL_ESNI_ext
 *
 * @param in is the structure to free up
 * @param size says how many indices are in in
 */
void SSL_ESNI_ext_free(SSL_ESNI_ext *in, int size)
{
    int i=0;
    if (in==NULL) return;
    for (i=0;i!=size;i++)  {
        if (in[i].public_name!=NULL) OPENSSL_free(in[i].public_name);
        if (in[i].prefixes!=NULL) OPENSSL_free(in[i].prefixes);
    }
    return;
}

/**
 * @brief down-select to use of one option with an SSL_ESNI
 *
 * This allows the caller to select one of the RR values 
 * within an SSL_ESNI for later use.
 *
 * @param in is an SSL_ESNI structure with possibly multiple RR values
 * @param index is the index value from an SSL_ESNI_ext produced from the 'in'
 * @param out is a returned SSL_ESNI containing only that indexed RR value 
 * @return 1 for success, error otherwise
 */
int SSL_ESNI_reduce(SSL_ESNI *in, int index, SSL_ESNI **out)
{
    SSL_ESNI *newone=NULL;
    if (in==NULL || out==NULL || index >= in->num_esni_rrs) {
        ESNIerr(ESNI_F_SSL_ESNI_REDUCE, ERR_R_INTERNAL_ERROR);
        return(0);
    }
    newone=SSL_ESNI_dup(in,in->num_esni_rrs,index);
    if (newone!=NULL) {
        *out=newone;
        return(1);
    } else {
        ESNIerr(ESNI_F_SSL_ESNI_REDUCE, ERR_R_INTERNAL_ERROR);
        return(0);
   }
}

/**
 * @brief utility fnc for application that wants to print an SSL_ESNI_ext
 *
 * @param out is the BIO to use (e.g. stdout/whatever)
 * @param se is a pointer to an SSL_ESNI_ext struture
 * @param count is the number of elements in se
 * @return 1 for success, error othewise
 */
int SSL_ESNI_ext_print(BIO* out, SSL_ESNI_ext *se,int count)
{
    int i=0;
    if (se==NULL) return(0);
    BIO_printf(out,"SSL_ESNI_ext:\n");
    for (i=0;i!=count;i++) {
        BIO_printf(out,"Element %d\n",i);
        if (se[i].public_name==NULL) {
            BIO_printf(out,"\tNo Public name\n");
        } else {
            BIO_printf(out,"\tPublic name: %s\n",se[i].public_name);
        }
        if (se[i].prefixes==NULL) {
            BIO_printf(out,"\tNo Prefixes\n");
        } else {
            BIO_printf(out,"\tPrefixes: %s\n",se[i].prefixes);
        }
        time_t tt=se[i].not_before;
        if (tt!=ESNI_NOTATIME) {
            BIO_printf(out,"\tNot before: (%ju) %s", se[i].not_before, asctime(gmtime(&tt)));
        } else {
            BIO_printf(out,"\tNot before: unset\n");
        }
        tt=se[i].not_after;
        if (tt!=ESNI_NOTATIME) {
            BIO_printf(out,"\tNot after: (%ju) %s", se[i].not_after, asctime(gmtime(&tt)));
        } else {
            BIO_printf(out,"\tNot after: unset\n");
        }
    }
    return(1);
}


/**
 * @brief Make up a GREASE/fake SSL_ESNI structure
 *
 * When doing GREASE (draft-ietf-tls-grease) we want to make up a
 * phony encrypted SNI. This function will do that:-)
 *
 * @param s is the SSL context
 * @param cp is a pointer to a possible greasy ESNI
 * @return 1 for success, other otherwise
 *
 */
int SSL_ESNI_grease_me(SSL *s, CLIENT_ESNI **cp)
{
    /*
     * Ciphersuite handling: we have an array of ciphersuite
     * numbers, with duplicates allowed. We randomly pick an
     * array element and use that value. So if e.g. you wanted
     * to use ciphersuite 0x1301 75% of the time, make sure that
     * 75% of the entries have that value.
     * For now we only populate:
     * TLS_AES_128_GCM_SHA256,0x1301 (@80%) and 
     * TLS_CHACHA20_POLY1305_SHA256, 0x1303 (@20%)
     */
    uint16_t csarray[]={
       0x1301,0x1301,0x1301,0x1301,
       0x1303
    };
    /*
     * decare these early so goto err works
     */

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    SSL_ESNI *greasy=NULL;
    size_t esl=292; unsigned char *esb=NULL;
    size_t rdl=32; unsigned char *rdb=NULL;
    unsigned char *ekbc=NULL;
    unsigned char *ekb=NULL;
    /*
     * If there's already an SSL_ESNI, leave it alone
     * But that wasn't a good call so return an error
     */
    if (s==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ESNI_R_BAD_INPUT);
        goto err;
    }
    if (cp==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ESNI_R_BAD_INPUT);
        goto err;
    }
    if (s->esni!=NULL) return 0;
    if (!RAND_set_rand_method(NULL)) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ESNI_R_BAD_INPUT);
        goto err;
    }
    /*
     * Don't grease if told/configured not to grease
     */
    int client_grease=(s->options & SSL_OP_ESNI_GREASE); 
    if (client_grease ==0) {
        return 0;
    }

    /*
     * We're gonna grease
     */
    greasy=OPENSSL_malloc(sizeof(SSL_ESNI));
    if (greasy==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memset(greasy,0,sizeof(SSL_ESNI));
    greasy->version=ESNI_GREASE_VERSION;

#define ESNI_GREASE_RANDBUF(xxLen,xxPtr) \
    { \
        xxPtr=OPENSSL_malloc(xxLen); \
        if (xxPtr==NULL) { \
            ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ERR_R_MALLOC_FAILURE); \
            goto err; \
        } \
        RAND_bytes(xxPtr,xxLen); \
    }

    /*
     * Setup for success exit, or for goto err which should free correctly
     */
    CLIENT_ESNI *c=OPENSSL_malloc(sizeof(CLIENT_ESNI));
    if (c==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memset(c,0,sizeof(CLIENT_ESNI));
    greasy->the_esni=c;
    greasy->num_esni_rrs=1;
    s->esni=greasy;
    /*
     * Prepare bogus values
     */
    size_t randind=0;
    int rv=RAND_bytes((unsigned char*)&randind,sizeof(randind));
    if (rv!=1) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    int mc=sizeof(csarray)/sizeof(csarray[0]);
    randind=randind%mc;
    uint16_t cs=csarray[randind];

    pctx=EVP_PKEY_CTX_new_id(NID_X25519, NULL);
    if (pctx==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &pkey);
    if (pkey==NULL) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);pctx=NULL;
    size_t eklc = EVP_PKEY_get1_tls_encodedpoint(pkey,&ekbc); 
    if (eklc == 0) {
        ESNIerr(ESNI_F_SSL_ESNI_GREASE_ME, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    EVP_PKEY_free(pkey);pkey=NULL;
    size_t ekl=0;
    ekb=SSL_ESNI_wrap_keyshare(ekbc,eklc,NID_X25519,&ekl);
    OPENSSL_free(ekbc);ekbc=NULL;
    ESNI_GREASE_RANDBUF(rdl,rdb);
    /*
     * I think (but am not sure, TODO: check) that a chacha20_poly1305
     * ciphertext would be 4 octets shorter than an AES GCM one.
     */
    if (cs==0x1303) {
        esl-=4;
    }
    ESNI_GREASE_RANDBUF(esl,esb);

    /*
     * Populate CLIENT_ESNI structure with bogosity
     */
    c->ciphersuite=cs;
    c->encoded_keyshare=ekb;
    c->encoded_keyshare_len=ekl;
    c->record_digest=rdb;
    c->record_digest_len=rdl;
    c->encrypted_sni=esb;
    c->encrypted_sni_len=esl;
    *cp=c;
    return 1;

err:
    if (ekbc!=NULL) OPENSSL_free(ekbc);
    if (ekb!=NULL) OPENSSL_free(ekb);
    if (esb!=NULL) OPENSSL_free(esb);
    if (rdb!=NULL) OPENSSL_free(rdb);
    if (pkey!=NULL) EVP_PKEY_free(pkey);
    if (greasy!=NULL) SSL_ESNI_free(greasy);
    OPENSSL_free(greasy);
    return 0;
}

#endif

