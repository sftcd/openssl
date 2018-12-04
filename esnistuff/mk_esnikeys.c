/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a standalone ESNIKeys Creator main file to start in on esni
 * in OpenSSL style, as per https://tools.ietf.org/html/draft-ietf-tls-esni-02
 * Author: stephen.farrell@cs.tcd.ie
 * Date: 20181203
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/esni.h>
// for getopt()
#include <getopt.h>

#define BUFLEN 1024 ///< just for laughs, won't be that long

/*
 * stdout version of esni_pbuf - just for odd/occasional debugging
 */
static void so_esni_pbuf(char *msg,unsigned char *buf,size_t blen,int indent)
{
    if (buf==NULL) {
        printf("OPENSSL: %s is NULL",msg);
        return;
    }
    printf("OPENSSL: %s (%zd):\n    ",msg,blen);
    int i;
    for (i=0;i!=blen;i++) {
        if ((i!=0) && (i%16==0))
            printf("\n    ");
        printf("%02x:",buf[i]);
    }
    printf("\n");
    return;
}

/**
 * @brief generate the SHA256 checksum that should be in the DNS record
 *
 * Fixed SHA256 hash in this case, we work on the offset here,
 * (bytes 2 bytes then 4 checksum bytes then rest) with no other 
 * knowledge of the encoding.
 *
 * @param buf is the buffer
 * @param buf_len is obvous
 * @return 1 for success, not 1 otherwise
 */
static int esni_checksum_gen(unsigned char *buf, size_t buf_len, unsigned char cksum[4])
{
    /* 
     * copy input with zero'd checksum, do SHA256 hash, compare with checksum, tedious but easy enough
     */
    unsigned char *buf_zeros=OPENSSL_malloc(buf_len);
    if (buf_zeros==NULL) {
		fprintf(stderr,"Crypto error (line:%d)\n",__LINE__);
        goto err;
    }
    memcpy(buf_zeros,buf,buf_len);
    memset(buf_zeros+2,0,4);
    unsigned char md[EVP_MAX_MD_SIZE];
    SHA256_CTX context;
    if(!SHA256_Init(&context)) {
		fprintf(stderr,"Crypto error (line:%d)\n",__LINE__);
        goto err;
    }
    if(!SHA256_Update(&context, buf_zeros, buf_len)) {
		fprintf(stderr,"Crypto error (line:%d)\n",__LINE__);
        goto err;
    }
    if(!SHA256_Final(md, &context)) {
		fprintf(stderr,"Crypto error (line:%d)\n",__LINE__);
        goto err;
    }
    OPENSSL_free(buf_zeros);
	memcpy(cksum,md,4);
    return 1;
err:
    if (buf_zeros!=NULL) OPENSSL_free(buf_zeros);
    return 0;
}

void usage(char *prog) 
{
    printf("Create an ESNIKeys data structure as per draft-ietf-tls-esni-02\n");
    printf("Usage: \n");
    printf("\t%s [-o <fname>] [-p <privfname>] [-d duration]\n",prog);
    printf("where:\n");
    printf("-o specifies the output file name for the base64-encoded ESNIKeys (default: ./esnikeys.pub)\n");
    printf("-p specifies the output file name for the corresponding private key (default: ./esnikeys.priv)\n");
    printf("-d duration, specifies the duration in seconds from now, for which the public should be valid (default: 1 week)\n");
    printf("\n");
    printf("If <privfname> exists already and contains an appropriate value, then that key will be used without change.\n");
    printf("There is no support for options - we just support TLS_AES_128_GCM_SHA256, X5519 and no extensions.\n");
    printf("Fix that if you like:-)\n");
    exit(1);
}

/**
 * @brief Make an X25519 key pair and ESNIKeys structure for the public
 *
 * @todo TODO: write base 64 version of public as well 
 * @todo TODO: check out NSS code to see if I can make same format private
 */
static int mk_esnikeys(int argc, char **argv)
{
    // getopt vars
    int opt;

    char *pubfname=NULL; ///< public key file name
    char *privfname=NULL; ///< private key file name
    int duration=60*60*24*7; ///< 1 week in seconds
    int maxduration=duration*52*10; ///< 10 years max - draft -02 will definitely be deprecated by then:-)
    int minduration=3600; ///< less than one hour seems unwise

    // check inputs with getopt
    while((opt = getopt(argc, argv, "?ho:p:d:")) != -1) {
        switch(opt) {
            case 'h':
            case '?':
                usage(argv[0]);
                break;
            case 'o':
                pubfname=optarg;
                break;
            case 'p':
                privfname=optarg;
                break;
            case 'd':
                duration=atoi(optarg);
                break;
            default:
                fprintf(stderr, "Error - No such option: `%c'\n\n", optopt);
                usage(argv[0]);
        }
    }

    if (duration <=0) {
        fprintf(stderr,"Can't have negative duration (%d)\n",duration);
        usage(argv[0]);
    }
    if (duration>=maxduration) {
        fprintf(stderr,"Can't have >10 years duration (%d>%d)\n",duration,maxduration);
        usage(argv[0]);
    }
    if (duration<minduration) {
        fprintf(stderr,"Can't have <1 hour duration (%d<%d)\n",duration,minduration);
        usage(argv[0]);
    }

    if (privfname==NULL) {
        privfname="esnikeys.priv";
    }
    EVP_PKEY *pkey = NULL;
    FILE *privfp=fopen(privfname,"rb");
    if (privfp!=NULL) {
        // read contents
        if (!PEM_read_PrivateKey(privfp,&pkey,NULL,NULL)) {
            fprintf(stderr,"Can't read private key - exiting\n");
            fclose(privfp);
            exit(1);
        }
        // don't close file yet, used as signal later
    } else {
        /* new private key please... */
        if (!RAND_set_rand_method(NULL)) {
            fprintf(stderr,"Can't init (P)RNG - exiting\n");
            exit(1);
        }
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
        if (pctx==NULL) {
            fprintf(stderr,"Crypto error (line:%d)\n",__LINE__);
            exit(2);
        }
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &pkey);
        if (pkey==NULL) {
            fprintf(stderr,"Crypto error (line:%d)\n",__LINE__);
            exit(3);
        }
        EVP_PKEY_CTX_free(pctx);

    }
    unsigned char *public=NULL;
    size_t public_len=0;
    public_len = EVP_PKEY_get1_tls_encodedpoint(pkey,&public); 
    if (public_len == 0) {
        fprintf(stderr,"Crypto error (line:%d)\n",__LINE__);
        exit(4);
    }

    // write private key to file, if we didn't just read private key file
    if (privfp==NULL) {
        privfp=fopen(privfname,"wb");
        if (privfp==NULL) {
            fprintf(stderr,"fopen error (line:%d)\n",__LINE__);
            exit(5);
        }
        if (!PEM_write_PrivateKey(privfp,pkey,NULL,NULL,0,NULL,NULL)) {
            fclose(privfp);
            fprintf(stderr,"file write error (line:%d)\n",__LINE__);
            exit(6);
        }
    }
    fclose(privfp);

	EVP_PKEY_free(pkey);

    time_t nb=time(0)-1;
    time_t na=nb+duration;

    /*
     * Here's a hexdump of one cloudflare value:
     * 00000000  ff 01 c7 04 13 a8 00 24  00 1d 00 20 e1 84 9f 8d  |.......$... ....|
     * 00000010  2c 89 3c da f5 cf 71 7c  2a ac c1 34 19 cc 7a 38  |,.<...q|*..4..z8|
     * 00000020  a6 d2 62 59 68 f9 ab 89  ad d7 b2 27 00 02 13 01  |..bYh......'....|
     * 00000030  01 04 00 00 00 00 5b da  50 10 00 00 00 00 5b e2  |......[.P.....[.|
     * 00000040  39 10 00 00                                       |9...|
     * 00000044
     *
     * And here's the TLS presentation syntax:
     *     struct {
     *         uint16 version;
     *         uint8 checksum[4];
     *         KeyShareEntry keys<4..2^16-1>;
     *         CipherSuite cipher_suites<2..2^16-2>;
     *         uint16 padded_length;
     *         uint64 not_before;
     *         uint64 not_after;
     *         Extension extensions<0..2^16-1>;
     *     } ESNIKeys;
     *
     */

    unsigned char bbuf[BUFLEN]; ///< binary buffer
    unsigned char *bp=bbuf;
    memset(bbuf,0,BUFLEN);
    *bp++=0xff; 
    *bp++=0x01;// version = 0xff01
    memset(bp,0,4); bp+=4; // space for checksum
    *bp++=0x00;
    *bp++=0x24; // length=36
    *bp++=0x00;
    *bp++=0x1d; // curveid=X25519= decimal 29
    *bp++=0x00;
    *bp++=0x20; // length=32
    memcpy(bp,public,32); bp+=32;
    *bp++=0x00;
    *bp++=0x02; // length=2
    *bp++=0x13;
    *bp++=0x01; // ciphersuite TLS_AES_128_GCM_SHA256
    *bp++=0x01;
    *bp++=0x04; // 2 bytes padded length - 260, same as CF for now
    memset(bp,0,4); bp+=4; // top zero 4 octets of time
    *bp++=(nb>>24)%256;
    *bp++=(nb>>16)%256;
    *bp++=(nb>>8)%256;
    *bp++=nb%256;
    memset(bp,0,4); bp+=4; // top zero 4 octets of time
    *bp++=(na>>24)%256;
    *bp++=(na>>16)%256;
    *bp++=(na>>8)%256;
    *bp++=na%256;
    *bp++=0x00;
    *bp++=0x00; // no extensions
    size_t bblen=bp-bbuf;

    so_esni_pbuf("BP",bbuf,bblen,0);

	unsigned char cksum[4];
	if (esni_checksum_gen(bbuf,bblen,cksum)!=1) {
        fprintf(stderr,"fopen error (line:%d)\n",__LINE__);
        exit(7);
	}
	memcpy(bbuf+2,cksum,4);
    so_esni_pbuf("BP+cksum",bbuf,bblen,0);

    if (pubfname==NULL) {
        pubfname="esnikeys.pub";
    }
    FILE *pubfp=fopen(pubfname,"wb");
    if (pubfp==NULL) {
        fprintf(stderr,"fopen error (line:%d)\n",__LINE__);
        exit(7);
    }
    if (fwrite(bbuf,1,bblen,pubfp)!=bblen) {
        fprintf(stderr,"fopen error (line:%d)\n",__LINE__);
        exit(8);
    }
    fclose(pubfp);

	OPENSSL_free(public);

    return(0);
}


int main(int argc, char **argv)
{
    return mk_esnikeys(argc, argv);
}
