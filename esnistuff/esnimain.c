/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a temporary library and main file to start in on esni
 * in OpenSSL style, as per https://tools.ietf.org/html/draft-ietf-tls-esni-02
 * Author: stephen.farrell@cs.tcd.ie
 * Date: 20181103
 */

#include <stdio.h>
#include <ssl_locl.h>
#include <../ssl/packet_locl.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/esni.h>
#include <openssl/esnierr.h>
// for getopt()
#include <getopt.h>


/*
 * For local testing
 */
#define TESTMAIN

#ifdef TESTMAIN

void usage(char *prog) 
{
    /*
     * TODO: moar text
     */
    printf("%s -e ESNI [-p priv] [-r client_random] [-s encservername] [-f covername] [-k h/s key_share] [-n nonce]\n",prog);
    exit(1);
}

// code within here need not be openssl-style, but we'll migrate there:-)
int main(int argc, char **argv)
{
    char *encservername=NULL; // the one we'll encrypt
    char *covername=NULL; // the one we'll (optionally) leave visible 
    char *esni_str=NULL; // esni b64 string from DNS
    // for debugging purposes
    char *client_random_str=NULL;
    char *hs_key_share_str=NULL;
    char *nonce_str=NULL;
    char *private_str=NULL; // input ECDH private
    int rv;
    unsigned char *nbuf=NULL;

    // getopt vars
    int opt;
    
    // check inputs with getopt
    while((opt = getopt(argc, argv, "?hs:e:p:r:k:f:n:")) != -1) {
        switch(opt) {
            case 'h':
            case '?':
                usage(argv[0]);
                break;
            case 'r':
                client_random_str=optarg;
                break;
            case 'p':
                private_str=optarg;
                break;
            case 'e':
                esni_str=optarg;
                break;
            case 'k':
                hs_key_share_str=optarg;
                break;
            case 's':
                encservername=optarg;
                break;
            case 'n':
                nonce_str=optarg;
                break;
            case 'f':
                covername=optarg;
                break;
            default:
                fprintf(stderr, "Error - No such option: `%c'\n\n", optopt);
                usage(argv[0]);
        }
    }
    
    if (!ERR_load_ESNI_strings()) {
        printf("Can't init error strings - exiting\n");
        exit(1);
    }
    // init ciphers
    if (!ssl_load_ciphers()) {
        printf("Can't init ciphers - exiting\n");
        exit(1);
    }
    if (!RAND_set_rand_method(NULL)) {
        printf("Can't init (P)RNG - exiting\n");
        exit(1);
    }

    FILE *fp=NULL;
    BIO *out=NULL;
    SSL_ESNI *esnikeys=NULL;
    CLIENT_ESNI *the_esni=NULL;
    /* 
     * fake client random
     */
    if (client_random_str!=NULL && strlen(client_random_str) != 64 ) {
        printf("Weird client_random length - exiting\n");
        exit(1);
    }
    size_t cr_len=SSL3_RANDOM_SIZE;
    unsigned char client_random[SSL3_RANDOM_SIZE];
#ifdef ESNI_CRYPT_INTEROP
    if (client_random_str==NULL) {
        RAND_bytes(client_random,cr_len);
    } else {
        int i; /* loop counter - android build doesn't like C99;-( */
        for (i=0;i!=32;i++) {
            client_random[i]=AH2B(client_random_str[2*i])*16+AH2B(client_random_str[(2*i)+1]);
        }
    }
#else
    RAND_bytes(client_random,cr_len);
#endif

    /*
     * fake client keyshare
     */
    if (hs_key_share_str!=NULL && strlen(hs_key_share_str) != 64 ) {
        printf("Weird hs_key_share length - exiting\n");
        exit(1);
    }
    uint16_t cid=0x001d;
    size_t ckl=32;
    unsigned char ck[32];
#ifdef ESNI_CRYPT_INTEROP
    if (hs_key_share_str==NULL) {
        // RAND_bytes(ck,32);
        memset(ck,0xA5,32);
    } else {
		int i; /* loop counter - android build doesn't like C99;-( */
        for (i=0;i!=32;i++) {
            ck[i]=AH2B(hs_key_share_str[2*i])*16+AH2B(hs_key_share_str[(2*i)+1]);
        }
    }
#else
    memset(ck,0xA5,32);
#endif


    if (!(rv=SSL_esni_checknames(encservername,covername))) {
        printf("Bad names! %d\n",rv);
        goto end;
    }

    esnikeys=SSL_ESNI_new_from_buffer(strlen(esni_str),esni_str);
    if (esnikeys == NULL) {
        printf("Can't create SSL_ESNI from b64!\n");
        goto end;
    }

#ifdef ESNI_CRYPT_INTEROP
    if (private_str!=NULL) {
        SSL_ESNI_set_private(esnikeys,private_str);
    }
    if (nonce_str!=NULL) {
        nbuf=OPENSSL_malloc(strlen(nonce_str)/2+1);
        if (nbuf==NULL) {
            goto end;
        }
        size_t nlen=strlen(nonce_str)/2;
		int i; /* loop counter - android build doesn't like C99;-( */
        for (i=0;i!=nlen;i++) {
            nbuf[i]=AH2B(nonce_str[2*i])*16+AH2B(nonce_str[(2*i)+1]);
        }
        SSL_ESNI_set_nonce(esnikeys,nbuf,nlen);
    }
#else 
    if (private_str!=NULL) {
        printf("Can't use private_str if built without ESNI_CRYPT_INTEROP - exiting\n");
        goto end;
    }
    if (nonce_str!=NULL) {
        printf("Can't use nonce_str if built without ESNI_CRYPT_INTEROP - exiting\n");
        goto end;
    }
#endif

    fp=fopen("/dev/stdout","w");
    if (fp==NULL)
        goto end;

    out=BIO_new_fp(fp,BIO_CLOSE|BIO_FP_TEXT);
    if (out == NULL)
        goto end;

    esnikeys->encservername=OPENSSL_strndup(encservername,TLSEXT_MAXLEN_host_name);
    if (esnikeys->encservername==NULL)
        goto end;
    if (covername!=NULL) {
        esnikeys->covername=OPENSSL_strndup(covername,TLSEXT_MAXLEN_host_name);
        if (esnikeys->covername==NULL)
            goto end;
    } else {
        esnikeys->covername=NULL;
    }

    if (!SSL_ESNI_enc(esnikeys,cr_len,client_random,cid,ckl,ck,&the_esni)) {
        printf("Can't encrypt SSL_ESNI!\n");
        goto end;
    }

    if (!SSL_ESNI_print(out,esnikeys)) {
        printf("Can't print SSL_ESNI!\n");
        goto end;
    }

end:
    BIO_free_all(out);
    if (esnikeys!=NULL) {
        SSL_ESNI_free(esnikeys);
        OPENSSL_free(esnikeys);
    }
    OPENSSL_free(nbuf);
    return(0);
}
#endif




