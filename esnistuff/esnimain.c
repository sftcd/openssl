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
#include <../apps/apps.h>
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
    printf("%s -e ESNI [-p priv] [-r client_random] [-s encservername] [-f frontname] [-k h/s key_share] \n",prog);
    exit(1);
}

// code within here need not be openssl-style, but we'll migrate there:-)
int main(int argc, char **argv)
{
    // default for names
    const char *defname="www.cloudflare.com";
    char *encservername=NULL; // the one we'll encrypt
    char *frontname=NULL; // the one we'll (optionally) leave visible 
    char *esni_str=NULL; // esni b64 string from DNS
    // for debugging purposes
    char *private_str=NULL; // input ECDH private
    char *client_random_str=NULL;
    char *hs_key_share_str=NULL;
    int rv;
    // s_client gets stuff otherwise but for now...
    // usage: esni frontname esniname

    // getopt vars
    int opt;
    
    // check inputs with getopt
    while((opt = getopt(argc, argv, "?hs:e:p:r:k:f:")) != -1) {
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
            case 'f':
                frontname=optarg;
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
	if (client_random_str==NULL) {
    	RAND_bytes(client_random,cr_len);
	} else {
		for (int i=0;i!=32;i++) {
			client_random[i]=AH2B(client_random_str[2*i])*16+AH2B(client_random_str[(2*i)+1]);
		}
	}

    /*
     * fake client keyshare
     */
	if (hs_key_share_str!=NULL && strlen(hs_key_share_str) != 64 ) {
        printf("Weird hs_key_share length - exiting\n");
        exit(1);
	}
    size_t ckl=32;
    unsigned char ck[32];
	if (hs_key_share_str==NULL) {
    	RAND_bytes(ck,32);
    	memset(ck,0xA5,32);
	} else {
		for (int i=0;i!=32;i++) {
			ck[i]=AH2B(hs_key_share_str[2*i])*16+AH2B(hs_key_share_str[(2*i)+1]);
		}
	}


    if (!(rv=esni_checknames(encservername,frontname))) {
        printf("Bad names! %d\n",rv);
        goto end;
    }

    esnikeys=SSL_ESNI_new_from_base64(esni_str);
    if (esnikeys == NULL) {
        printf("Can't create SSL_ESNI from b64!\n");
        goto end;
    }

	if (private_str!=NULL) {
		SSL_ESNI_set_private(esnikeys,private_str);
	}

    fp=fopen("/dev/stdout","w");
    if (fp==NULL)
        goto end;

    out=BIO_new_fp(fp,BIO_CLOSE|BIO_FP_TEXT);
    if (out == NULL)
        goto end;

    if (!SSL_ESNI_enc(esnikeys,encservername,frontname,cr_len,client_random,ckl,ck,&the_esni)) {
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
    return(0);
}
#endif




