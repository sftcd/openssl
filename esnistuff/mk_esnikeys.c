/*
 * Copyright 2018,2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This is a standalone ESNIKeys Creator main file to start in on esni
 * in OpenSSL style, as per https://tools.ietf.org/html/draft-ietf-tls-esni-02
 * and now also https://tools.ietf.org/html/draft-ietf-tls-esni-02
 * Author: stephen.farrell@cs.tcd.ie
 * Date: 20190313
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/esni.h>
// for getopt()
#include <getopt.h>

// for getaddrinfo()
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_ESNIKEYS_BUFLEN 1024 ///< just for laughs, won't be that long
#define MAX_ESNI_COVER_NAME 254 ///< longer than this won't fit in SNI
#define MAX_ESNI_ADDRS   16 ///< max addresses to include in AddressSet
#define MAX_PADDING 40 ///< max padding to use when folding DNS records
#define MAX_FMT_LEN 16 ///< max length to allow for generated format strings
#define MAX_ZONEDATA_BUFLEN 2*MAX_ESNI_COVER_NAME+10*MAX_ESNIKEYS_BUFLEN+24*MAX_ESNI_ADDRS

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
 * @brief write draft-02 TXT zone fragment to buffer for display or writing to file
 *
 * @param sbuf where zone fragment will be written
 * @param slen length of sbuf
 * @param buf binary public key data
 * @param blen length of buf
 * @param ttl is the TTL to use
 * @param owner_name fully-qualified DNS owner, without trailing dot
 *
 */
static void sp_esni_txtrr(unsigned char *sbuf,
                        size_t slen,
                        unsigned char *buf,
                        size_t blen,
                        int ttl,
                        char *owner_name)
{
    unsigned char *sp=sbuf;
    char *owner_string=NULL;

    if (sbuf==NULL) {
        return;
    }
    memset(sbuf,0,slen);          /* clear buffer for zone data */
    if (buf==NULL) {
        return;
    }
    if (owner_name==NULL) {
        owner_string="invalid.example";
    } else {
        owner_string=owner_name;
    }

    char *outp=malloc(blen);
    if (outp==NULL) {
        return;
    }
    int toolong=slen-(strlen(owner_string)+20);
    int b64len = EVP_EncodeBlock(outp, (unsigned char *)buf, blen);
    if (b64len>toolong) {
        return;
    }
    outp[b64len]='\0';

    snprintf(sbuf,slen,"%s. %d IN TXT \"%s\"\n",owner_string,ttl,outp); 

    return;

}

/**
 * @brief write zone fragment to buffer for display or writing to file
 *
 * @param sbuf where zone fragment will be written
 * @param slen length of sbuf
 * @param buf binary public key data
 * @param blen length of buf
 * @param typecode DNS TYPE code to use
 * @param ttl is the TTL to use
 * @param owner_name fully-qualified DNS owner, without trailing dot
 *
 */
static void sp_esni_prr(unsigned char *sbuf,
                        size_t slen,
                        unsigned char *buf,
                        size_t blen,
                        unsigned short typecode,
                        int ttl,
                        char *owner_name)
{
    unsigned char *sp=sbuf;
    char *owner_string=NULL;

    if (sbuf==NULL) {
        return;
    }
    memset(sbuf,0,slen);          /* clear buffer for zone data */
    if (buf==NULL) {
        return;
    }
    if (owner_name==NULL) {
        owner_string="invalid.example";
    } else {
        owner_string=owner_name;
    }

    char fold_fmt[MAX_FMT_LEN];
    int padwidth;
    int available=MAX_ZONEDATA_BUFLEN;
    int chunk=0;
    
    int i;
    for (i=0; (i!=blen) && (chunk < available); i++) {
        if (i==0) {
            /* Process prolog */
            chunk = snprintf(sp, available,
                             "%s. %d IN TYPE%d \\# ",
                             owner_string, ttl, typecode);

            if (chunk < available) {
                padwidth = (chunk<MAX_PADDING) ? chunk : MAX_PADDING;
                if (snprintf(fold_fmt,MAX_FMT_LEN,"\n%%%ds",padwidth)
                    >= MAX_FMT_LEN) {
                    memset(sbuf,0,chunk); /* reset buffer */
                    return;
                }
            }

            if (chunk < available) {
                available -= chunk; sp += chunk;
                chunk = snprintf(sp, available, "%zd (",blen);
            }
        }

        /* Process each octet in buffer */
        if (chunk < available) {
            available -= chunk; sp += chunk;
            if (i%16==0) {
                chunk = snprintf(sp, available, fold_fmt,"");
            }
            else if (i%2==0) {
                chunk = snprintf(sp, available, " ");
            }
            else {
                chunk = 0;
            }
        }
        if (chunk < available) {
            available -= chunk; sp += chunk;
            chunk = snprintf(sp, available, "%02x",buf[i]);
        }
    }

    /* Process epilog: line-fold or space */
    if (chunk < available) { 
        available -= chunk; sp += chunk;
        if (i%16==0)
            chunk = snprintf(sp, available, fold_fmt,"");
        else
            chunk = snprintf(sp, available, " ");
    }
    
    /* Process epilog: closing paren */
    if (chunk < available) {
        available -= chunk; sp += chunk;
        chunk = snprintf(sp, available, ")\n");
    }

    if (chunk >= available) {
        memset(sbuf,0,slen-available); /* reset buffer */
    }

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
     * copy input with zero'd checksum, do SHA256 hash, compare with
     * checksum, tedious but easy enough
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
    printf("Create an ESNIKeys data structure as per draft-ietf-tls-esni-[02|03]\n");
    printf("Usage: \n");
    printf("\t%s [-V version] [-o <fname>] [-p <privfname>] [-d duration] \n",prog);
    printf("\t\t\t[-P public-/cover-name] [-z zonefrag-file] [-g] [-J [file-name]] [-A [file-name]]\n"); 
    printf("where:\n");
    printf("-V specifies the ESNIKeys version to produce (default: 0xff01; 0xff02 allowed)\n");
    printf("-o specifies the output file name for the binary-encoded ESNIKeys (default: ./esnikeys.pub)\n");
    printf("-p specifies the output file name for the corresponding private key (default: ./esnikeys.priv)\n");
    printf("-d duration, specifies the duration in seconds from, now, for which the public share should be valid (default: 1 week), The DNS TTL is set to half of this value.\n");
    printf("-g grease - adds a couple of nonsense extensions to ESNIKeys for testing purposes.\n");
    printf("-P specifies the public-/cover-name value\n");
    printf("-z says to output the zonefile fragment to the specified file\n");
    printf("-J specifies the name of a JSON output file\n");
    printf("If <privfname> exists already and contains an appropriate value, then that key will be used without change.\n");
    printf("There is no support for crypto options - we only support TLS_AES_128_GCM_SHA256 and X25519.\n");
    printf("Fix that if you like:-)\n");
    printf("-A is only supported for version 0xff02 and not 0xff01\n");
    printf("-A says to include an AddressSet extension\n");
    printf("\n");
    printf("If a filename ie given with -A then that should contain one IP address per line.\n");
    printf("If no filename is given with -A then we'll look up the A and AAAA for the cover-/public-name and use those.\n");
    printf("   and make that -A the last argument provided or we'll mess up!\n");
    printf("If no zonefrag-file is provided a default zonedata.fragment file will be created\n");
    exit(1);
}

/**
 * @brief map version string like 0xff01 to unsigned short
 * @param arg is the version string, from command line
 * @return is the unsigned short value (with zero for error cases)
 */
static unsigned short verstr2us(char *arg)
{
    long lv=strtol(arg,NULL,0);
    unsigned short rv=0;
    if (lv < 0xffff && lv > 0 ) {
        rv=(unsigned short)lv;
    }
    return(rv);
}

/**
 * @brief Add an adderess to the list if it's not there already
 * @param
 * @return 0 if added, 1 if already present, <0 for error
 */
static int add2alist(char *ips[], int *nips_p, char *line)
{
    int nips=0;
    int added=0;

    if (!ips || !nips_p || !line) {
        return -1;
    }
    nips=*nips_p;

    if (nips==0) {
        ips[0]=strdup(line);
        nips=1;
        added=1;
    } else {
        int found=0;
        for (int i=0;i!=nips;i++) {
            if (!strncmp(ips[i],line,strlen(line))) {
                found=1;
                return(1);
            }
        }
        if (!found) {
            if (nips==MAX_ESNI_ADDRS) {
                fprintf(stderr,"Too many addresses found (max is %d) - exiting\n",MAX_ESNI_ADDRS);
                exit(1);
            }
            ips[nips]=strdup(line);
            nips++;
            added=1;
        }
    }
    if (added) {
        *nips_p=nips;
        return(0);
    }
    return(-2);
}

/**
 * @brief make up AddressSet extension
 *
 * @param asetfname names a file with one IPv4 or IPv6 address per line
 * @param cover_name names the cover site
 * @param elen returns the length of the AddressSet extension encoding
 * @param eval returns the AddressSet extension encoding (including the type)
 * @return 1 for success, 0 for error
 */
static int mk_aset(char *asetfname, char *cover_name, size_t *elen, unsigned char **eval)
{
    if (elen==NULL || eval==NULL) {
        return(0);
    }
    size_t cnlen=(cover_name==NULL?0:strlen(cover_name));
    int nips=0;
    char *ips[MAX_ESNI_ADDRS];
    memset(ips,0,MAX_ESNI_ADDRS*sizeof(char*));
    if (asetfname!=NULL) {
        /* open file and read 1 IP per line */
        FILE *fp=fopen(asetfname,"r");
        if (!fp) {
            fprintf(stderr,"Can't open address file (%s)\n",asetfname);
            return(0);
        }
        char * line = NULL;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, fp)) != -1) {
            if (line[0]=='#') {
                continue;
            }
            line[read-1]='\0'; /* zap newline */
            int rv=add2alist(ips,&nips,line);
            if (rv<0) {
                fprintf(stderr,"add2alist failed (%d)\n",rv);
                return(0);
            }
        }
        if (line)
            free(line);
        fclose(fp);
    } else if (cnlen!=0) {
        /* try getaddrinfo() */
        struct addrinfo *ai,*rp=NULL;
        int rv=getaddrinfo(cover_name,NULL,NULL,&ai);
        if (rv!=-0) {
            fprintf(stderr,"getaddrinfo failed (%d) for %s\n",rv,cover_name);
            return(0);
        }
        for (rp=ai;rp!=NULL;rp=rp->ai_next) {
            // just print first
            char astr[100];
            astr[0]='\0';
            struct sockaddr *sa=rp->ai_addr;
            if (rp->ai_family==AF_INET) {
                inet_ntop(rp->ai_family, 
                          &((struct sockaddr_in *)sa)->sin_addr,
                          astr, sizeof astr);
            } else if (rp->ai_family==AF_INET6) {
                inet_ntop(rp->ai_family, 
                          &((struct sockaddr_in6 *)sa)->sin6_addr,
                          astr, sizeof astr);
            }
            int rv=add2alist(ips,&nips,astr);
            if (rv<0) {
                fprintf(stderr,"add2alist failed (%d)\n",rv);
                return(0);
            }
        }
        freeaddrinfo(ai);
    }

    /* 
     * put those into extension buffer
     */
    unsigned char tmpebuf[MAX_ESNIKEYS_BUFLEN]; 
    unsigned char *tp=tmpebuf;
    for (int i=0;i!=nips;i++) {
        /* 
         * it's IPv6 if it has a ':" otherwise IPv4
         * we do this here and not based on getaddrinfo because they may
         * have come from a file - could be better done later I guess
         */
        int rv=0;
        if (strrchr(ips[i],':')) {
            printf("IPv6 Address%d: %s\n",i,ips[i]);
            *tp++=0x06;
            rv=inet_pton(AF_INET6,ips[i],tp);
            if (rv!=1) {
                fprintf(stderr,"Failed to convert string (%s) to IP address\n",ips[i]);
                return(0);
            }
            tp+=16;
        } else {
            printf("IPv4 Address%d: %s\n",i,ips[i]);
            *tp++=0x04;
            rv=inet_pton(AF_INET,ips[i],tp);
            if (rv!=1) {
                fprintf(stderr,"Failed to convert string (%s) to IP address\n",ips[i]);
                return(0);
            }
            tp+=4;
        }
        if ((tp-tmpebuf)>(MAX_ESNIKEYS_BUFLEN-100)) {
            fprintf(stderr,"Out of space converting string (%s) to IP address\n",ips[i]);
            return(0);
        }
    }

    /*
     * free strings
     */
    for (int i=0;i!=nips;i++) {
        free(ips[i]);
    }

    int nelen=(tp-tmpebuf);
    int exttype=ESNI_ADDRESS_SET_EXT;
    if (nelen>ESNI_MAX_RRVALUE_LEN) {
        fprintf(stderr,"Encoded extensions too big (%d)\n",nelen);
        return(0);
    }
    unsigned char *extvals=NULL;
    extvals=(unsigned char*)malloc(4+nelen);
    if (!extvals) {
        fprintf(stderr,"Out of space converting string to IP address\n");
        return(0);
    }
    extvals[0]=(exttype>>8)%256;
    extvals[1]=exttype%256;
    extvals[2]=(nelen>>8)%256;
    extvals[3]=nelen%256;
    memcpy(extvals+4,tmpebuf,nelen);

    *elen=nelen+4;
    *eval=extvals;

    return(1);
}

/**
 * @brief return a greasy extension value
 *
 * @param type - the extension type to use
 * @param elen - returns the extension length
 * @param eval - the octets of the extension encoding
 * @return 1 for good, 0 for error
 */
static int mk_grease_ext(int type, size_t *elen, unsigned char **eval)
{
    unsigned char blen=0x00;
    RAND_bytes(&blen,1);
    unsigned char *extvals=NULL;
    extvals=OPENSSL_malloc(blen+8);
    size_t evoffset=0;
    /*
     * if generated length is even then add an emptyvalued extension before 
     */
    if (blen%2) {
        printf("Adding empty grease\n");
        const unsigned char emptygreaseext[]={0xff,0xf3,0x00,0x00};
        memcpy(extvals,emptygreaseext,sizeof(emptygreaseext));
        evoffset+=4;
    }
    extvals[evoffset++]=(type>>8)%256;
    extvals[evoffset++]=type%256;
    extvals[evoffset++]=(blen>>8)%256;
    extvals[evoffset++]=blen%256;
    RAND_bytes(extvals+evoffset,blen);
    *elen=blen+evoffset;
    *eval=extvals;
    return(1);
}

/**
 * @brief Make an X25519 key pair and ESNIKeys structure for the public
 *
 * @todo TODO: check out NSS code to see if I can make same format private
 * @todo TODO: Decide if supporting private key re-use is even needed.
 */
static int mk_esnikeys(int argc, char **argv)
{
    // getopt vars
    int opt;

    char *pubfname=NULL; ///< public key file name
    char *privfname=NULL; ///< private key file name
    char *fragfname=NULL; ///< zone fragment file name
    unsigned short ekversion=0xff01; ///< ESNIKeys version value (default is for draft esni -02)
    char *cover_name=NULL; ///< ESNIKeys "public_name" field (here called cover name)
    size_t cnlen=0; ///< length of cover_name
    int includeaddrset=0; ///< whether or not to include an AddressSet extension
    char *asetfname=NULL; ///< optional file name for AddressSet values
    int duration=60*60*24*7; ///< 1 week in seconds
    int maxduration=duration*52*10; ///< 10 years max - draft -02 will definitely be deprecated by then:-)
    int minduration=3600; ///< less than one hour seems unwise
    int grease=0; ///< if set, we add a couple of nonsense extensions
    size_t gel1=0; ///< length of 1st grease extension buffer
    unsigned char *geb1=NULL;  ///< 1st grease buffer
    size_t gel2=0; ///< length of 1st grease extension buffer
    unsigned char *geb2=NULL;  ///< 1st grease buffer

    int extlen=0; ///< length of overall ESNIKeys extension value (with all extensions included)
    unsigned char *extvals=NULL; ///< buffer with all encoded ESNIKeys extensions

    int zblen=0; ///< length of output zone fragment (if any)
    unsigned char zbuf[MAX_ZONEDATA_BUFLEN]; //< buffer for zone fragment (if any)

    int jsonout=0; ///< whether or not we want a JSON output file
    char *jsonfname=NULL; ///< json output file

    /*
     * AddressSet 
     */
    size_t asetlen=0;
    unsigned char *asetval=NULL;

    // check inputs with getopt
    while((opt = getopt(argc, argv, ":J:A:P:V:?ho:p:d:z:g")) != -1) {
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
        case 'z':
            fragfname=optarg;
            break;
        case 'd':
            duration=atoi(optarg);
            break;
        case 'g':
            grease=1;
            break;
        case 'V':
            ekversion=verstr2us(optarg);
            break;
        case 'P':
            cover_name=optarg;
            break;
        case 'A':
            includeaddrset=1;
            asetfname=optarg;
            break;
        case 'J':
            jsonout=1;
            jsonfname=optarg;
            break;
        case ':':
            switch (optopt) {
            case 'A':
                includeaddrset=1;
                break;
            case 'J':
                jsonout=1;
                break;
            default: 
                fprintf(stderr, "Error - No such option: `%c'\n\n", optopt);
                usage(argv[0]);
            }
            break;
        default:
            fprintf(stderr, "Error - No such option: `%c'\n\n", optopt);
            usage(argv[0]);
        }
    }

    if (ekversion==0xff01 && includeaddrset!=0) {
        fprintf(stderr,"Version 0xff01 doesn't support AddressSet - exiting\n\n");
        usage(argv[0]);
    }
    if (duration <=0) {
        fprintf(stderr,"Can't have negative duration (%d)\n\n",duration);
        usage(argv[0]);
    }
    if (duration>=maxduration) {
        fprintf(stderr,"Can't have >10 years duration (%d>%d)\n\n",duration,maxduration);
        usage(argv[0]);
    }
    if (duration<minduration) {
        fprintf(stderr,"Can't have <1 hour duration (%d<%d)\n\n",duration,minduration);
        usage(argv[0]);
    }
    switch(ekversion) {
    case 0xff01: /* esni draft -02 */
    case 0xff02: /* esni draft -03 */
        cnlen=(cover_name==NULL?0:strlen(cover_name));
        if (cnlen > MAX_ESNI_COVER_NAME) {
            fprintf(stderr,"Cover name too long (%zd), max is %d\n\n",cnlen,MAX_ESNI_COVER_NAME);
            usage(argv[0]);
        }
        if (cnlen > 0 && cover_name[cnlen-1]=='.') {
            cover_name[cnlen-1] = 0; /* strip trailing dot to canonicalize */
        }
        break;
    default:
        fprintf(stderr,"Bad version supplied: %x\n\n",ekversion);
        usage(argv[0]);
    }

    /* handle AddressSet stuff */
    if (ekversion==0xff02 && includeaddrset!=0) {
        int rv=mk_aset(asetfname,cover_name,&asetlen,&asetval);
        if (rv!=1) {
            fprintf(stderr,"mk_aset failed - exiting\n");
            exit(1);
        }
    }

    if (grease==1) {
        int rv=mk_grease_ext(0xfff1,&gel1,&geb1);
        if (rv!=1) {
            fprintf(stderr,"mk_grease_ext failed - exiting\n");
            exit(1);
        }
        rv=mk_grease_ext(0xfff2,&gel2,&geb2);
        if (rv!=1) {
            fprintf(stderr,"mk_grease_ext failed - exiting\n");
            exit(1);
        }
    }

    /*
     * Package up (for now, one) extensions as needed
     */
    if (asetlen>0 || gel1 >0 || gel2 >0) {
        extlen=asetlen+gel1+gel2;
        extvals=OPENSSL_malloc(extlen+2);
        if (extvals==NULL) {
            fprintf(stderr,"can't make space for extvals - exiting\n");
            exit(1);
        }

        extvals[0]=(extlen/256);
        extvals[1]=(extlen%256);
        unsigned char *evp=extvals+2;
        if (gel1>0) {
            memcpy(evp,geb1,gel1);
            evp+=gel1;
            OPENSSL_free(geb1);
        }
        if (asetlen>0){
            memcpy(evp,asetval,asetlen);
            evp+=asetlen;
            OPENSSL_free(asetval);
        }
        if (gel2>0) {
            memcpy(evp,geb2,gel2);
            evp+=gel2;
            OPENSSL_free(geb2);
        }
        extlen+=2;

    }

    if (privfname==NULL) {
        privfname="esnikeys.priv";
    }
    EVP_PKEY *pkey = NULL;
    FILE *privfp=fopen(privfname,"rb");
    if (privfp!=NULL) {
        /*
         * read contents and re-use key if it's a good key
         *
         * The justification here is that we might need to handle public
         * values that overlap, e.g. due to TTLs being set differently
         * by different hidden domains or some such. (I.e. I don't know
         * yet if that's really needed or not.)
         *
         * Note though that re-using private keys like this could end
         * up being DANGEROUS, in terms of damaging forward secrecy
         * for hidden service names. Not sure if there're other possible
         * bad effects, but certainly likely safer operationally to 
         * use a new key pair every time. (Which is also supported of
         * course.)
         *
         */
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
    time_t na=nb+1.5*duration;

    /*
     * Here's a hexdump of one draft-02 cloudflare value:
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
     * draft-03 adds this just after the checksum:
     *         opaque public_name<1..2^16-1>;
     *
     * I don't yet have anyone else's example of a -03/ff02 value but here's one
     * of mine where this was called with "-P www.cloudflarecom -A":
     *
     * 00000000  ff 02 36 60 b9 a0 00 12  77 77 77 2e 63 6c 6f 75  |..6`....www.clou|
     * 00000010  64 66 6c 61 72 65 2e 63  6f 6d 00 24 00 1d 00 20  |dflare.com.$... |
     * 00000020  c7 e8 4b 92 59 d6 1c 58  36 6c eb 26 46 ec 9d 3d  |..K.Y..X6l.&F..=|
     * 00000030  fb 3d ab de 9a 94 ac 34  7e bd 7c 2a c4 ae e3 60  |.=.....4~.|*...`|
     * 00000040  00 02 13 01 01 04 00 00  00 00 5c 89 6e 0c 00 00  |..........\.n...|
     * 00000050  00 00 5c 92 a8 8c 00 2f  10 01 00 2c 06 26 06 47  |..\..../...,.&.G|
     * 00000060  00 00 00 00 00 00 00 00  00 c6 29 d6 a2 06 26 06  |..........)...&.|
     * 00000070  47 00 00 00 00 00 00 00  00 00 c6 29 d7 a2 04 c6  |G..........)....|
     * 00000080  29 d6 a2 04 c6 29 d7 a2                           |)....)..|
     * 00000088
     *
     */

    unsigned char bbuf[MAX_ESNIKEYS_BUFLEN]; ///< binary buffer
    unsigned char *bp=bbuf;
    memset(bbuf,0,MAX_ESNIKEYS_BUFLEN);
    *bp++=(ekversion>>8)%256; 
    *bp++=(ekversion%256);// version = 0xff01 or 0xff02
    memset(bp,0,4); bp+=4; // space for checksum
    if (cnlen > 0 && ekversion==0xff02) {
        /* draft -03 has public_name here, -02 hasn't got that at all */
        *bp++=(cnlen>>8)%256;
        *bp++=cnlen%256;
        memcpy(bp,cover_name,cnlen); bp+=cnlen;
    }
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
    if (extlen==0) {
        *bp++=0x00;
        *bp++=0x00; // no extensions
    } else {
        memcpy(bp,extvals,extlen);
        bp+=extlen;
        free(extvals);
    }
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
        fprintf(stderr,"fwrite error (line:%d)\n",__LINE__);
        exit(8);
    }
    fclose(pubfp);

    if (ekversion==0xff01) {

        /* Prepare zone fragment in buffer */
        sp_esni_txtrr(zbuf,MAX_ZONEDATA_BUFLEN,bbuf,bblen,duration/2,cover_name);
        zblen=strlen(zbuf);
        if (zblen==0) {
            fprintf(stderr,"zone fragment error (line:%d)\n",__LINE__);
            exit(19);
        }
    }

    if (ekversion==0xff02) {

        /* Prepare zone fragment in buffer */
        sp_esni_prr(zbuf,MAX_ZONEDATA_BUFLEN,bbuf,bblen,0xff9f,duration/2,cover_name);
        zblen=strlen(zbuf);
        if (zblen==0) {
            fprintf(stderr,"zone fragment error (line:%d)\n",__LINE__);
            exit(9);
        }
   }

   if (zblen>0) {
   
        puts("OPENSSL: zone fragment:");
        printf("%s", zbuf);     /* Display zone fragment on stdout */

        /* Ready file where zone fragment will be written */
        if (fragfname==NULL) {
            fragfname="zonedata.fragment";
        }
        FILE *fragfp=fopen(fragfname,"w");
        if (fragfp==NULL) {
            fprintf(stderr,"fopen error (line:%d)\n",__LINE__);
            exit(7);
        }

        /* Write zone fragment to file */
        if (fwrite(zbuf,1,zblen,fragfp)!=zblen) {
            fprintf(stderr,"fwrite error (line:%d)\n",__LINE__);
            exit(8);
        }

        fclose(fragfp);
    }

    if (jsonout==1) {
        /*
         * write out a JSON file
         */
        char jsonstr[MAX_ZONEDATA_BUFLEN];
        memset(jsonstr,0,MAX_ZONEDATA_BUFLEN);
        char esnistr[MAX_ZONEDATA_BUFLEN/2];
        memset(esnistr,0,MAX_ZONEDATA_BUFLEN/2);

        /*
         * Make up JSON string
         */
        if (ekversion==0xff01) {
            int b64len = EVP_EncodeBlock(esnistr, (unsigned char *)bbuf, bblen);
            esnistr[b64len]='\0';
        }
        if (ekversion==0xff02) {
            /* binary -> ascii hex */
            char ch3[3];
            for (int i=0;i<(MAX_ZONEDATA_BUFLEN/4) && i!=bblen;i++) {
                snprintf(ch3,3, "%02X",bbuf[i]);
                esnistr[2*i]=ch3[0];
                esnistr[2*i+1]=ch3[1];

            }
        }

        snprintf(jsonstr,MAX_ZONEDATA_BUFLEN,
                "{\n   \"ESNIKeys.version\": 0x%4x,\n   \"desired-ttl\": %d,\n   \"ESNIKeys\": \"%s\"\n}\n", 
                ekversion, duration/2, esnistr);

        size_t jlen=strlen(jsonstr);

        /* Ready file where zone fragment will be written */
        if (jsonfname==NULL) {
            jsonfname="zonedata.json";
        }
        FILE *jsonfp=fopen(jsonfname,"w");
        if (jsonfp==NULL) {
            fprintf(stderr,"fopen error (line:%d)\n",__LINE__);
            exit(17);
        }

        /* Write zone fragment to file */
        if (fwrite(jsonstr,1,jlen,jsonfp)!=jlen) {
            fprintf(stderr,"fwrite error (line:%d)\n",__LINE__);
            exit(18);
        }

        fclose(jsonfp);
    }

    OPENSSL_free(public);

    return(0);
}


int main(int argc, char **argv)
{
    return mk_esnikeys(argc, argv);
}

// -*- Make Emacs behave
// -*- Local Variables:
// -*- c-basic-offset: 4
// -*- indent-tabs-mode: nil
// -*- End:
