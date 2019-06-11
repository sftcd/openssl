
# OpenSSL Encrypted SNI Design

stephen.farrell@cs.tcd.ie, 20190610ish

This file describes the current design for our proof-of-concept 
openssl implementation of encrypted SNI.

- The code in our [fork](https://gitbub.com/sftcd/openssl) implements 
  both client and server sides of the ESNI Internet-draft
[draft-ietf-tls-esni-02](https://tools.ietf.org/html/draft-ietf-tls-esni-02)
spec.
- I've started to code up the [draft-ietf-tls-esni-03](https://tools.ietf.org/html/draft-ietf-tls-esni-03)
version, but so far have only done the ``mk_esnikeys`` command line tool (and that's
not very tested yet) and have also added handling of multivalued ESNIKeys RRs for
both -02 and -03 versions of ESNIKeys.
(API changes for that are not yet reflected below but are in the code.) 
Everything else to do with draft -03 is either non-existent or
untested as of now. And AFAIK there's nowhere to do interop testing just
yet, but that may change in a week or two.
- The most up to date
  [README.md](https://github.com/sftcd/openssl/tree/master/esnistuff) for that
code.

The -02 draft version of ESNI works by having the "hidden" domain publish a TXT
RR in the DNS below the name that would otherwise be present in an SNI
extension. That RR contains a public key usable to encrypt the name as a TLS
ClientHello extension when connecting to the IP address that goes with the
name.

The -03 draft changes the ESNIKeys RR to use a new RRTYPE and adds some
IP address handling.

## Our Goals

- Implement ESNI in a way that's helpful to the OpenSSL project
- Help the standardisation process in the IETF
- Allow other folks to play with ESNI
- Help make ESNI more widely available/usable 
- Ultimately - maybe some of this code might end up part of a release
when there's an ESNI RFC

## Status

Our client build works against the www.cloudflare.com service (see
[here](https://www.cloudflare.com/ssl/encrypted-sni/) for details of what
CloudFlare have deployed) and e.g. allows passing www.ietf.org as the value in
the ESNI extension.  First you need to set ``LD_LIBRARY_PATH`` and get a fresh
public key from DNS, then you can pass that and your preferred hidden server
name on the command line as follows:

            $ export LD_LIBRARY_PATH=/path/to/your/libssl.so
            $ RRVAL=`dig +short txt _esni.www.cloudflare.com | sed -e 's/"//g'`
            $ openssl s_client -connect www.cloudflare.com:443 -esni www.ietf.org -esnirr $RRVAL
            ...usual s_client output...
            ESNI: success: cover: www.cloudflare.com, hidden: www.ietf.org
            ...usual s_client output...
            read R BLOCK
            ^D DONE
            $

The ``esnirr`` value above is time-dependent so won't work for that long.
(Perhaps an hour or so, not sure - the DNS TTL seems to be set to 3600 anyway).
With the above command, you need to hit CTRL-D (the "^D" shown above) to exit
as is usual with ``s_client``.

The server side code so far has only been tested on localhost against my client-side code
and an NSS client, and in a very limited manner.

This is not well-tested code at this point, it's just an initial proof-of-concept,
so **don't depend on this for anything**.

**SECURITY**: you'll notice that we use ``dig`` above. On my development
machine, we have installed
[stubby](https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Daemon+-+Stubby) so
these DNS queries and answers are using
[DoT](https://tools.ietf.org/html/rfc7858) and hence are encrypted. If you
didn't do that, (or equivalently use [DoH](https://tools.ietf.org/html/rfc8484)
as Firefox nightly does), there'd not be so much point in encrypting SNI unless
you somehow otherwise trust your connection to your recursive resolver.

## General Design/Implementation Notes

- If you want to dive right in to the main code: [esni.c](../ssl/esni.c) has (what I think is;-) good(ish) OPENSSL-style code
do the [-02 Internet-draft](https://tools.ietf.org/html/draft-ietf-tls-esni-02),
and the main header file is [esni.h](../include/openssl/esni.h).
- We don't do any DNS queries from within the OpenSSL library. We just take the
  required inputs and run the protocol.
- ``s_client`` currently tells the OpenSSL library to check if the TLS server cert matches the
name from the ESNI payload. That could be configurable later, but for now, if 
they don't match, the ``SSL_get_esni_status`` call at the end of 
``s_client`` will report an error.
- We want to be relatively easily able to evolve the code as the
  standardisation process continues, so many intermediate cryptographic
values are stored in the ``SSL_ESNI`` structure to help  us more easily figure
out interop issues. That has been v. useful esp. vs. the [NSS ESNI implementation](https://hg.mozilla.org/projects/nss/file/tip/lib/ssl/tls13esni.c)
which we used during development.
As the spec matures, a lot of those values won't be needed, and some of
the related code wouldn't be part of a release. (Such code will
be protected via  ``#ifdef ESNI_CRYPTO_INTEROP`` - that's not
yet well-done.)
- Some padding is needed to avoid exposing which ESNI value is in-play due to the
  length of handshake messages.
  Our (perhaps over-subtle) goal could be to pad to the longest cert length as described 
  in the I-D. The cert-verify message however can also need padding if key lengths differ.
  For now, our super-crude default padding scheme just calls the existing openssl padding ``SSL_CTX_set_block_padding``
  with a size of 486 bytes, which should mask some lengths. Those calls are made
  from ``SSL_esni_server_enable`` and ``SSL_esni_enable``. The effect of that
  is to pad up all TLS plaintexts to a multiple of 486 bytes, so
  it's ineffecient and could expose some information if we're unlucky with
  length boundaries. To pad less and just cover ESNI-related materials, ``s_server`` has a command line argument
  (``esnispecificpad``) 
  telling it to only pad Certificate and CertificateVerify messages. 
  486 bytes was chosen so as to allow 3 ciphertexts to fit within one MTU
  whilst not being too long nor too short.
  TODO: test how this affects a real application, once we have one
  integrated, and justify our default padding length better based on 
  that analysis.
- Session resumption: within ``s_client`` I've added checks that the ESNI
  value (or SNI value if ESNI isn't provided) matches the stored cert
  in the session. I also added the ``encservername`` as a field to the
  ``SSL_SESSION`` and populate that, as well as the existing ``hostname``
  that wasn''t populated at all, both just for logging/debugging
  purposes. Didn't do anything special server side, but testing 
  seems to indicate that the expected abbreviated handshakes are
  happening as planned. 

- Currently notes, (including this one), test scripts and a few other things are in an [esnistuff](https://github.com/sftcd/openssl/esnistuff/)
directory - that should disappear over time as we better integrate the
code following good project practice.
- For now, I'm using doxygen and [moxygen](https://github.com/sourcey/moxygen) to generate API and data structure
documentation. That'd probably be pruned when/if submitting a PR to the main
project, but should be helpful for now.

## Plans

- We may try integrate the client-side with some web client application such
  as wget or curl.
- We may try integrate the server-side with some web server (apache/nginx)

The timeline for our work is that Calum needs to be finished his project
by approx. end March 2019. Stephen will continue work on this thereafter.

## Design details

We have a simple client-side [test script](#test-script) that exercises various ``s_client`` options.

We modified the [``s_client``](#s_client-modifications) application to provide command line arguments
allowing one to turn on ESNI.

There's also a [server-side test script](#server-test-script) that can generate keys and run ``s_server``
in various ways.

We've documented our data structures and [APIs](#apis) that allow OpenSSL applications to support
ESNI.

We've some notes on our [extension and ``SSL_CTX``](#extension-and-ssl_ctx-handling) handling.


There're also a few notes about [testing](#testing).

Lastly, we note the [files](#file-changes) that are new, or modified.

## Client Side

### Test script

The ``usage()`` function for the [testclient.sh](https://github.com/sftcd/openssl/blob/master/esnistuff/testclient.sh) 
produces this:

            $ ./testclient.sh -h
            Running ./testclient.sh at 20190610-135659
            ./testclient.sh [-cHPpsrdnlvhLV] - try out encrypted SNI via openssl s_client
            -c [name] specifices a covername that I'll send as a clear SNI (NONE is special)
            -H means try connect to that hidden server
            -P [filename] means read ESNIKeys public value from file and not DNS
            -s [name] specifices a server to which I'll connect (localhost=>local certs, unless you also provide --realcert)
            -r (or --realcert) says to not use locally generated fake CA regardless
            -p [port] specifices a port (default: 443)
            -d means run s_client in verbose mode
            -v means run with valgrind
            -l means use stale ESNIKeys
            -S [file] means save or resume session from <file>
            -L means to not set esni_strict on the command line (be lax)
            -n means don't trigger esni at all
            -h means print this
            -V allows to specify which draft version to try (values: 02, 03, any; default: any)
            
            The following should work:
                ./testclient.sh -s www.cloudflare.com -c NONE -H ietf.org

The only really interesting concept embodied there is the idea of the
HIDDEN (e.g. www.ietf.org) service, the COVER (e.g. www.cloudflare.com) service 
and the SERVER (e.g. www.cloudflare.com) to which one connects can be
separately provided. (There're comments in the script about that.)

Other notes:

- If ``-c NONE`` is specifed, then no cleartext SNI is sent at all.
- COVER and SERVER default to being the same thing which is www.cloudflare.com
- ``-d`` runs with various debug tracing (including new
  ESNI specific tracing of cryptographic intermediate values)
- ``-v`` runs under valgrind and currently has no complaints (in the 
  nominal case)
- ``-S`` is to check session resumption (via TLS1.3 PSK). If the file
exists then we assume that's a stored session (i.e. ``-sess_in`` is
given to ``s_client``, if the file doesn't exist, we assume you want
to save the session to the file, so give ``-sess_out`` to ``s_client``.

There's another more basic test script [doit.sh](https://github.com/sftcd/openssl/blob/master/esnistuff/doit.sh)
that runs a standalone test application ([esnimain.c](https://github.com/sftcd/openssl/blob/master/esnistuff/esnimain.c))
which just tests the client-side ESNI APIs directly. That should become some kind of unit test in the main
build, and needs error cases added. Another variant of that [doit2.sh](https://github.com/sftcd/openssl/blob/master/esnistuff/doits2.sh)
does the same but now supplying more than one ESNIKeys value, as is allowed for in the -03 draft.

### ``s_client`` modifications

Here and elsewhere, almost all of our code changes are enclosed with ``#ifndef OPENSSL_NO_ESNI``

The [``apps/s_client.c``](https://github.com/sftcd/openssl/blob/master/apps/s_client.c)
has two new comnand line arguments:

- ``esni`` allows one to specifiy the HIDDEN service
- ``esnirr`` allows one to provide the (base64 encoded) RR value as per the spec.
   This value can match either the -02 (TXT RR) or -03 (new RRTYPE) versions of 
   the spec.
- ``esni_strict`` if set, then the ESNI value is compared to the TLS server cert
  and an error is returned if they dont match (both for new and stored sessions).
  At present this is off by default for ``s_client`` and the library, not quite
  sure that's correct. TODO: maybe swap the default, but that needs a change
  inside the main openssl ``make test`` which'd fail if we're strict on this
  when resuming a session.
  
There is new debugging output showing the ESNI intemediate values
if TLS message-level debugging is turned on via ``-msg`` 

There is a new output line that shows if the ESNI protocol 
succeeded, as shown in the 2nd last line below:

            ---
            New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
            Server public key is 2048 bit
            Secure Renegotiation IS NOT supported
            Compression: NONE
            Expansion: NONE
            No ALPN negotiated
            Early data was not sent
            Verify return code: 20 (unable to get local issuer certificate)
            ESNI: success: cover: www.cloudflare.com, hidden: www.ietf.org
            ---

When the new command line arguments are set, the following APIs are
called, nominally in this order:

- ``SSL_esni_checknames``: do a basic check on HIDDEN/COVER (e.g. not the same:-)
- ``SSL_ESNI_new_from_buffer``: decode the RR value and return an ``SSL_ESNI`` structure
- ``SSL_ESNI_print``: if ``-msg`` set, print the (initial) ``SSL_ESNI`` contents based on decoding 
- ``SSL_esni_enable``: modify the ``SSL *con`` structure to ask that ESNI be run
- ``SSL_ESNI_free``: release memory
- ``SSL_set_esni_callback``: if ``-msg`` set, register callback so (final) ``SSL_ESNI`` values are printed
- ``esni_cb``: is a local call-back function, it retrives and prints the ``SSL_ESNI`` structure
- ``SSL_ESNI_get_esni``: is used in ``esni_cb`` to get the ``SSL_ESNI`` structure which is printed via ``SSL_ESNI_print``
- ``SSL_get_esni_status``: check if ESNI worked or failed and print a status line

Notes:
- The function names above that contain the string ``SNI_ESNI`` either return
or take as a parameter a value of that type. Function names with a lowercase
esni substring do not. (This seems to be an OpenSSL convention.)

## Server-side 

Some open questions:

- Policy: should server have a concept of "only visible via ESNI"? E.g. some server
  certs might only ever be used when asked-for via ESNI.
- Policy: Various combinations of existing/non-existing SNI/ESNI and how to handle
  'em.

### Generating ESNIKeys

For now, all that exists is [mk_esnikeys.c](./mk_esnikeys.c), a simple command
line tool to generate a key pair and store the public in ESNIKeys format as 
per I-D -02 or -03. That's pretty limited (by design), it's usage explains most of
it:

            $ ./mk_esnikeys -h
            Create an ESNIKeys data structure as per draft-ietf-tls-esni-[02|03]
            Usage: 
                ./mk_esnikeys [-V version] [-o <fname>] [-p <privfname>] [-d duration] 
                        [-P public-/cover-name] [-A [file-name]]
            where:
            -V specifies the ESNIKeys version to produce (default: 0xff01; 0xff02 allowed)
            -o specifies the output file name for the binary-encoded ESNIKeys (default: ./esnikeys.pub)
            -p specifies the output file name for the corresponding private key (default: ./esnikeys.priv)
            -d duration, specifies the duration in seconds from, now, for which the public share should be valid (default: 1 week)
            If <privfname> exists already and contains an appropriate value, then that key will be used without change.
            There is no support for crypto options - we only support TLS_AES_128_GCM_SHA256, X25519 and no extensions.
            Fix that if you like:-)
            The following are only valid with -V 0xff02:
            -P specifies the public-/cover-name value
            -A says to include an AddressSet extension
            -P and -A are only supported for version 0xff02 and not 0xff01
            If a filename ie given with -A then that should contain one IP address per line.
            If no filename is given aith -A then we'll look up the A and AAAA for the cover-/public-name and use those.
            

The private key is in PEM format. (I'm not v. familiar with PEM format for
X25519 but hopefully it's portable, I've a TODO: to check.) For now the 
public key is the binary form of ESNIKeys so needs to be base64 encoded
before being put in a zone file.  To do that, you can use the ``base64 -w0``
command as shown in the sequence below:


            $ hd esnikeys.pub
            00000000  ff 01 e4 68 cb 8f 00 24  00 1d 00 20 7a e3 a1 b1  |...h...$... z...|
            00000010  63 7f d2 fe 21 ea ef 6b  9c 1a 1b 55 23 70 72 a2  |c...!..k...U#pr.|
            00000020  f4 29 4d 04 41 73 db fe  b5 c8 6f 07 00 02 13 01  |.)M.As....o.....|
            00000030  01 04 00 00 00 00 5c 10  10 1b 00 00 00 00 5c 19  |......\.......\.|
            00000040  4a 9b 00 00                                       |J...|
            00000044
            $ cat esnikeys.pub | base64 -w0 >esnikeys.b64
            $ cat esnikeys.b64
            /wHkaMuPACQAHQAgeuOhsWN/0v4h6u9rnBobVSNwcqL0KU0EQXPb/rXIbwcAAhMBAQQAAAAAXBAQGwAAAABcGUqbAAA= 

``mk_esnikeys`` should likely
end up in some tools or utils directory, but as the format will change we
won't do that  yet as, with luck, we may end up only needing to publish
much simpler values in DNS. Lastly, ``mk_esnikeys`` does currently
allow private key re-use, just in case that may be needed, but we should 
decide if that could be removed, which seems safer in general.

### Server test script

The [testserver.sh](./testserver.sh) script starts an ``openssl s_server``
and listens for connections. 
The ``usage()`` from that script is:

            $ ./testserver -h
            Running ./testserver.sh at 20181204-125134
            ./testserver.sh [-cHpsdnlvhK] - try out encrypted SNI via openssl s_server
              -H means serve that hidden server
              -D means find esni private/public values in that directory
              -d means run s_server in verbose mode
              -v means run with valgrind
              -n means don't trigger esni at all
              -c [name] specifices a covername that I'll accept as a clear SNI (NONE is special)
              -p [port] specifices a port (default: 443)
              -K to generate server keys 
              -h means print this
            
            The following should work:
                ./testserver.sh -c example.com -H foo.example.com
            To generate keys, set -H/-c as required:
                ./testserver.sh -K

The ``-K`` argument generates RSA key pairs (by calling ``make-example-ca.sh`` 
script) for ``example.com``
and ``foo.example.com`` which are the defaults for COVER and HIDDEN respectively. 
It also generates a fake CA and certifies those public keys. (That CA is set
to trusted by the ``testclient.sh`` script if the SERVER is ``localhost``.)
With
other inputs the script causes ``s_server`` to load those. All of the TLS
server certificates created are wildcard certs, e.g. for ``*.foo.example.com``.
That's so you can use many different names as HIDDEN or COVER. Note that these are keys
for the TLS server and are not ESNI public keys (generate those with ``mk_esnikeys``).

### ``s_server`` modifications

I added new command line arguments as follows:

- ``esnikey`` the private key filename for ESNI
- ``esnipub`` the name of the file containing the binary form of the corresponding ESNIKeys 
- ``esnidir`` the name of a directory containing pairs of the above
- ``esnispecificpad`` choose ESNI specific, and not general, padding

If ``esnikey`` and ``esnipub`` are set, we load those files.
If (additionally, or instead) ``esnidir`` is set the we try load in
all the pairs of matching ``<name>.priv`` and ``<name>.pub``
files found in that directory.

If ``esnispecificpad`` is set only the Certificate and CertificateVerity
messages are padded, to a multiple of 2000 and 500 bytes respectively.
Without this, we use our current default padding.

When those are set, the following API calls ensue:

- ``SSL_esni_server_enable`` - setup ESNI for the server context, can be called more than once, if >1 public/private value loaded
- ``esni_cb``: is a local call-back function, it retrives and prints the ``SSL_ESNI`` structure
- ``SSL_ESNI_get_esni_ctx``: is used to get the ``SSL_ESNI`` structure which is printed via ``SSL_ESNI_print``

We also added a new server name callback handler (``ssl_esni_servername_cb``) that
knows about ESNI. That treats the 2nd key/cert provided on the command line as a
possible ESNI target - we do X509 name matching between the (E)SNI supplied and
the certificate. (Standard ``s_server`` behaviour was to compare the SNI from
the TLS extension only against the ``-servername`` command line argument.) 
That should mean we get wildcard matching. TODO: test that!

## APIs

[Here's](./api.md) what moxygen produces from what doxygen produces (with a bit of sed
scrpting - see the [Makefile](./Makefile) ```make doc``` target. Since that's a build
target, it may be more up to date that the text below (but I'll try keep the stuff here
correct and brief).

The main data structures are:

- [ESNI_RECORD](./api.md#structesni__record__st) representing the DNS RR value
- [CLIENT_ESNI](./api.md#structclient__esni__st) representing the extension value for a ClientHello
- [SSL_ESNI](./api.md#structssl__esni__st) the internal state structure with the above plus gory crypto details

(Most of the content of) The main ESNI header file [esni.h](https://github.com/sftcd/openssl/blob/master/include/openssl/esni.h)
is below...


			#define ESNI_MAX_RRVALUE_LEN 2000 ///< Max size of a collection of ESNI RR values
			#define ESNI_SELECT_ALL -1 ///< used to duplicate all RRs in SSL_ESNI_dup
			
			/*
			 * ESNIKeys Extensions we know about...
			 */
			#define ESNI_ADDRESS_SET_EXT 0x1001 ///< AddressSet as per draft-03
			
			/* TODO: find another implemenation of this, there's gotta be one */
			#define A2B(__c__) (__c__>='0'&&__c__<='9'?(__c__-'0'):\
			                        (__c__>='A'&&__c__<='F'?(__c__-'A'+10):\
			                            (__c__>='a'&&__c__<='f'?(__c__-'a'+10):0)))
			
			
			/*
			 * Known text input formats for ESNIKeys RR values
			 * - can be TXT containing base64 encoded value (draft-02)
			 * - can be TYPE65439 containing ascii-hex string(s)
			 * - can be TYPE65439 formatted as output from dig +short (multi-line)
			 */
			#define ESNI_RRFMT_GUESS     0  ///< try guess which it is
			#define ESNI_RRFMT_BIN       1  ///< binary encoded
			#define ESNI_RRFMT_ASCIIHEX  2  ///< draft-03 ascii hex value(s catenated)
			#define ESNI_RRFMT_B64TXT    3  ///< draft-02 (legacy) base64 encoded TXT
			
			#define ESNI_DRAFT_02_VERSION 0xff01 ///< ESNIKeys version from draft-02
			#define ESNI_DRAFT_03_VERSION 0xff02 ///< ESNIKeys version from draft-03
			
			#define ESNI_RRTYPE 65439 ///< experimental (as per draft-03) ESNI RRTYPE
			
			
			/** 
			 * @brief Representation of what goes in DNS
			 *
			 * This is from the -02 I-D, in TLS presentation language:
			 *
			 * <pre>
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
			 * </pre>
			 * 
			 * Note that I don't like the above, but it's what we have to
			 * work with at the moment.
			 *
			 * This structure is purely used when decoding the RR value
			 * and is then discarded (selected values mapped into the
			 * SSL_ESNI structure).
			 *
			 * draft-03 changed this some ...
			 * <pre>
			 *  struct {
			 *         uint16 version;
			 *         uint8 checksum[4];
			 *         opaque public_name<1..2^16-1>;
			 *         KeyShareEntry keys<4..2^16-1>;
			 *         CipherSuite cipher_suites<2..2^16-2>;
			 *         uint16 padded_length;
			 *         uint64 not_before;
			 *         uint64 not_after;
			 *         Extension extensions<0..2^16-1>;
			 *     } ESNIKeys;
			 * </pre>
			 */
			typedef struct esni_record_st {
			    unsigned int version;
			    unsigned char checksum[4];
			    int public_name_len;
			    unsigned char *public_name;
			    unsigned int nkeys;
			    uint16_t *group_ids;
			    EVP_PKEY **keys;
			    size_t *encoded_lens;
			    unsigned char **encoded_keys;
				size_t nsuites;
				uint16_t *ciphersuites;
			    unsigned int padded_length;
			    uint64_t not_before;
			    uint64_t not_after;
			    unsigned int nexts;
			    unsigned int *exttypes;
			    size_t *extlens;
			    unsigned char **exts;
			} ESNI_RECORD;
			
			/**
			 * What we send in the esni CH extension:
			 *
			 * The TLS presentation language version is:
			 *
			 * <pre>
			 *     struct {
			 *         CipherSuite suite;
			 *         KeyShareEntry key_share;
			 *         opaque record_digest<0..2^16-1>;
			 *         opaque encrypted_sni<0..2^16-1>;
			 *     } ClientEncryptedSNI;
			 * </pre>
			 *
			 * Fields encoded in extension, these are copies, (not malloc'd)
			 * of pointers elsewhere in SSL_ESNI. One of these is returned
			 * from SSL_ESNI_enc, and is also pointed to from the SSL_ESNI
			 * structure.
			 *
			 */
			typedef struct client_esni_st {
				uint16_t ciphersuite;
			    size_t encoded_keyshare_len; 
			    unsigned char *encoded_keyshare;
			    size_t record_digest_len;
			    unsigned char *record_digest;
			    size_t encrypted_sni_len;
			    unsigned char *encrypted_sni;
			} CLIENT_ESNI;
			
			/**
			 * @brief The ESNI data structure that's part of the SSL structure 
			 *
			 * On the client-side, one of these is part of the SSL structure.
			 * On the server-side, an array of these is part of the SSL_CTX
			 * structure, and we match one of 'em to be part of the SSL 
			 * structure when a handshake is in porgress. (Well, hopefully:-)
			 *
			 * Note that SSL_ESNI_dup copies all these fields (when values are
			 * set), so if you add, change or remove a field here, you'll also
			 * need to modify that (in ssl/esni.c)
			 */
			typedef struct ssl_esni_st {
			    unsigned int version; ///< version from underlying ESNI_RECORD/ESNIKeys
			    char *encservername; ///< hidden server name
			    char *covername; ///< cleartext SNI (can be NULL)
			    char *public_name;  ///< public_name from ESNIKeys
			    int require_hidden_match; ///< If 1 then SSL_get_esni_status will barf if hidden name doesn't match TLS server cert. If 0, don't care.
			    int num_esni_rrs; ///< the number of ESNIKeys structures in this array
			    size_t encoded_rr_len;
			    unsigned char *encoded_rr; ///< Binary (base64 decoded) RR value
			    size_t rd_len;
			    unsigned char *rd; ///< Hash of the above (record_digest), using the relevant hash from the ciphersuite
				uint16_t ciphersuite; ///< from ESNIKeys after selection of local preference
			    uint16_t group_id;  ///< our chosen group e.g. X25519
			    size_t esni_peer_keyshare_len;  
			    unsigned char *esni_peer_keyshare; ///< the encoded peer's public value
			    EVP_PKEY *esni_peer_pkey; ///< the peer public as a key
			    size_t padded_length; ///< from ESNIKeys
			    uint64_t not_before; ///< from ESNIKeys (not currently used)
			    uint64_t not_after; ///< from ESNIKeys (not currently used)
			    int nexts; ///< number of extensions (not yet supported so >0 => fail)
			    unsigned int *exttypes; ///< array of extension types
			    size_t *extlens; ///< lengths of encoded extension octets
			    unsigned char **exts; ///< encoded extension octets
			    int naddrs; ///< decoded AddressSet cardinality
			    BIO_ADDR *addrs; ///< decoded AddressSet values (v4 or v6)
			    size_t nonce_len; 
			    unsigned char *nonce; ///< Nonce we challenge server to respond with
			    size_t hs_cr_len; 
			    unsigned char *hs_cr; ///< Client random from TLS h/s
			    size_t hs_kse_len;
			    unsigned char *hs_kse;///< Client key share from TLS h/s
			    /* 
			     * Crypto Vars - not all are really needed in the struct
			     * (though tickets/resumption need a quick thought)
			     * But all are handy for interop testing
			     */
			    EVP_PKEY *keyshare; ///< my own private keyshare to use with  server's ESNI share 
			    size_t encoded_keyshare_len; 
			    unsigned char *encoded_keyshare; ///< my own public key share
			    size_t hi_len; 
			    unsigned char *hi; ///< ESNIContent encoded (hash input)
			    size_t hash_len;
			    unsigned char *hash;  ///< hash of hi (encoded ESNIContent)
			    size_t realSNI_len; 
			    unsigned char *realSNI; ///< padded ESNI
			    /* 
			     * Derived crypto vars
			     */
			    size_t Z_len;
			    unsigned char *Z; ///< ECDH shared secret 
			    size_t Zx_len;
			    unsigned char *Zx; ///< derived from Z as per I-D
			    size_t key_len;
			    unsigned char *key; ///< derived key
			    size_t iv_len;
			    unsigned char *iv; ///< derived iv
			    size_t aad_len; 
			    unsigned char *aad; ///< derived aad
			    size_t plain_len;
			    unsigned char *plain; ///< plaintext value for ESNI
			    size_t cipher_len;
			    unsigned char *cipher; ///< ciphetext value of ESNI
			    size_t tag_len;
			    unsigned char *tag; ///< GCM tag (already also in ciphertext)
			#ifdef ESNI_CRYPT_INTEROP
			    char *private_str; ///< for debug purposes, requires special build
			#endif
			    CLIENT_ESNI *the_esni; ///< the final outputs for the caller (note: not separately alloc'd)
			} SSL_ESNI;
			
			/**
			 * Exterally visible form of an ESNIKeys RR value
			 */
			typedef struct ssl_esni_ext_st {
			    int index; ///< externally re-usable reference to this RR value
			    char *public_name; ///< public_name from ESNIKeys
			    char *prefixes;  ///< comman seperated list of IP address prefixes, in CIDR form
			    uint64_t not_before; ///< from ESNIKeys (not currently used)
			    uint64_t not_after; ///< from ESNIKeys (not currently used)
			} SSL_ESNI_ext; 
			
			/*
			 * Non-external Prototypes
			 */
			
			/**
			 * @brief wrap a "raw" key share in the relevant TLS presentation layer encoding
			 *
			 * Put the outer length and curve ID around a key share.
			 * This just exists because we do it a few times: for the ESNI
			 * client keyshare and for handshake client keyshare.
			 * The input keyshare is the e.g. 32 octets of a point
			 * on curve 25519 as used in X25519.
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
			                size_t *outlen);
			
			/**
			 * @brief Do the client-side SNI encryption during a TLS handshake
			 *
			 * This is an internal API called as part of the state machine
			 * dealing with this extension.
			 *
			 * @param esnikeys is the SSL_ESNI structure
			 * @param client_random_len is the number of bytes of
			 * @param client_random being the TLS h/s client random
			 * @param curve_id is the curve_id of the client keyshare
			 * @param client_keyshare_len is the number of bytes of
			 * @param client_keyshare is the h/s client keyshare
			 * @return 1 for success, other otherwise
			 */
			int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
			                size_t  client_random_len,
			                unsigned char *client_random,
			                uint16_t curve_id,
			                size_t  client_keyshare_len,
			                unsigned char *client_keyshare,
			                CLIENT_ESNI **the_esni);
			
			/**
			 * @brief Server-side decryption during a TLS handshake
			 *
			 * This is the internal API called as part of the state machine
			 * dealing with this extension.
			 * Note that the decrypted server name is just a set of octets - there
			 * is no guarantee it's a DNS name or printable etc. (Same as with
			 * SNI generally.)
			 *
			 * @param esni is the SSL_ESNI structure
			 * @param client_random_len is the number of bytes of
			 * @param client_random being the TLS h/s client random
			 * @param curve_id is the curve_id of the client keyshare
			 * @param client_keyshare_len is the number of bytes of
			 * @param client_keyshare is the h/s client keyshare
			 * @return NULL for error, or the decrypted servername when it works
			 */
			unsigned char *SSL_ESNI_dec(SSL_ESNI *esni,
							size_t	client_random_len,
							unsigned char *client_random,
							uint16_t curve_id,
							size_t	client_keyshare_len,
							unsigned char *client_keyshare,
							size_t *encservername_len);
			
			/**
			 * Memory management - free an SSL_ESNI
			 *
			 * Free everything within an SSL_ESNI. Note that the
			 * caller has to free the top level SSL_ESNI, IOW the
			 * pattern here is: 
			 *      SSL_ESNI_free(esnikeys);
			 *      OPENSSL_free(esnikeys);
			 *
			 * @param esnikeys is an SSL_ESNI structure
			 */
			void SSL_ESNI_free(SSL_ESNI *esnikeys);
			
			/**
			 * @brief Duplicate the configuration related fields of an SSL_ESNI
			 *
			 * This is needed to handle the SSL_CTX->SSL factory model in the
			 * server. Clients don't need this.  There aren't too many fields 
			 * populated when this is called - essentially just the ESNIKeys and
			 * the server private value. For the moment, we actually only
			 * deep-copy those.
			 *
			 * @param orig is the input array of SSL_ESNI to be partly deep-copied
			 * @param nesni is the number of elements in the array
			 * @param selector allows for picking all (ESNI_SELECT_ALL==-1) or just one of the RR values in orig
			 * @return a partial deep-copy array or NULL if errors occur
			 */
			SSL_ESNI* SSL_ESNI_dup(SSL_ESNI* orig, size_t nesni, int selector);
			
			/*
			 * Externally visible Prototypes
			 */
			
			/**
			 * Make a basic check of names from CLI or API
			 *
			 * Note: This may disappear as all the checks currently done would
			 * result in errors anyway. However, that could change, so we'll
			 * keep it for now.
			 *
			 * @param encservername the hidden servie
			 * @param convername the cleartext SNI to send (can be NULL if we don't want any)
			 * @return 1 for success, other otherwise
			 */
			int SSL_esni_checknames(const char *encservername, const char *covername);
			
			/**
			 * @brief Decode and check the value retieved from DNS (binary, base64 or ascii-hex encoded)
			 *
			 * The esnnikeys value here may be the catenation of multiple encoded ESNIKeys RR values 
			 * (or TXT values for draft-02), we'll internally try decode and handle those and (later)
			 * use whichever is relevant/best. The fmt parameter can be e.g. ESNI_RRFMT_ASCII_HEX
			 *
			 * @param ekfmt specifies the format of the input text string
			 * @param eklen is the length of the binary, base64 or ascii-hex encoded value from DNS
			 * @param esnikeys is the binary, base64 or ascii-hex encoded value from DNS
			 * @param num_esnis says how many SSL_ESNI structures are in the returned array
			 * @return is an SSL_ESNI structure
			 */
			SSL_ESNI* SSL_ESNI_new_from_buffer(const short ekfmt, const size_t eklen, const char *esnikeys, int *num_esnis);
			
			/**
			 * @brief Turn on SNI encryption for an (upcoming) TLS session
			 * 
			 * @param s is the SSL context
			 * @param hidde is the hidden service name
			 * @param cover is the cleartext SNI name to use
			 * @param esni is an array of SSL_ESNI structures
			 * @param nesnis says how many structures are in the esni array
			 * @param require_hidden_match say whether to require (==1) the TLS server cert matches the hidden name
			 * @return 1 for success, error otherwise
			 * 
			 */
			int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni, int nesnis, int require_hidden_match);
			
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
			 * @param out is the returned externally visible detailed form of the SSL_ESNI structure
			 * @param nindices is an output saying how many indices are in the SSL_ESNI_ext structure 
			 * @return 1 for success, error otherwise
			 */
			int SSL_esni_query(SSL_ESNI *in, SSL_ESNI_ext **out,int *nindices);
			
			/** 
			 * @brief free up memory for an SSL_ESNI_ext
			 *
			 * @param in is the structure to free up
			 * @param size says how many indices are in in
			 */
			void SSL_ESNI_ext_free(SSL_ESNI_ext *in,int size);
			
			/**
			 * @brief utility fnc for application that wants to print an SSL_ESNI_ext
			 *
			 * @param out is the BIO to use (e.g. stdout/whatever)
			 * @param se is a pointer to an SSL_ESNI_ext struture
			 * @param count is the number of elements in se
			 * @return 1 for success, error othewise
			 */
			int SSL_ESNI_ext_print(BIO* out, SSL_ESNI_ext *se,int count);
			
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
			int SSL_esni_reduce(SSL_ESNI *in, int index, SSL_ESNI **out);
			
			/**
			 * Turn on SNI Encryption, server-side
			 *
			 * When this works, the server will decrypt any ESNI seen in ClientHellos and
			 * subsequently treat those as if they had been send in cleartext SNI.
			 *
			 * @param s is the SSL server context
			 * @param esnikeyfile has the relevant (X25519) private key in PEM format
			 * @param esnipubfile has the relevant (binary encoded, not base64) ESNIKeys structure
			 * @return 1 for success, other otherwise
			 */
			int SSL_esni_server_enable(SSL_CTX *s, const char *esnikeyfile, const char *esnipubfile);
			
			/**
			 * Access an SSL_ESNI structure note - can include sensitive values!
			 *
			 * @param s is a an SSL structure, as used on TLS client
			 * @param esni is an SSL_ESNI structure
			 * @return 1 for success, anything else for failure
			 */
			int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni);
			
			/**
			 * Access an SSL_ESNI structure note - can include sensitive values!
			 *
			 * @param s is a an SSL_CTX structure, as used on TLS server
			 * @param esni is an SSL_ESNI structure
			 * @return 0 for failure, non-zero is the number of SSL_ESNI in the array
			 */
			int SSL_ESNI_get_esni_ctx(SSL_CTX *s, SSL_ESNI **esni);
			
            /** 
             * Print the content of an SSL_ESNI
             *
             * @param out is the BIO to use (e.g. stdout/whatever)
             * @param esni is an SSL_ESNI strucutre
             * @param selector allows for picking all (ESNI_SELECT_ALL==-1) or just one of the RR values in orig
             * @return 1 for success, anything else for failure
             * 
             * The esni pointer must point at the full array, and not at
             * the element you want to select using the selector. That is,
             * the implementation here will try access esni[2] if you
             * provide selector value 2.
             */
            int SSL_ESNI_print(BIO* out, SSL_ESNI *esni,int selector);
			
			/* 
			 * Possible return codes from SSL_get_esni_status
			 */
			
			#define SSL_ESNI_STATUS_SUCCESS                 1 ///< Success
			#define SSL_ESNI_STATUS_FAILED                  0 ///< Some internal error
			#define SSL_ESNI_STATUS_BAD_CALL             -100 ///< Required in/out arguments were NULL
			#define SSL_ESNI_STATUS_NOT_TRIED            -101 ///< ESNI wasn't attempted 
			#define SSL_ESNI_STATUS_BAD_NAME             -102 ///< ESNI succeeded but the TLS server cert used didn't match the hidden service name
			
			/**
			 * @brief API to allow calling code know ESNI outcome, post-handshake
			 *
			 * This is intended to be called by applications after the TLS handshake
			 * is complete. This works for both client and server. The caller does
			 * not have to (and shouldn't) free the hidden or cover strings.
			 * TODO: Those are pointers into the SSL struct though so maybe better
			 * to allocate fresh ones.
			 *
			 * @param s The SSL context (if that's the right term)
			 * @param hidden will be set to the address of the hidden service
			 * @param cover will be set to the address of the hidden service
			 * @return 1 for success, other otherwise
			 */
			int SSL_get_esni_status(SSL *s, char **hidden, char **cover);
			
			/*
			 * Crypto detailed debugging functions to allow comparison of intermediate
			 * values with other code bases (in particular NSS) - these allow one to
			 * set values that were generated in another code base's TLS handshake and
			 * see if the same derived values are calculated.
			 */
			
			/**
			 * Allows caller to set the ECDH private value for ESNI. 
			 *
			 * This is intended to only be used for interop testing - what was
			 * useful was to grab the value from the NSS implemtation, force
			 * it into mine and see which of the derived values end up the same.
			 *
			 * @param esni is the SSL_ESNI struture
			 * @param private_str is an ASCII-hex encoded X25519 point (essentially
			 * a random 32 octet value:-) 
			 * @return 1 for success, other otherwise
			 *
			 */
			int SSL_ESNI_set_private(SSL_ESNI *esni, char *private_str);
			
			/**
			 * @brief Allows caller to set the nonce value for ESNI. 
			 *
			 * This is intended to only be used for interop testing - what was
			 * useful was to grab the value from the NSS implemtation, force
			 * it into mine and see which of the derived values end up the same.
			 *
			 * @param esni is the SSL_ESNI struture
			 * @param nonce points to a buffer with the network byte order value
			 * @oaram nlen is the size of the nonce buffer
			 * @return 1 for success, other otherwise
			 *
			 */
			int SSL_ESNI_set_nonce(SSL_ESNI *esni, unsigned char *nonce, size_t nlen);
			
## Extension and ``SSL_CTX`` Handling

The ESNI extension is handled using ```statem``` code, in the same
way as other extensions.

Code blocks in those files that are documented in the [api](./api.md) are filtered 
out (using the [NOESNI_filter.sh](./NOESNI_filter.sh)) script. Basically
such blocks start with ```// ESNI_DOXY_START``` and
end with ```// ESNI_DOXY_END```.

### Client-side

The main extension handling function is [tls_construct_ctos_esni](./api.md#extensions__clnt_8c_1afca936de2d3ae315b5e8b8b200d17462)
which uses the above APIs (most substantively ``SSL_ESNI_enc``) to generate the extension value and puts that in the ClientHello. 

The [tls_parse_ctos_esni](./api.md#extensions__clnt_8c_1ac388d56d20b4d3b507e56203f1c08303)
function is rather simple and just checks that the EncryptedExtensions contains the right
nonce that was sent (encrypted) in the ESNI.

We do also have to tweak the (cleartext) SNI extension handling too to make
sure we don't send the same value encrypted and in clear. That's done using
the [esni_server_name_fixup](./api.md#extensions__clnt_8c_1a2454a14e823689509154ca3bfb4cdaea)
function.

### Server-side

On the server-side, the main extension handling functions are
``tls_parse_ctos_esni`` and ``tls_construct_stoc_esni``.

The first parses out the octets received into an ``SSL_ESNI`` structure and then
calls ``SSL_ESNI_dec`` and (on success) sets the appropriate SNI value in the internal state. 
The second function will return the nonce to the client for 
verification.

### ``SSL/SSL_CTX`` structure handlng

It appears
that an instance of the ``SSL_CTX`` factory structure is used to create an ``SSL``
structure for each connection - which we guess means that ``SSL_CTX`` is specific to the config
and/or generic application API calls, whereas presumably the ``SSL`` type
is specific to a particular connection.

Basically we added the following fields to both ``SSL`` and ``SSL_CTX``
- ``size_t nesni`` has a count of the number of ``SSL_ESNI`` structures in the ``esni`` array  (which
is one per loaded public/private ESNI value)
-  ``SSL_ESNI *esni`` pointer to an array of all of the ``SSL_ESNI`` instances we've loaded
- ``int esni_done`` is 0 until we've finished the ESNI game successfully
- ``esni_cb`` is a callback function only used to print the ``SSL_ESNI`` details for debug purposes

For ``s_client`` we'll have ``nesni==1`` as there's only the ESNIKeys value
from DNS for the relevant HIDDEN service.

For ``s_server`` the ``nesni`` value will reflect how many ESNIKeys public and
private values were loaded. We replicate all of that from ``SSL_CTX`` to the ``SSL``
for each connection as we won't know ahead of time which public value was
used. We select one to process via the ``record_digest`` value that's in
the ESNI TLS extension and that's calculated on loading the ESNI public value.

The ``SSL_ESNI`` structure could be rationalised more as the spec stabilises
but for now, each element of the ``esni`` array in an ``SSL`` or ``SSL_CTX``
has all fields, but only one will be fully populated when we receive a TLS
ESNI extension on the server.

The ``SSL_ESNI_dup`` function is used to produce the ``esni`` value in a
connection-specific ``SSL`` structure (from the ``SSL_CTX`` factory). That
function selectively deep-copies the generic parts (public/private key
essentially.)

The various new and free functions for ``SSL_CTX`` and ``SSL`` structures
are modified to do the right thing with our new fields.

Handling of cleartext SNI extension in OpenSSL is a bit messy - there's
a second ``SSL_CTX`` value maintained by ``s_server`` (variables are
``ctx`` and ``ctx2``) which is used to keep the different server context.
Servers for different names might e.g. differ in the set of X.509 CAs
they trust for client auth. For now, we just replicate the same ESNI
information in both.

## Testing

**We haven't done any significant testing. Use at your own risk.**

1. Make TLS server certs/keys
1. Make ESNI public/private values
1. Run server
1. Run client

### Make TLS server certs/keys

Easy-peasy (if it works:-) ...

            $ cd $HOME/code/openssl # or wherever you put this, but scripts assume here
            $ ./config
            $ make
            $ cd esnistuff
            $ make
            $ make keys

That'll create a local ``cadir`` and some others with stuff you can mostly ignore.
It's ok to blow that away and start over anytime so long as you've
not copied key material elsewhere.

Each of the commands above produces lots of output of course.

### Run Server

            $ ./testserver.sh -p 4000 -D ./esnikeydir -vd
            ...lots of output...

### Run Client

And finally in a 2nd window we fire up a client as follows:

            $ ./testclient.sh -p 4000 -s localhost -H foo.example.com -P ./esnikeydir/e3.pub -c NONE -vd -C cadir
            ...lots of output...

If you want to try session resumption, then use the ``-S`` option and there's no need to do the ESNI game 2nd time:

            $ ./testclient.sh -p 4000 -s localhost -H foo.example.com -P ./esnikeydir/e3.pub -c NONE -vd -C cadir -S sessionfile
            ...lots of output...
            $ ./testclient.sh -p 4000 -s localhost -n -c NONE -vd -C cadir -S sessionfile
            ...lots of output...

### Test our client against www.cloudflare.com

            $ ./testclient.sh -H ietf.org 
            ...a little output...

### Test NSS's client against our server

This is a bit basic (so read the script) but if you started our server as above
and you have an NSS build in the expected location, then this should work:

            $ ./nssdoit.sh localhost

### Future testing

- Future things to test (later, when writing test code:-):
    - checksum fail in ESNIKeys
    - unknown version, group, suite in ESNIKeys
    - bad times (but I disklike the whole inclusion of not_before/after!)
    - some (bogus) ESNIKeys extension  
    - bad nonce returned by server
    - no nonce returned by server
    - fuzzing (need to check how that's generally done for openssl)
    - malloc fails
    - triggered internal fails

## File changes

### New files

All path names are below your clone of openssl, for me that's
usually in ``$HOME/code/openssl``.

- ssl/esni.c - main esni-specific functions
- include/openssl/esni.h - data structures are commented some

These two are produced as a result of tooling and some of the
automation below.

- include/openssl/esnierr.h 
- crypto/esnierr.c 

Things in this temporary directory. Some will disappear over time, some
will migrate into the normal openssl build.

- esnistuff/design.md - this file
- esnistuff/README.md - README with notes on state of play
- esnistuff/resumption.md - notes about resumption testing (will be deleted later)

- esnistuff/Makefile - build/run/clean stuff here in this temp space
- esnistuff/Makefile.ndk - build file for android NDK
- esnistuff/android_envvars.sh - set env vars for an android build
- esnistuff/esnimain.c - a basic standalone tester
- esnistuff/doit.sh - calls esnimain
- esnistuff/testclient.sh - calls ``openssl s_client`` 
- esnistuff/testserver.sh - calls ``openssl s_server`` 
- esnistuff/nssdoit.sh - calls NSS's ``tstclnt`` (if you have one)
- esnistuff/mk_esnikeys.c - generates private key and ESNIKeys binary files
- esnistuff/make-example-ca.sh - generates TLS server keys/certs and fake CA
- esnistuff/make-esnikeys.sh - make ESNI public/private pairs (a few)

Running tests as described above will result in some files being generated that hold
public and private keys both for the TLS server and for ESNI.

### Existing Files modified 

- Configurations/unix-Makefile.tmpl - added esni.h to sslheaders and esnierr.h to cryptoheaders
- ssl/build.info - need to add new libssl source files here 
- utils/libssl.num - changes generated via ``make ordinals``
- utils/libcrypto.num - changes generated via ``make ordinals``
- crypto/err/openssl.ec - following advice in crypto/err/README
- crypto/err/openssl.txt - automated, based on above
- include/openssl/err.h - following advice in crypto/err/README
- crypto/err/err.c - following advice in crypto/err/README
- include/openssl/ssl.h
- include/openssl/sslerr.h
- include/openssl/tls1.h
- apps/s_client.c
- apps/s_server.c
- ssl/ssl_locl.h - TLSEXT_IDX_esni isn't #ifndef protected for some reason, maybe because it's an enum?
- ssl/ssl_lib.c
- ssl/s3_lib.c
- ssl/t1_trce.c
- ssl/statem/extensions.c - lots of new code, mainly copied from server_name handling
- ssl/statem/statem_locl.h
- ssl/statem/extensions_clnt.c
- ssl/statem/extensions_srvr.c 
- crypto/err/err_all.c - loads ESNI strings
- ssl/ssl_asn1.c - for ``SSL_SESSION`` state stuff
- ssl/ssl_sess.c - for ``SSL_SESSION`` API stuff



