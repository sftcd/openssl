
# OpenSSL Encrypted SNI Design

stephen.farrell@cs.tcd.ie, 20181203

This file describes the current design for our proof-of-concept 
openssl implementation of encrypted SNI.

- The code in our [fork](https://gitbub.com/sftcd/openssl) imlpements the
  client side of the ESNI Internet-draft
[draft-ietf-tls-esni-02](https://tools.ietf.org/html/draft-ietf-tls-esni-02)
spec.
- The most up to date
  [README.md](https://github.com/sftcd/openssl/tree/master/esnistuff) for that
code.

The -02 draft version of ESNI works by having the "hidden" domain publish a TXT
RR in the DNS below the name that would otherwise be present in an SNI
extension. That RR contains a public key usable to encrypt the name as a TLS
ClientHello extension when connecting to the IP address that goes with the
name.

## Our Goals

- Provide Callum with a cool final year project:-)
- Amuse Stephen
- Do the above in a way that's helpful to the OpenSSL project
- Help the standardisation process in the IETF
- Allow other folks to play with ESNI
- Help make ESNI more widely available/usable 
- Ultimately - maybe some of this code might end up part of a release
when there's an ESNI RFC

## Status

Our build works against the www.cloudflare.com service (see
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

This is not well-tested code at this point, it's just an initial proof-of-concept,
so **don't depend on this for anything**.

## Design/Implementation Notes

- Our implementation so far is just a client-side proof-of-concept.
There is no server-side code at all (other than a couple of stubs).
- We don't do any DNS queries from within the OpenSSL library. We just take the
  required inputs and run the protocol.
- ``s_client`` currently tells the OpenSSL library to check if the TLS server cert matches the
name from the ESNI payload. That could be configurable later, but for now, if 
they don't match, the ``SSL_ensi_get_status`` call at the end of 
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
- Currently notes, (including this one), test scripts and a few other things are in an [esnistuff](https://github.com/sftcd/openssl/esnistuff/)
directory - that should disappear over time as we better integrate the
code following good project practice.
- For now, I'm using doxygen and moxygen to generate API and data structure
documentation. That'd probably be pruned when/if submitting a PR to the main
project, but should be helpful for now.

## Plans

- We do plan to add a server-side implementation
- We may try integrate the server-side with some web server (apache/nginx)
- We may try integrate the client-side with some web client application such
  as wget or curl.

The timeline for our work is that Calum needs to be finished his project
by approx. end March 2019. Stephen will continue work on this thereafter.

## Design details

We provide [data structures](#data-structures) and [APIs](#apis) that allow (client) applications to include
ESNI in handshakes.

We modified the [``s_client``](#s_client-modifications) application to provide command line arguments
allowing one to turn on ESNI.

We have a simple [test script](#test-script) that exercises various ``s_client`` options.

We'll describe those in reverse order, and then consider [testing](#testing).

### Client Side

#### Test script

The ``usage()`` function for the [testit.sh](https://gitbub.com/sftcd/openssl/esnistuff/testit.sh) 
produces this:

			$ ./testit.sh -h
			Running ./testit.sh at 20181128-125116
			./testit.sh [-cHpsdnlvh] - try out encrypted SNI via openssl s_client
			  -H means try connect to that hidden server
			  -d means run s_client in verbose mode
			  -v means run with valgrind
			  -l means use stale ESNIKeys
			  -n means don't trigger esni at all
			  -s [name] specifices a server to which I'll connect
			  -c [name] specifices a covername that I'll send as a clear SNI (NONE is special)
			  -p [port] specifices a port (default: 442)
			  -h means print this

			The following should work:
    		./testit.sh -c www.cloudflare.com -s NONE -H www.ietf.org

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

#### ``s_client`` modifications

Here and elsewhere, almost all of our code changes are enclosed with ``#ifndef OPENSSL_NO_ESNI``

The [``apps/s_client.c``](https://github.com/sftcd/openssl/blob/master/apps/s_client.c)
has two new comnand line arguments:

- ``esni`` allows one to specifiy the HIDDEN service
- ``esnirr`` allows one to provide the (base64 encoded) TXT RR as per the spec.

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
- ``SSL_ESNI_new_from_base64``: decode the TXT RR value and return an ``SSL_ESNI`` structure
- ``SSL_ESNI_print``: if ``-msg`` set, print the (initial) ``SSL_ESNI`` contents based on decoding 
- ``SSL_esni_enable``: modify the ``SSL *con`` structure to ask that ESNI be run
- ``SSL_set_esni_callback``: if ``-msg`` set, register callback so (final) ``SSL_ESNI`` values are printed
- ``esni_cb``: is a local call-back function, it retrives and prints the ``SSL_ESNI`` structure
- ``SSL_ESNI_get_esni``: is used in ``esni_cb`` to get the ``SSL_ESNI`` structure which is printed via ``SSL_ESNI_print``
- ``SSL_get_esni_status``: check if ESNI worked or failed and print a status line

Notes:
- The functions names above that contain the string ``SNI_ESNI`` either return
or take as a parameter a value of that type. Function names with a lowercase
esni substring do not. (This seems to be an OpenSSL convention.)
- We're not clear if the ``SSL_ESNI`` information ought be part of the ``SSL``
structure or the ``SSL_CTX`` structure - guess is that server side code will
force us to do the right thing, if the current one's wrong.
- There's another test script [doit.sh](https://github.com/sftcd/openssl/blob/master/esnistuff/doit.sh)
that runs a standalone test application ([esnimain.c](https://github.com/sftcd/openssl/blob/master/esnistuff/esnimain.c))
which just tests the ESNI APIs directly. That should become some kind of unit test in the main
build, and needs error cases added.

### Server-side 

#### Generating ESNIKeys

For now, all that exists is [mk_esnikeys.c](./mk_esnikeys.c), a simple command
line tool to generate a key pair and store the public in ESNIKeys format as 
per I-D -02. That's pretty limited (by design), it's usage explains most of
it:

			$ ./mk_esnikeys -h
			Create an ESNIKeys data structure as per draft-ietf-tls-esni-02
			Usage: 
				./mk_esnikeys [-o <fname>] [-p <privfname>] [-d duration]
			where:
			-o specifies the output file name for the binary-encoded ESNIKeys (default: ./esnikeys.pub)
			-p specifies the output file name for the corresponding private key (default: ./esnikeys.priv)
			-d duration, specifies the duration in seconds from now, for which the public should be valid (default: 1 week)
			
			If <privfname> exists already and contains an appropriate value, then that key will be used without change.
			There is no support for options - we just support TLS_AES_128_GCM_SHA256, X5519 and no extensions.
			Fix that if you like:-)
			
The private key is in PEM format. (I'm not v. familiar with PEM format for
X25519 but hopefully it's portable, I've a TODO: to check.) For now the 
public key is the binary form of ESNIKeys so needs to be base64 encoded
before being put in a zone file. I've yet to test that these are good
keys - have just generated and formatted 'em so far. This should likely
go into some tools or utils directory, not sure yet. Lastly, this does
allow private key re-use, just in case that may be needed, but we should 
decide if that could be removed, which seems safer in general.

#### Server test script

The [testserver.sh](./testserver.sh) script starts an ``openssl s_server``
and listens for connections. 
The ``usage()`` from that script is:

			$ ./testserver -h
			Running ./testserver.sh at 20181204-125134
			./testserver.sh [-cHpsdnlvhK] - try out encrypted SNI via openssl s_server
			  -H means serve that hidden server
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

There's not yet any ESNI code there really. Coming soon though:-)

#### ``s_server`` modifications

TBD

### APIs

[Here's](./api.md) what moxygen produces from what doxygen produces (with a bit of sed
scrpting - see the [Makefile](./Makefile) ```make doc``` target. Since that's a build
target, it may be more up to date that this text (but I'll try keep the stuff here
correct and brief).

The main ESNI header file [esni.h](https://github.com/sftcd/openssl/blob/master/include/openssl/esni.h)
includes the following prototypes:

			/*
			 * Make a basic check of names from CLI or API
			 */
			int SSL_esni_checknames(const char *hidden, const char *cover);

			/*
			 * Decode and check the value retieved from DNS (currently base64 encoded)
			 */
			SSL_ESNI* SSL_ESNI_new_from_base64(const char *esnikeys);
			
			/*
			 * Turn on SNI encryption for this TLS (upcoming) session
			 */
			int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni, int require_hidden_match);
			
			/*
			 * Do the client-side SNI encryption during a TLS handshake
			 */
			int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
			                size_t  client_random_len,
			                unsigned char *client_random,
			                uint16_t curve_id,
			                size_t  client_keyshare_len,
			                unsigned char *client_keyshare,
			                CLIENT_ESNI **the_esni);
			
			/*
			 * Memory management
			 */
			void SSL_ESNI_free(SSL_ESNI *esnikeys);
			void CLIENT_ESNI_free(CLIENT_ESNI *c);
			
			/*
			 * Debugging - note - can include sensitive values!
			 * (Depends on compile time options)
			 */
			int SSL_ESNI_print(BIO* out, SSL_ESNI *esni);
			
			/*
			 * SSL_ESNI_print calls a callback function that uses this
			 * to get the SSL_ESNI structure from the external view of
			 * the TLS session.
			 */
			int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni);
			
			/* 
			 * Possible return codes from SSL_ESNI_get_status
			 */
			#define SSL_ESNI_STATUS_SUCCESS                 1
			#define SSL_ESNI_STATUS_FAILED                  0
			#define SSL_ESNI_BAD_STATUS_CALL             -100
			#define SSL_ESNI_STATUS_NOT_TRIED            -101
			#define SSL_ESNI_STATUS_BAD_NAME             -102
			
			/*
			 * API to allow calling code know ESNI outcome, post-handshake
			 */
			int SSL_get_esni_status(SSL *s, char **hidden, char **cover);
			
			#ifdef ESNI_CRYPT_INTEROP
			/*
			 * Crypto detailed debugging functions to allow comparison of intermediate
			 * values with other code bases (in particular NSS) - these allow one to
			 * set values that were generated in another code base's TLS handshake and
			 * see if the same derived values are calculated.
			 */
			int SSL_ESNI_set_private(SSL_ESNI *esni, char *private_str);
			int SSL_ESNI_set_nonce(SSL_ESNI *esni, unsigned char *nonce, size_t nlen);
			#endif
			
Notes:
- The above are externally visible, internal functions below. 
- Various functions (but mostly ``SSL_ESNI_enc``) should be modified to be
  more consistent with other internal APIs, e.g. to have as their main
  context an ``SSL *s`` input. (Didn't do that yet, as our initial code
  was run from a standalone test application, but we'll make such changes
  soon.)

### Extension Handling

The ESNI extension is handled using ```statem``` code, in the same
way as other extensions.

Code blocks in those files that are documented in the [api](./api.md) are filtered 
out (using the [NOESNI_filter.sh](./NOESNI_filter.sh)) script. Basically
such blocks start with ```// ESNI_DOXY_START``` and
end with ```// ESNI_DOXY_END```.

The main extension handling function is [tls_construct_ctos_esni](./api.md#extensions__clnt_8c_1afca936de2d3ae315b5e8b8b200d17462)
which uses the above APIs to generate the extension value and puts that in the ClientHello. 
The [tls_parse_ctos_esni](./api.md#extensions__clnt_8c_1ac388d56d20b4d3b507e56203f1c08303)
function is rather simple and just checks that the EncryptedExtensions contains the right
nonce that was sent (encrypted) in the ESNI.
We do also have to tweak the (cleartext) SNI extension handling too to make
sure we don't send the same value encrypted and in clear. That's done using
the [esni_server_name_fixup](./api.md#extensions__clnt_8c_1a2454a14e823689509154ca3bfb4cdaea)
function.

### Data structures

See the [api](./api.md)

The main data structures are:

- [ESNI_RECORD](./api.md#structesni__record__st) representing the DNS RR value
- [CLIENT_ESNI](./api.md#structclient__esni__st) representing the extension value for a ClientHello
- [SSL_ESNI](./api.md#structssl__esni__st) the internal state structure with the above plus gory crypto details

### Internal functions

See the [api](./api.md)

### Testing

- Things to test (later, when writing test code:-):
	- DNS: dns query/answer failure(s) - affects script not code so far...
	- API: No ESNI but Encservername (and vice versa)
	- checksum fail in ESNIKeys
	- decode fail(s) in ENSIKeys
	- unknown version, group, suite in ESNIKeys
	- bad times (but I disklike the whole inclusion of not_before/after!)
	- some (bogus) extension  
	- bad nonce returned by server
	- no nonce returned by server
	- fuzzing (need to check how that's generally done for openssl)
	- malloc fails
	- triggered internal fails

### New files

All path names are below your clone of openssl, for me that's
usually in ``$HOME/code/openssl``.

- ssl/esni.c - main esni-specific functions
- include/openssl/esni.h - data structures are commented some
- include/openssl/esnierr.h - boring errors
- crypto/esnierr.c - load boring strings (need to check if this is right)

- esnistuff/esnimain.c - a tester
- esnistuff/doit.sh - calls esnimain
- esnistuff/testit.sh - calls ``openssl s_client`` 
- esnistuff/testserver.sh - calls ``openssl s_server`` (still evolving!)
- esnistuff/mk_esnikeys.c - generates private key and ESNIKeys binary files

### Existing Files modified 

- ssl/build.info - need to add new libssl source files here (just esni.c for now)
- utils/libssl.num - seem to need to add exported stuff here manually?
- utils/libcrypto.num - seem to need to add exported stuff here manually?
- include/openssl/err.h
- include/openssl/ssl.h
- include/openssl/sslerr.h
- include/openssl/tls1.h
- apps/s_client.c
- ssl/ssl-locl.h - TLSEXT_IDX_esni isn't #ifndef protected for some reason, maybe because it's an enum?
- ssl/ssl-lib.c
- ssl/s3_lib.c
- ssl/t1_trce.c
- ssl/statem/extensions.c - lots of new code, mainly copied from server_name handling
- ssl/statem/statem_locl.h
- ssl/statem/extensions_clnt.c
- ssl/statem/extensions_srvr.c 
- crypto/err/err_all.c - loads ESNI strings

### Files still to figure out/check

- ssl/ssl_asn1.c - might be a challenge, not sure if I need to go there
	- a comment in ssl/ssl_locl.h implies I might, perhaps for state mgmt, not
	  sure

