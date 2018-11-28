
# OpenSSL Encrypted SNI Design

stephen.farrell@cs.tcd.ie, 20181126

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
- Help make ESNI more widely available/usable 
- Ultimately - maybe some of this code might end up part of a release

## Status

Our build works against the www.cloudflare.com service
(see [here](https://www.cloudflare.com/ssl/encrypted-sni/)
for details of what CloudFlare have deployed)
and e.g. allows passing www.ietf.org as the value in the ESNI extension.

			openssl s_client -cipher TLS13-AES-128-GCM-SHA256 -connect www.cloudflare.com:443 -esni www.ietf.org -esnirr /wEvuMKuACQAHQAgepo8PLvXxcAjcN4T3dQDxANhwPjVbNHqEEE3lbjDrjoAAhMBAQQAAAAAW/qOwAAAAABcAnfAAAA= 

You need to set the ``LD_LIBRARY_PATH`` to use the shared
object in our build and the 
esnirr value above is time-dependent so won't work, to get a fresh value:

			dig +short txt _esni.www.cloudflare.com | sed -e 's/"//g'
			/wEvuMKuACQAHQAgepo8PLvXxcAjcN4T3dQDxANhwPjVbNHqEEE3lbjDrjoAAhMBAQQAAAAAW/qOwAAAAABcAnfAAAA=


## Design/Implementation Notes

- Our implementation so far is just a client-side proof-of-concept.
There is no server-side code at all (other than a couple of stubs).
- We don't do any DNS queries from within the OpenSSL library. We just take the
  required inputs and run the protocol.
- We want to be relatively easily able to evolve the code as the
  standardisation process continues, so many intermediate cryptographic
values are stored in the ``SSL_ESNI`` structure that should allow us to more easily figure
out interop issues, which has been useful esp. vs. the [NSS ESNI implementation](https://hg.mozilla.org/projects/nss/file/tip/lib/ssl/tls13esni.c).
As the spec matures, a lot of those values won't be needed, and some of
the related code wouldn't be part of a release. (Such code will
be protected via  ``#ifdef ESNI_CRYPTO_INTEROP`` macros - that's not
yet well-done.)
- Currently notes, test scripts and a few other things are in an [esnistuff](https://github.com/sftcd/openssl/esnistuff/)
directory - that should disappear over time as we better integrate the
code following good prooject practice.

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

## Test script

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

## ``s_client`` modifications

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

- ``esni_checknames``: do a basic check on HIDDEN/COVER (e.g. not the same:-)
- ``SSL_ESNI_new_from_base64``: decode the TXT RR value and return an ``SSL_ESNI`` structure
- ``SSL_ESNI_print``: if ``-msg`` set, print the (initial) ``SSL_ESNI`` contents based on decoding 
- ``SSL_esni_enable``: modify the ``SSL *con`` structure to ask that ESNI be run
- ``SSL_set_esni_callback``: if ``-msg`` set, register callback so (final) ``SSL_ESNI`` values are printed
- ``esni_cb``: is a local call-back function, it retrives and prints the ``SSL_ESNI`` structure
- ``SSL_ESNI_get_esni``: is used in ``esni_cb`` to get the ``SSL_ESNI`` structure which is printed via ``SSL_ESNI_print``
- ``SSL_get_esni_status``: check if ESNI worked or failed and print a status line

Notes:
- We're not clear if the ``SSL_ESNI`` information ought be part of the ``SSL``
structure or the ``SSL_CTX`` structure - guess is that server side code will
force us to do the right thing, if the current one's wrong.
- There's another test script [doit.sh](https://github.com/sftcd/openssl/blob/master/esnistuff/doit.sh)
that runs a standalone test application ([esnimain.c](https://github.com/sftcd/openssl/blob/master/esnistuff/esnimain.c))
which just tests the ESNI APIs directly.

## APIs

The main ESNI header file [esni.h](https://github.com/sftcd/openssl/blob/master/include/openssl/esni.h)
includes the following prototypes:

			/*
			 * Make a basic check of names from CLI or API
			 */
			int esni_checknames(const char *encservername, const char *frontname);
			
			/*
			 * Decode and check the value retieved from DNS (currently base64 encoded)
			 */
			SSL_ESNI* SSL_ESNI_new_from_base64(const char *esnikeys);
			
			/*
			 * Turn on SNI encryption for this TLS (upcoming) session
			 */
			int SSL_esni_enable(SSL *s, const char *hidden, const char *cover, SSL_ESNI *esni);
			
			/*
			 * Do the client-side SNI encryption during a TLS handshake
			 */
			int SSL_ESNI_enc(SSL_ESNI *esnikeys, 
			                char *protectedserver, 
			                char *frontname, 
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
			 * Possible return codes from SSL_ESNI_get_status
			 */
			#define SSL_ESNI_STATUS_SUCCESS                 1
			#define SSL_ESNI_STATUS_FAILED                  0
			#define SSL_ESNI_BAD_STATUS_CALL             -100
			#define SSL_ESNI_STATUS_NOT_TRIED            -101
			
			/*
			 * SSL_ESNI_print calls a callback function that uses this
			 * to get the SSL_ESNI structure from the external view of
			 * the TLS session.
			 */
			int SSL_ESNI_get_esni(SSL *s, SSL_ESNI **esni);
			
			
			/*
			 * API to allow calling code know ESNI outcome, post-handshake
			 */
			int SSL_get_esni_status(SSL *s, char **cover, char **hidden);
			
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
- Need to figure out a doxygen-equivalent way to produce the above
- Various functions (but mostly ``SSL_ESNI_enc``) should be modified to be
  more consistent with other internal APIs, e.g. to have as their main
  context an ``SSL *s`` input. (Didn't do that yet, as our initial code
  was run from a standalone test application, but we'll make such changes
  soon.)

## Data structures

TBD

## Testing

TBD

