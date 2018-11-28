
# OpenSSL Encrypted SNI Design

stephen.farrell@cs.tcd.ie, 20181126

This file describes the current design for our proof-of-concept 
openssl implementation of encrypted SNI.

- The code in our [fork](https://gitbub.com/sftcd/openssl) imlpements the
  client side of the ESNI Internet-draft
[draft-ietf-tls-esni-02](https://tools.ietf.org/html/draft-ietf-tls-esni-02)
spec.
- This is the most up to date
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

## Design Notes

- Our implementation so far is just a proof-of-concept.
- There is no server-side code at all (other than a couple of stubs).
- We don't do any DNS queries from within the OpenSSL library. We just take the
  required inputs and run the protocol.
- Our code is designed to enable us to evolve the code as the
  standardisation process continues, so many intermediate cryptographic
values are stored in the ``SSL_ESNI`` structure that allow us to more easily figure
out interop issues, which has been useful esp. vs. the NSS implementation.
As the spec matures, a lot of those values won't be needed, and some of
the related code wouldn't be part of a release. (Such code will
be protected via  ``#ifdef ESNI_CRYPTO_INTEROP`` macros - that's not
yet well-done.)

We provide [data structures](#data-structures) and [APIs](#apis) that allow (client) applications to include
ESNI in handshakes.

We modified the [``s_client``](#s_client-modifications) application to provide command line arguments
allowing one to turn on ESNI.

We have a simple [test script](#test-script) that exercises various ``s_client`` options.

We'll describe those in reverse order, and then consider [testing](#testing).

## Test script

[testit.sh](https://gitbub.com/sftcd/openssl/esnistuff/testit.sh) 

## ``s_client`` modifications

TBD

## APIs

TBD

## Data structures

TBD

## Testing

TBD

