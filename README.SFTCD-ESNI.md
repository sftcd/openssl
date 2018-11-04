
# SF notes on initial playing about with openssl/esni

20181103, stephen.farrell@cs.tcd.ie

I've set a student project to do work on esni. I'm playing about a bit before
the student starts work to try see if doing that on openssl is tractable (for
the scale of such a student project).

TODO: If this goes anywhere, do the CLA thing, and get the student to do likewise.

## References

- TLS1.3, [RFC8446](https://tools.ietf.org/html/rfc8446)
- [esni draft](https://tools.ietf.org/html/draft-ietf-tls-esni)
- CF [blog](https://blog.cloudflare.com/encrypted-sni/) on esni
- Openssl on [guthub](https://github.com/openssl/openssl)
- My [fork](https://github.com/sftcd/openssl)
	- This file is in there as [README.SFTCD-ESNI.md](./README.SFTCD-ESNI.md)

## Initially - poking about the code ...

It seems that:

- code/openssl/ssl/statem/README is a place to start
	- but that wasn't so useful really, other than leading to...
- code/openssl/ssl/extensions.c seems to be where a bunch of the action takes place
- would wanna define functions for an ``EXTENSION_DEFINITION`` for esni, that struct has:
			
			/* Structure to define a built-in extension */
			typedef struct extensions_definition_st {
			    /* The defined type for the extension */
			    unsigned int type;
			    /*
			     * The context that this extension applies to, e.g. what messages and
			     * protocol versions
			     */
			    unsigned int context;
			    /*
			     * Initialise extension before parsing. Always called for relevant contexts
			     * even if extension not present
			     */
			    int (*init)(SSL *s, unsigned int context);
			    /* Parse extension sent from client to server */
			    int (*parse_ctos)(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
			                      size_t chainidx);
			    /* Parse extension send from server to client */
			    int (*parse_stoc)(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
			                      size_t chainidx);
			    /* Construct extension sent from server to client */
			    EXT_RETURN (*construct_stoc)(SSL *s, WPACKET *pkt, unsigned int context,
			                                 X509 *x, size_t chainidx);
			    /* Construct extension sent from client to server */
			    EXT_RETURN (*construct_ctos)(SSL *s, WPACKET *pkt, unsigned int context,
			                                 X509 *x, size_t chainidx);
			    /*
			     * Finalise extension after parsing. Always called where an extensions was
			     * initialised even if the extension was not present. |sent| is set to 1 if
			     * the extension was seen, or 0 otherwise.
			     */
			    int (*final)(SSL *s, unsigned int context, int sent);
			} EXTENSION_DEFINITION;

- A sketch/guess of what those might do for esni:
	- ``type``, as per I-D from exp space
	- ``context`` - dunno TBD
	- ``init`` - not sure yet
		- server: check policies wrt doing-it, local, remote
		- client: 
	- ``construct_ctos`` 
		- check DNS for key for whatever's in SNI (so do after real SNI)
		- if no RR found, mark to not include and exit
		- make CH value as per I-D
		- change SNI value to dummy  - what value?
	- ``parse_ctos`` 
		- check known key
		- decrypt
		- success, local:
			- I guess fix up SNI and proceed as normal
		- success, remote: 
			- Will need more thought:-) In theory: act as a TCP proxy to that origin
			- but for how long?
			- punt on that for now
	- ``contsruct_stoc``
		- make EE value, from rx'd esni
		- could be that acion from success of ``parse_ctos`` is postponed 'till here or ``final`` not sure
	- ``parse_stoc``
		- check presence and nonce, continue if good, barf if bad
	- ``final``
		- on client did server answer and with right nonce?

## Baby step1: fork, build, ...

I always have to look this stuff up as I don't do it often...
	- Forking instructions [here](https://help.github.com/articles/fork-a-repo/)
	- Syncing with upatream [instructions](https://help.github.com/articles/syncing-a-fork/)
	- Eventually, all going well, we may do a [PR](https://help.github.com/articles/about-pull-requests/) with out results

I forked, cloned, sync'd, built & ran openssl tests on Ubuntu 18.10. All easy-peasy.

			$ ./config
			... small output...
			$ make
			... loadsa output...
			$ make test
			... loads more ouput, then ...
			All tests successful.
			Files=152, Tests=1360, 161 wallclock secs ( 2.32 usr  0.23 sys + 155.32 cusr 18.99 csys = 176.86 CPU)
			Result: PASS
			make[1]: Leaving directory '/home/stephen/code/openssl'

One nit - to run from commannd line in build dir, I had to set ``LD_LIBRARY_PATH``

			$ cd code/openssl
			$ ./apps/openssl version
			./apps/openssl: /usr/lib/x86_64-linux-gnu/libssl.so.1.1: version `OPENSSL_1_1_1' not found (required by ./apps/openssl)
			./apps/openssl: /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1: version `OPENSSL_1_1_2' not found (required by ./apps/openssl)
			./apps/openssl: /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1: version `OPENSSL_1_1_1' not found (required by ./apps/openssl)
			$ export LD_LIBRARY_PATH=`/bin/pwd`
			$ ./apps/openssl version
			OpenSSL 1.1.2-dev  xx XXX xxxx
			$ 

## Baby step2: add a command line argument to ``openssl s_client``

TODO: figure out how to turn off my esni code.  Lots of optional things are
protected via ``#ifndef OPENSSL_NO_foo`` pragmas, so I guess I should wrap my
code with ``#ifndef OPENSSL_NO_ESNI`` but I've yet to figure out how to
properly define ``OPENSSL_NO_ESNI`` if needed - it *might* just work, from a
quick look at the ``Configure`` script, but who knows. 

TODO: figure out how to add a test that'll run as part of ``make test``

File modified: ``apps/s_client.c``
	- added ``-esni val`` option to CLI, setting ``char *encservername``

### Side baby step:

Writing standalone code in ``tempstuff/esni.c`` just to figure out 
calls I'll wanna integrate into ``s_client.c``. Plan is to delete
that soon's we get things working. That also has a hacked together
``Makefile``. 


