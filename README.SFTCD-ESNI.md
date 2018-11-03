
# SF notes on openssl/esni

20181103, stephen.farrell@cs.tcd.ie

## References

- TLS1.3, [RFC8446](https://tools.ietf.org/html/rfc8446)
- [esni draft](https://tools.ietf.org/html/draft-ietf-tls-esni)
- CF [blog](https://blog.cloudflare.com/encrypted-sni/) on esni
- Openssl on [guthub](https://github.com/openssl/openssl)
	- I always have to look this stuff up as I don't do it often...
	- Forking instructions [here](https://help.github.com/articles/fork-a-repo/)
	- Syncing with upatream [instructions](https://help.github.com/articles/syncing-a-fork/)
	- Eventually, all going well, we may do a [PR](https://help.github.com/articles/about-pull-requests/) with out results
- My [fork](https://github.com/sftcd/openssl)
	- This file is in there as [README.SFTCD-ESNI.md](./README.SFTCD-ESNI.md)

## Initially - check stuff out...

I downloaded, built & ran openssl tests, all easy, peasy.

Poking around the code, I find that:

- code/openssl/ssl/statem/README is the next place to look
- code/openssl/ssl/extensions.c seems to be where a bunch of the action takes place
- would wanna define functions for an EXTENSION_DEFINITION for esni, that struct has:
			
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

- A sketch of what those might do for esni:
	- type, as per I-D from exp space
	- context - dunno TBD
	- init - not sure yet
		- server: check policies wrt doing-it, local, remote
		- client: 
	- construct_ctos 
		- check DNS for key for whatever's in SNI (so do after real SNI)
		- if no RR found, mark to not include and exit
		- make CH value as per I-D
		- change SNI value to dummy  - what value?
	- parse_ctos 
		- check known key
		- decrypt
		- success, local:
		- success, remote: 
	- contsruct_stoc
		- make EE value, from 
	- parse_stoc
		- check presence and nonce
	- final
		- on client did server answer and with right nonce?

## Some baby steps:

DONE - fork openssl
- add a command line arg to say to try esni
- go from there:-)

