
# Playing about with Apache2

State of play: ESNI worked in a localhost setup. 

Getting ESNI working was a bit harder than with [nginx](nginx.md) as
``mod_ssl`` sniffed the ClientHello as soon as one is seen (i.e., before ESNI
processing) and then set the key pair to use based on the cleartext SNI. I had
to use the ESNI print callback instead (if ESNI configured)  so that's done
after ESNI processing.  That really ought be a new callback for use after ENSI
processing but before the main TLS key exchange. So I should make the print
callback more generic.

## Clone and Build

I started by forking httpd from https://github.com/apache/httpd, just because
it's familiar.  That's apache 2.5 - whereas 2.4 is probably what's widely used.
Might want to revert to that later, but we'll see (also later:-). 

Turns out that needs the Apache Portable Runtime (APR) to build. (That name
rings a bell from the distant past;-) As recommended, my httpd build has the
APR stuff in a ``srclib`` sub-directory of the httpd source directory.

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/httpd
            $ cd httpd
            $ cd srclib
            $ git clone https://github.com/apache/apr.git
            $ cd ..
            $ ./buildconf
            ... stuff ...

Before running configure, this build seems to assume that OpenSSL shared
objects will be in a ``lib`` subdirectory of the one we specify, and similarly
for an ``include`` directory. The latter is true of OpenSSL builds, but the
former is not (in my case anyway). We'll work around that with a link:

            $ ln -s $HOME/code/openssl $HOME/code/openssl/lib

If you re-configure your OpenSSL build (e.g. re-running
``$HOME/code/openssl/config``) then you may need to re-do the above step.

And off we go with configure and make ...

            $ ./configure --enable-ssl --with-ssl=$HOME/code/openssl
            ... loads of stuff ...
            # I got an error on the 2nd last ouput line there:
            #           rm: cannot remove 'libtoolT': No such file or directory
            # but it seems to work out ok so far
            $ make -j8
            ... lotsa lotsa stuff ...

After running configure, I see mention of ``$HOME/code/openssl`` in
``modules/ssl/modules.mk`` that seems to the right things with
includes and shared objects.

Other configure options I may want (later):
            --enable-debugger-mode
            --enable-log-debug

## Generate TLS and ESNI keys

This should be the same as for [nginx](nginx.md#generate)

At least, I'm using the same keys for now and that seems ok.

## ESNI Configuration in Apache

I added a server-wide ``SSLESNIKeyDir`` setting (as with
[lighttpd](lightttpd.md) that ought have the directory where ESNI key pair
files are stored, and we then load those keys as before using a
``load_esnikeys()`` function in ``ssl_module_init.c``.  That seems to load keys
ok. There's an example in [apachemin.conf](apachemin.conf). 

## Run

I created a [testapache.sh](testapache.sh) script to start a local instance of apache 
for example.com and baz.example.com on port 9443. That uses (what I hope is) a 
pretty minimal configuration that can be found in [apachemin.conf](apachemin.conf).
That starts an instance of httpd listening on port 9443 with VirtualServers
for example.com (default) and baz.example.com.

When that's running then you can use curl to access web pages:

            $ cd $HOME/code/openssl/esnistuff
            $ ./testapache.sh
            Killing old httpd in process 17365
            Executing:  httpd -f apachemin.conf
            $
            $ curl --connect-to example.com:9443:localhost:9443 https://example.com:9443/index.html --cacert cadir/oe.csr
            ... you should see HTML now ...
            $ curl --connect-to baz.example.com:9443:localhost:9443 https://baz.example.com:9443/index.html --cacert cadir/oe.csr
            ... you should see slightly different HTML now ...

If I try my testclient against an apache server with no ESNI configured I get the expected 
behaviour, which is for the server to return a GREASE ESNI
value, when it gets sent one.

            $ ./testclient.sh -p 9443 -s localhost -H baz.example.com -c example.com -P esnikeydir/ff03.pub -d
            ... loadsa stuff...
			ESNI Nonce (16):
			    96:52:2d:18:f9:bc:09:7e:8e:70:cb:1d:bf:db:25:50:
			Nonce Back: <<< TLS 1.3, Handshake [length 006c], EncryptedExtensions
			    08 00 00 68 00 66 00 00 00 00 ff ce 00 5e 01 55
			    8c 49 42 e3 30 d0 9d b7 3c ce fe 14 ad 13 ea 1d
			    2b 27 97 63 eb e8 79 42 e3 9f b8 15 b4 76 7a 19
			    85 d8 ab 8c 9c 59 82 eb 2d 05 83 16 75 18 80 1f
			    b6 24 2c ab c0 c6 a7 6d 03 28 ab 53 b1 44 8c e7
			ESNI: tried but failed
            
The "ff ce" just after the "Nonce Back" line there is the 
extension type for the GREASEd value - in that case it's
0x5e long. (The extract above doesn't have the entire value
in case you're wondering.)

Trying after ESNI is configured now works and (with OpenSSL tracing on) looks like:

            $ ./testclient.sh -p 9443 -s localhost -H baz.example.com -c whatever  -P esnikeydir/ff03.pub -d -f index.html
            ... lotsa stuff ...
            ./testclient.sh Summary: 
            Nonce sent: ESNI Nonce: buf is NULL
            ESNI H/S Client Random: buf is NULL
            --
            ESNI Nonce (16):
                8f:90:5c:63:d9:83:4c:ae:83:3b:75:0b:0a:39:89:1a:
            Nonce Back:     EncryptedExtensions, Length=23
                extensions, length = 21
                    extension_type=encrypted_server_name(65486), length=17
                    Got an esni of length (17)
                        ESNI (len=17): 008F905C63D9834CAE833B750B0A39891A
            ESNI: success: clear sni: 'whatever', hidden: 'baz.example.com'

Without OpenSSL tracing you'll see fewer lines but it's the last one that counts.

In the apache server error log (with "info" log level) we also see:

            [Sat Nov 16 07:30:46.717225 2019] [ssl:info] [pid 7769:tid 139779161855744] [client 127.0.0.1:52010] AH01964: Connection to child 129 established (server example.com:443)
            [Sat Nov 16 07:30:46.718464 2019] [ssl:info] [pid 7769:tid 139779161855744] [client 127.0.0.1:52010] AH10246: later call to get server nane of |baz.example.com|
            [Sat Nov 16 07:30:46.718519 2019] [ssl:info] [pid 7769:tid 139779161855744] [client 127.0.0.1:52010] AH10248: init_vhost worked for baz.example.com


## Code changes in httpd

Quick notes on code changes I've made so far:

- All changes are within ``modules/ssl``.

- I've bracketed my changes with ``#ifdef HAVE_OPENSSL_ESNI``. That's
defined in ``ssl_private.h`` if the included ``ssl.h`` defines ``SSL_OP_ESNI_GREASE``.

- The build generated a few warnings of deprecated OpenSSL functions, but seems
  ok otherwise. (This is similar to what I saw in [nginx](nginx.md) and
[lighttpd](lighttpd.md).) I modified calls to these as I did for lighttpd but
the changes may be dodgier in this case and I likely won't be testing them
(soon) as they seem related to client auth and CRLs. The deprecated functions
are listed below 
    - ``SSL_CTX_load_verify_locations()``
    - ``X509_STORE_load_locations()``
    - ``ERR_peek_error_line_data()``

- I'm using ``ap_log_error()`` liberally for now, with ``APLOG_INFO`` level (or
  higher) even if some of those should be debug really.  There's a
semi-automated log numbering scheme - the idea is to start with code that uses
the ``APLOGNO()`` macro with nothing in the brackets, then to run a perl script
(from $HOME/code/httpd) that'll generate the next unique log number to use, and
modify the code accordingly. (I guess that would need re-doing when a PR is
eventually submitted but can cross that hurdle when I get there.) As I'll
forget what to do, the first time I used this the command I ran was:

            $ cd $HOME/code/httpd
            $ perl docs/log-message-tags/update-log-msg-tags modules/ssl/ssl_engine_config.c

- Adding the SSLESNIKeyDir config item required changes to: ``ssl_private.h``
  and ``ssl_engine_config.c``

- I added a ``load_esnikeys()`` function as with other servers, (in ``ssl_engine_init.c``)
  but as that is called more than once (not sure how to avoid that yet) I
needed to not fail if all the keys we attempt to load in one call are there already. That
also seems to be called more than once for each ``SSL_CTX`` at the moment, which could
do with being fixed (but doesn't break).

- There are various changes in ``ssl_engine_init.c``  and ``ssl_engine_kernel.c``
to handle ESNI. All of those need to be tidied up.

## Debugging

With a bit of arm-wrestling I figured out how to run apache in the debugger
loading all the various shared libraries needed with one process.  Since that's
too much to type each time, I made an [apachegdb.sh](apachegdb.sh) script to do
that. If you give it a function name as a command line argument it'll start the
server with a breakpoint set there. With no command line argument it just
starts the server.

## TODOs

- Proper logging of ESNI success/failure (there's basically debug stuff there now)
- Tidy up code generally.
- Make ``load_esnikeys()`` portable (using APR).
- Make ESNI callback more generic. (Requires changes to my OpenSSL library, 
  and hence other applications I've done too.)
- Make ESNI status visible to e.g. PHP applications.
- Check how ESNI key configuration plays with VirtualHost and other stanzas.
- Check if changes for deprecated functions break anything
- Add other ESNI key configuration options (i.e. SSLESNIKeyFile) - maybe solicit 
  feedback from some apache maintainer first.
- Testing, testing, testing.

