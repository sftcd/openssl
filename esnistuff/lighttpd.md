
# Playing with lighttpd

Notes as I ESNI-enabled lighttpd-1.4.

##  Build

- I made a [fork](https://github.com/sftcd/lighttpd1.4)

            $ ./autogen.sh 
            ... stuff ...
            # I don't have bzip2 dev/headers and want my own openssl build so...
            $ export LDFLAGS=$HOME/code/openssl
            # on another system I had to tweak this a bit presumably
            # due to different tools being installed...
            # so if the above causes a compile problem with doing
            # configure, then try...
            # $ export LDFLAGS="-L$HOME/code/openssl"
            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            # The below may also need --without-zlib
            $ ./configure --with-openssl=$HOME/code/openssl --without-bzip2
            ... stuff ...
            $ make
            ... stuff ...

The LDFLAGS seems to be needed to pick up the right .so's.

##  Configuration

First idea is to have a minimal lighttpd config that can re-use the keys (TLS
and ESNI) otherwise used by ``testserver.sh``  - so we'll put things below
``esnistuff`` in our openssl repo clone for now.  I modified the
``make-example-ca.sh`` script to produce the catenated private key +
certificate files that lighttpd needs to match our configuration.

That config is in [``lighttpdmin.conf``](./lighttpdmin.conf)

That basically has example.com and foo.example.com both listening on port 3443.

To ESNI-enable that I added three new lighttpd configuration settings:

- ssl.esnikeydir - the name of a directory we scan for ESNI key files (as
  produced by [``mk_esnikeys.c``](./mk_esnikeys.c)) - we load all key pairs
  where we find matching <foo>.priv and <foo>.pub files in that directory with
  the right content This allows for "outisde" key management as noted in our
  notes on [web server integration](./web-server-config.md).
- ssl.esnirefresh - a time in seconds specifying how often the server should
  try re-load the keys (default: 1800) 
- ssl.esnitrialdecrypt - set to "disable" (exactly) to turn off trial
  decryption, (it's is on by default).

Trial decryption here means if an ESNI extension received from a client has
a digest that doesn't match any loaded ESNI key, then we go through all loaded
ESNI keys and try use each to decrypt anyway, before we fail. For lighttpd,
that seems to make sense as we're expecting servers to be small and not
have many ESNI keys loaded.

##  Test runs

The script [``testlighttpd.sh``](./testlighttpd.sh) sets environment vars and
then runs lighttpd from the build, listening (for HTTPS only) on port 3443:

            $ ./testlighttpd.sh

That starts the server in the foreground so you need to hit ``^C`` to exit.
There's some temporary logging about ESNI that'll go away when we're more
done.

You can test that without ESNI with either of:

            $ ./testclient.sh -p 3443 -s localhost -n -c example.com -d -f index.html 
            $ ./testclient.sh -p 3443 -s localhost -n -c foo.example.com -d -f index.html 

Even before we changed any lighttpd code, ESNI greasing worked!

            $ ./testclient.sh -p 3443 -s localhost -n -c example.com -d -f index.html -g

You can see the 0xffce extension value returned in the EncryptedExtensions
with that, so it does seem to be using my ESNI code. 

## Run-time modification

Based on the above new configuration settings (i.e. if esnikeydir is set) I added
the ``load_esnikeys()`` function to call ``SSL_esni_server_enable()``, and that...
seems to just work, more-or-less first time. Who'da thunk! :-)

To try that out:

            $ ./testlighttpd.sh 
            2019-09-28 16:37:12: (mod_openssl.c.862) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/ff01.pub 
            2019-09-28 16:37:12: (mod_openssl.c.862) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/e3.pub 
            2019-09-28 16:37:12: (mod_openssl.c.862) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/ff03.pub 
            2019-09-28 16:37:12: (mod_openssl.c.862) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/e2.pub 

            ... then in another shell...
            $ ./testclient.sh -p 3443 -s localhost -H foo.example.com  -c example.com -d -f index.html  -P esnikeydir/ff03.pub 
            ...
            OPENSSL: ESNI Nonce (16):
                83:a5:0b:da:86:5a:f0:12:cd:28:e2:93:ea:56:f5:cb:
            Nonce Back: <<< TLS 1.3, Handshake [length 001b], EncryptedExtensions
                08 00 00 17 00 15 ff ce 00 11 00 83 a5 0b da 86
                5a f0 12 cd 28 e2 93 ea 56 f5 cb
            ESNI: success: cover: example.com, hidden: foo.example.com

And the esnistuff/lighttpd/log/access.log file for ligtthpd said:

            ...
            127.0.0.1 foo.example.com - [28/Sep/2019:16:37:55 +0100] "GET /index.html HTTP/1.1" 200 458 "-" "-"
            ...

Yay!

## Deployment on [defo.ie](https://defo.ie)

When I deployed that on [defo.ie](https://defo.ie) I noted fairly quickly that
it didn't work:-) 

Turned out the lighttpd ``mod_openssl.c:mod_openssl_client_hello_cb`` function
had two definitions - one that peeked into the TLS ClientHello octets to
extract the SNI, and another that called an OpenSSL to get the servername.
Using the latter with my fork results in the right thing happening for ESNI,
but of course the former would not. Easy enough fix to just force use of the
OpenSSL API. (Though presumably this may break wherever that peeking into
octets was really needed? Hopefully it was just legacy code or something.)
Anyway, good lesson that some applications might not be using all OpenSSL APIs
as designed and might be doing their own bits of TLS. 

With that done, FF nightly and my test scripts both seem ok with things:-)

## Further improvement

- The server will re-load all ESNI keys found inside the configured directory
  once every refresh period. Before doing that it ditches all current ESNI keys
though (via ``SSL_esni_server_flush_keys()``). It'd be better if the server
could just keep calling ``SSL_esni_server_enable()`` and have the library
internally figure out if the supplied key is new or old or not. Need to ponder
how best to do that. Might be most sensible to not make changes here until we
see how those might pan out in Apache or Nginx too, so leave this for now.
- At present, if the server tries but fails to re-load the ESNI keys and if
  that fails (e.g. due to a disk error) then the server will stop doing ESNI.
That could also be made more robust, and e.g. fall back to the last set of keys
that did successfully load. We'd need to change the OpenSSL API for that
though.
- The check as to whether or not ESNI keys need to be re-loaded happens with
  each new TLS connection. (Actually loading keys only happens when the refresh
period has gone by.) There may well be a better way to trigger that check, e.g.
there is some timing-based code in ``server.c`` but putting OpenSSL-specific
code in there would seem wrong, so maybe come back to this later. 
- Add some ESNI tracing e.g. when ``debug.log-request-handling`` is enabled.

