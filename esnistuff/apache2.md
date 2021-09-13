
# Playing about with Apache2 and ECH

We earlier did all this for [ESNI](#ESNI), a precursor to ECH.

## Clone and Build for ECH draft-13

Continuing to use my fork of https://github.com/apache/httpd but now
with a branch for ECH draft-13.

That's apache 2.5 - whereas 2.4 is probably what's widely used.
Might want to revert to that later, but we'll see (also later:-). 

Turns out that needs the Apache Portable Runtime (APR) to build. (That name
rings a bell from the distant past;-) As recommended, my httpd build has the
APR stuff in a ``srclib`` sub-directory of the httpd source directory.

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/httpd httpd-draft-13
            $ cd httpd-draft-13
            $ git checkout ECH-experimental
            $ cd srclib
            $ git clone https://github.com/apache/apr.git
            $ cd ..
            $ ./buildconf
            ... stuff ...

And off we go with configure and make ...

            $ export CFLAGS="-I$HOME/code/openssl/include"
            $ export LDFLAGS="-L$HOME/code/openssl"
            $ ./configure --enable-ssl --with-ssl=$HOME/code/openssl
            ... loads of stuff ...
            $ make -j8
            ... lotsa lotsa stuff ...

As of 20210912 that build generates some deprecated warnings and
one code change was needed due to the API name change to
``SSL_CTX_ech_set_callback`` from ``SSL_CTX_set_ech_callback``.

## Generate TLS and ECH keys

This should be the same as for [nginx](nginx.md#generate), et al.

At least, I'm using the same keys for now and that seems ok.

## ECH Configuration in Apache

I added a server-wide ``SSLECHKeyDir`` setting (as with
[lighttpd](lightttpd.md) that ought have the directory where ECH key pair
files are stored, and we then load those keys as before using a
``load_echkeys()`` function in ``ssl_module_init.c``.  That seems to load keys
ok. There's an example in [apachemin-draft-13.conf](apachemin-draft-13.conf). 

## Run

I created a [testapache-draft-13.sh](testapache-draft-13.sh) script to start a
local instance of apache for example.com and foo.example.com on port 9443. That
uses (what I hope is) a pretty minimal configuration that can be found in
[apachemin-draft-13.conf](apachemin-draft-13.conf).  That starts an instance of
httpd listening on port 9443 with VirtualServers for example.com (default) and
foo.example.com. 

When that's running then you can use curl to access web pages:

            $ cd $HOME/code/openssl/esnistuff
            $ ./testapache-draft-13.sh 
            Killing old httpd in process 303611
            Executing:  /home/stephen/code/httpd-draft-13/httpd -f /home/stephen/code/openssl/esnistuff/apachemin-draft-13.conf
            $

Then you can use ``echcli.sh`` to request a web page while using ECH:

            $ ./echcli.sh -p 9443 -s localhost -H foo.example.com  -P d13.pem -f index.html
            Running ./echcli.sh at 20210913-001916
            ./echcli.sh Summary: 
            Looks like it worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $

For the above ``error.log`` should contain a line like:

            [Mon Sep 13 00:19:16.722021 2021] [ssl:info] [pid 209841:tid 140548152501824] [client 127.0.0.1:56556] AH10240: ECH success outer_sni: example.com inner_sni: foo.example.com

And ``access.log`` should contain something like:

            127.0.0.1 - - [13/Sep/2021:00:19:16 +0000] foo.example.com "GET /index.html HTTP/1.1" 200 "-" "-"

## Clone and Build for ECH draft-10

Continuing to use my fork of https://github.com/apache/httpd but now
with a branch for ECH stuff.

That's apache 2.5 - whereas 2.4 is probably what's widely used.
Might want to revert to that later, but we'll see (also later:-). 

Turns out that needs the Apache Portable Runtime (APR) to build. (That name
rings a bell from the distant past;-) As recommended, my httpd build has the
APR stuff in a ``srclib`` sub-directory of the httpd source directory.

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/httpd httpd-draft-10
            $ cd httpd-draft-10
            $ git checkout ECH-experimental
            $ cd srclib
            $ git clone https://github.com/apache/apr.git
            $ cd ..
            $ ./buildconf
            ... stuff ...

And off we go with configure and make ...

            $ export CFLAGS="-I$HOME/code/openssl/include"
            $ export LDFLAGS="-L$HOME/code/openssl"
            $ ./configure --enable-ssl --with-ssl=$HOME/code/openssl
            ... loads of stuff ...
            $ make -j8
            ... lotsa lotsa stuff ...

    - An Ubuntu 18.04 server required an additional ``sudo apt install libxml2-dev``
    and adding ``--with-libxml2`` to the configure command line above and adding
    and include path to CFLAGS to get that to work.

            $ export CFLAGS="-I$HOME/code/openssl/include -I/usr/include/libxml2"
            $ export LDFLAGS="-L$HOME/code/openssl"
            $ ./configure --enable-ssl --with-ssl=$HOME/code/openssl --with-libxml2
            ... loads of stuff ...
            $ make -j8
            ... lotsa lotsa stuff ...

On machines where I have >1 openssl build I tend to use $HOME/code/openssl-draft-10 
for example. You might find that in some scirpt or other and have to adjust.

## Generate TLS and ECH keys

This should be the same as for [nginx](nginx.md#generate), et al.

At least, I'm using the same keys for now and that seems ok.

## ECH Configuration in Apache

I added a server-wide ``SSLECHKeyDir`` setting (as with
[lighttpd](lightttpd.md) that ought have the directory where ECH key pair
files are stored, and we then load those keys as before using a
``load_echkeys()`` function in ``ssl_module_init.c``.  That seems to load keys
ok. There's an example in [apachemin-draft-10.conf](apachemin-draft-10.conf). 

## Run

I created a [testapache-draft-10.sh](testapache-draft-10.sh) script to start a
local instance of apache for example.com and foo.example.com on port 9443. That
uses (what I hope is) a pretty minimal configuration that can be found in
[apachemin-draft-10.conf](apachemin-draft-10.conf).  That starts an instance of
httpd listening on port 9443 with VirtualServers for example.com (default) and
foo.example.com. 

When that's running then you can use curl to access web pages:

            $ cd $HOME/code/openssl/esnistuff
            $ ./testapache-draft-10.sh 
            Killing old httpd in process 303611
            Executing:  httpd -f apachemin.conf
            $

Then you can use ``echcli.sh`` to request a web page while using ECH:

            $ ./echcli.sh -p 9443 -s localhost -H foo.example.com  -P `./pem2rr.sh -p echkeydir/foo.example.com.ech` -f index.html
            Running ./echcli.sh at 20210421-143445
            Assuming supplied ECH is RR value
            ./echcli.sh Summary: 
            Looks like it worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $

For the above ``error.log`` should contain a line like:

            Wed Apr 21 14:34:45.280917 2021] [ssl:info] [pid 304816:tid 139958983890496] [client 127.0.0.1:38748] AH10240: ECH success outer_sni: example.com inner_sni: foo.example.com

And ``access.log`` should contain something like:

            `127.0.0.1 - - [21/Apr/2021:14:34:45 +0000] foo.example.com "GET /index.html HTTP/1.1" 200 "-" "-"

One oddity is that I also see this error:

            [Wed Apr 21 14:34:45.676815 2021] [core:notice] [pid 304814:tid 139958999263104] AH00051: child pid 304816 exit signal Abort (6), possible coredump in /home/stephen/code/openssl/esnistuff

I'm not sure if that's caused by my code or something else. One [web
page](https://serverfault.com/questions/894248/ah00052-child-pid-pid-exit-signal-aborted-6-apache-error?noredirect=1)
implies it might be something to do with PHP configuration, but it's one to
check out. I don't see the same issue every time when using our curl ECH with ECH
but I have seen it sometimes. Using ``echcli.sh`` without trying ECH hasn't 
so far caused that error though.

One theory on the above: I did see ``s->rbio`` possibly being free'd twice, so
perhaps protect that as with ``s->wbio`` - see ``ssl/ssl_lib.c:1260`` or
about there. Haven't committed that change as IIRC it leads to a leak in
other contexts and the need for this should disappear once I move all
the ECH decryption stuff to before the outer CH is handled.

You can also use our ECH-enabled curl build to test this.  Note that I've added
example.com and foo.example.com to ``/etc/hosts`` as having addresses within
127.0.0/24. (If you don't do that you'll need to use curl's ``--connect-to`` or
``--resolve`` command line arguments to handle things.)

            $ cd $HOME/code/curl
            $ src/curl https://foo.example.com:9443/index.html --cacert ../openssl/esnistuff/cadir/oe.csr -v --echconfig AED+CgA8vwAgACCB9YyilgR2NMLVPOsESVceIrfGpXThGIUMIwGfGClmSgAEAAEAAQAAAAtleGFtcGxlLmNvbQAA
            * STATE: INIT => CONNECT handle 0x55b089e61fc8; line 1634 (connection #-5000)
            * Added connection 0. The cache now contains 1 members
            * STATE: CONNECT => RESOLVING handle 0x55b089e61fc8; line 1680 (connection #0)
            ... lots of stuff, then some HTML...
            <p>This is the pretty dumb top page for foo.example.com testing. </p>

            </body>
            </html>

            * STATE: PERFORMING => DONE handle 0x555980130fc8; line 2240 (connection #0)
            * multi_done
            * Connection #0 to host foo.example.com left intact
            * Expire cleared (transfer 0x555980130fc8)

## Debugging

With a bit of arm-wrestling I figured out how to run apache in the debugger
loading all the various shared libraries needed with one process.  Since that's
too much to type each time, I made an [apachegdb.sh](apachegdb.sh) script to do
that. If you give it a function name as a command line argument it'll start the
server with a breakpoint set there. With no command line argument it just
starts the server.

To build for debug:

            $ export CFLAGS="-I$HOME/code/openssl/include -I/usr/include/libxml2 -g"
            $ export LDFLAGS="-L$HOME/code/openssl"
            $ ./configure --enable-ssl --with-ssl=$HOME/code/openssl --with-libxml2
            ... loads of stuff ...
            $ make clean 
            $ make -j8
            ... lotsa lotsa stuff ...

# defo.ie deployment

20210422: Deployed on port 11410. ECH works but looks like some server callback
isn't working right - we're currently getting back the cert for the ``public_name``
even though the client sees the ServerHello as meaning success in ECH. That's
a bit of a puzzle, but a twice-called callback with the first setting the
cert based on outer SNI might do it. Investigating...   

# ESNI

This is text from late 2019 and only kept for posterity.

State of play: ESNI seems to work ok. Not much tested of course;-)
Currently deployed on [https://defo.ie:9443](https://defo.ie:9443). 

Getting ESNI working was a bit harder than with [nginx](nginx.md) as
``mod_ssl`` sniffed the ClientHello as soon as one is seen (i.e., before ESNI
processing) and then set the key pair to use based on the cleartext SNI. I 
used the ESNI callback instead (if ESNI configured)  so the ``init_vhost()``
call (you can guess what that does:-) happens after successful server-side 
ESNI processing.  

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

    - The above was on a laptop running Ununtu 19.10 on which lots of other
      s/w has been built.

    - An Ubuntu 18.04 server required an additional ``sudo apt install libxml2-dev``
    and adding ``--with-libxml2`` to the configure command line above to get that to work.

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

- I'm using ``ap_log_error()`` liberally for now, mostly with ``APLOG_INFO``
  level (or higher).  There's a semi-automated log numbering scheme - the idea
is to start with code that uses the ``APLOGNO()`` macro with nothing in the
brackets, then to run a perl script (from $HOME/code/httpd) that'll generate
the next unique log number to use, and modify the code accordingly. (I guess
that would need re-doing when a PR is eventually submitted but can cross that
hurdle when I get there.) As I'll forget what to do, the first time I used this
the command I ran was:

            $ cd $HOME/code/httpd
            $ perl docs/log-message-tags/update-log-msg-tags modules/ssl/ssl_engine_config.c

- Adding the SSLESNIKeyDir config item required changes to: ``ssl_private.h``
  and ``ssl_engine_config.c``

- I added a ``load_esnikeys()`` function as with other servers, (in
  ``ssl_engine_init.c``) but as that is called more than once (not sure how to
avoid that yet) I needed it to not fail if all the keys we attempt to load in
one call are there already.  That's a change from what I did with other
servers. That seems to be called more than once for each VirtualHost at the
moment, which could do with being fixed (but doesn't break).

- There are various changes in ``ssl_engine_init.c``  and ``ssl_engine_kernel.c``
to handle ESNI. 

## Debugging

With a bit of arm-wrestling I figured out how to run apache in the debugger
loading all the various shared libraries needed with one process.  Since that's
too much to type each time, I made an [apachegdb.sh](apachegdb.sh) script to do
that. If you give it a function name as a command line argument it'll start the
server with a breakpoint set there. With no command line argument it just
starts the server.

## Reloading ESNI keys

Apparently giving apache a command line argument of "-k graceful" causes a
graceful reload of the configuration, without dropping existing connections.
(Not sure how well I can test that proposition.)
In any case, "-k graceful" does seem to have the required effect, so we'll
try that whenever we deploy in a context with regular key updates. For the
present that can be done via the [testapache.sh](testapache.sh) script by
providing a "graceful" parameter to the script:

            $ ./testapache.sh graceful
            Telling apache to do the graceful thing

In the error.log file we see:

            [Sat Nov 16 15:21:14.405010 2019] [mpm_event:notice] [pid 26579:tid 140622617413440] AH00493: SIGUSR1 received.  Doing graceful restart

    followed by some (but fewer) of the usual startup lines.

If we check the process IDs, that seems to be behaving as desired:

			$ ps -ef | grep httpd
			stephen  26579  1882  0 15:20 ?        00:00:00 httpd -d ./esnistuff -f ./esnistuff/apachemin.conf
			stephen  26580 26579  0 15:20 ?        00:00:00 httpd -d ./esnistuff -f ./esnistuff/apachemin.conf
			stephen  26581 26579  0 15:20 ?        00:00:00 httpd -d ./esnistuff -f ./esnistuff/apachemin.conf
			stephen  26582 26579  0 15:20 ?        00:00:00 httpd -d ./esnistuff -f ./esnistuff/apachemin.conf
			stephen  26665 24624  0 15:20 pts/2    00:00:00 grep --color=auto httpd
			$ ./testapache.sh graceful 
			Telling apache to do the graceful thing
			$ ps -ef | grep httpd
			stephen  26579  1882  0 15:20 ?        00:00:00 httpd -d ./esnistuff -f ./esnistuff/apachemin.conf
			stephen  26709 26579  0 15:21 ?        00:00:00 httpd -d ./esnistuff -f ./esnistuff/apachemin.conf
			stephen  26710 26579  0 15:21 ?        00:00:00 httpd -d ./esnistuff -f ./esnistuff/apachemin.conf
			stephen  26711 26579  0 15:21 ?        00:00:00 httpd -d ./esnistuff -f ./esnistuff/apachemin.conf
			stephen  26810 24624  0 15:21 pts/2    00:00:00 grep --color=auto httpd
			
(Note that the above output from ``ps`` has been edited for clarity, in reality you'd see
longer absolute path names there due to how [testapache.sh](testapache.sh) starts the
server. I'm not sure if that's really needed or not though.)

## PHP variables

As with lighttpd and nginx I added the following variables that are now visible to
PHP code:

- ``SSL_ENSI_STATUS`` - ``success`` means that others also mean what they say
- ``SSL_ESNI_HIDDEN`` - has value that was encrypted in ESNI (or ``NONE``)
- ``SSL_ESNI_COVER`` - has value that was seen in plaintext SNI (or ``NONE``)

I setup PHP for my apache deployment on [https://defo.ie:9443](https://defo.ie:9443). 
That's not part of the localhost test setup, and there were a couple of things to
do:

    - If needed, install fast-cgi:

            $ sudo apt install php7.2-cgi

    - I edited ``/etc/php/7.2/fpm/pool.d/www.conf`` to use localhost:9000,
      added ``proxy_module`` and ``proxy_fcgi_module`` to the global apache
      config and turn on PHP and added the following to the apache config for the
      VirtualHost using ESNI: 

            <FilesMatch "\.php$">
                SetHandler "proxy:fcgi://127.0.0.1:9000"
            </FilesMatch>
            Options +ExecCGI


## TODOs

- Fix up 1st error.log line that says e.g. "Connection to child 128 established (server example.com:443)" since we're not using port 443 at all
- Check how ESNI key configuration plays with VirtualHost and other stanzas.
  (``load_esnikeys()`` is still being called a lot of times.)
- Add other ESNI key configuration options (i.e. SSLESNIKeyFile) - maybe solicit 
  feedback from some apache maintainer first.
- Check if changes for deprecated functions break anything

