
# Playing about with Apache2

No ESNI code changes have been made yet, just keeping notes as I setup 
for that...

## Clone and Build

I started by forking httpd from https://github.com/apache/httpd, just because it's familiar.
That's apache 2.5 - whereas 2.4 is probably what's widely used. Might want to revert to
that later, but we'll see (also later:-). 

Turns out that needs the Apache Portable Runtime (APR) to build. (That name
rings a bell from the distant past;-) As recommended, my httpd build has the
APR stuff in a ``srclib`` sub-directory of the httpd source directory.

            $ cd $HOME/code
            $ cd httpd
            $ git clone https://github.com/sftcd/httpd
            $ cd srclib
            $ git clone https://github.com/apache/apr.git
            $ cd ..
            $ ./buildconf
            ... stuff ...

Before running configure, this build seems to assume that OpenSSL shared objects will
be in a ``lib`` subdirectory of the one we specify, and similarly for an ``include``
directory. The latter is true of OpenSSL builds, but the former is not (in my case
anyway). We'll work around that with a link:

            $ ln -s $HOME/code/openssl $HOME/code/openssl/lib

And now off we go with configure and make ...

            $ ./configure --enable-ssl --with-ssl=$HOME/code/openssl
            ... loads of stuff ...
            # I got an error on the 2nd last ouput line there:
            # rm: cannot remove 'libtoolT': No such file or directory
            # but it seems to work out ok so far
            $ make -j8
            ... lotsa lotsa stuff ...

After running configure, I see mention of ``$HOME/code/openssl`` in
``modules/ssl/modules.mk`` that looks like it might do the right things
includes and shared objects.

That build does generate a few warnings of deprecated OpenSSL functions,
but seems ok otherwise. (Seems like the same stuff I saw in [nginx](nginx.mc) 
and [lighttpd](lighttpd.md).)

    Other configure options I may want (later):
            --enable-debugger-mode
            --enable-log-debug

## Generate TLS and ESNI keys

This should be the same as for [nginx](nginx.md#generate)

At least, I'm using the same keys for now and that seems ok.

## ESNI Configuration in Apache

TBD

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

If I try my testclient against that server I get the expected 
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


