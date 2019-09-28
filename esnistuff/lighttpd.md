
# Playing with lighttpd

Initial notes as I play with ESNI-enabling lighttpd-1.4.

- I made a [fork](https://github.com/sftcd/lighttpd1.4)

##  Build:

            $ ./autogen.sh 
            ... stuff ...
            # I don't have bzip2 dev/headers and want my own openssl build so...
            $ export LDFLAGS=$HOME/code/openssl
            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $ ./configure --with-openssl=$HOME/code/openssl --without-bzip2
            ... stuff ...
            $ make
            ... stuff ...

The LDFLAGS seems to be needed to pick up the right .so's.

##  Test config:

Idea is to copy over a basic lighttpd config that can re-use the
keys (TLS and ESNI) otherwise used by ``testserver.sh`` so we'll
put things below in ``esnistuff`` for now.

That config is in [``lighttpdmin.conf``](./lighttpdmin.conf)

That basically has:

- example.com and foo.example.com listening on port 3443
- (ESNI enabling TBD)

I modified the ``make-example-ca.sh`` script to produce the 
catenated private key + certificate files that lighttpd needs
to match that configuration.

##  Test run:

The script [``testlighttpd.sh``](./testlighttpd.sh) sets environment vars and
then runs lighttpd from the build, listening on ports 3000 and 3443:

            $ ./testlighttpd.sh

As of now, you can test that with either of:

            $ ./testclient.sh -p 3443 -s localhost -n -c example.com -d -f index.html 
            $ ./testclient.sh -p 3443 -s localhost -n -c foo.example.com -d -f index.html 

Without having really tried anything, it looks like ESNI greasing works with
that! (Or at least doesn't break it:-)

            $ ./testclient.sh -p 3443 -s localhost -n -c example.com -d -f index.html -g

You can actually see the 0xffce extension value returned in the EncryptedExtensions
with that, so it does seem to be using my ESNI code. 

Note that if you omit the "-n" above, then a real ESNI will be sent and cause an error:

            2019-09-27 15:49:04: (mod_openssl.c.1796) SSL: 1 error:14000438:SSL routines::tlsv1 alert internal error 

I guess that should be a useful pointer into the lighttpd ``mod_openssl`` code!

## Configuring ESNI in lighttpd

I added two new configuration settings:

- ssl.esnimaxage - a time in seconds specifying how old an ESNI key pair can get
   (0 => infinite age)
- ssl.esnikeydir - the name of a directory we scan for ESNI key files (as produced
   by [``mk_esnikeys.c``](./mk_esnikeys.c) - we load all key pairs where we find
   matching <foo>.priv and <foo>.pub files with the right content that are not
   older than ssl.esnimaxage

## Run-time modification

Based on those configurations (i.e. if esnikeydir is set) I wrote up a
``load_esnikeys()`` function to call ``SSL_esni_server_enable()``, and that...
seems to just work, more-or-less first time. Who'da thunk! :-)

To try that out:

            $ ./testlighttpd.sh 
            2019-09-28 13:09:40: (mod_openssl.c.1088) SSL: loading esnikeydir  /home/stephen/code/openssl/esnistuff/esnikeydir for config item 0 
            2019-09-28 13:09:40: (mod_openssl.c.809) load_esnikeys:   /home/stephen/code/openssl/esnistuff/esnikeydir maxage:  10800 
            2019-09-28 13:09:40: (mod_openssl.c.857) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/ff01.pub 
            2019-09-28 13:09:40: (mod_openssl.c.857) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/e3.pub 
            2019-09-28 13:09:40: (mod_openssl.c.857) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/ff03.pub 
            2019-09-28 13:09:40: (mod_openssl.c.857) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/e2.pub 

            ... and in another shell...
            $ ./testclient.sh -p 3443 -s localhost -H foo.example.com  -c example.com -d -f index.html  -P esnikeydir/ff03.pub 
            ...
            ./testclient.sh Summary: 
            Nonce sent: OPENSSL: ESNI Nonce is NULL
            OPENSSL: ESNI H/S Client Random is NULL
            --
            OPENSSL: ESNI Nonce (16):
                f3:44:21:76:c2:c0:ac:61:ea:62:7d:c3:d9:3a:61:bc:
            Nonce Back: <<< TLS 1.3, Handshake [length 001b], EncryptedExtensions
                08 00 00 17 00 15 ff ce 00 11 00 f3 44 21 76 c2
                c0 ac 61 ea 62 7d c3 d9 3a 61 bc
            ESNI: success: cover: example.com, hidden: foo.example.com

And the access.log file for ligtthpd said:

            ...
            127.0.0.1 foo.example.com - [28/Sep/2019:13:03:26 +0100] "GET /index.html HTTP/1.1" 200 458 "-" "-"
            ...

Yay!

## Next up...

- Refuse to load keys that are too old (inside ``load_esnikeys``)
- Figure out when/how to re-scan ESNI keys directory
- Add control trial decryption


