
# Playing with lighttpd

Notes as I ESNI-enabled lighttpd-1.4.

##  Build

- I made a [fork](https://github.com/sftcd/lighttpd1.4)

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

##  Configuration

Idea is to copy over a basic lighttpd config that can re-use the
keys (TLS and ESNI) otherwise used by ``testserver.sh`` so we'll
put things below ``esnistuff`` in our openssl repo clone for now.

I modified the ``make-example-ca.sh`` script to produce the 
catenated private key + certificate files that lighttpd needs
to match that configuration.

That config is in [``lighttpdmin.conf``](./lighttpdmin.conf)

That basically has example.com and foo.example.com listening on port 3443.

To ESNI-enable that I added two new lighttpd configuration settings:

- ssl.esnimaxage - a time in seconds specifying how old an ESNI key pair can get
   (0 => infinite age, and 0 is the default so this is optional)
- ssl.esnikeydir - the name of a directory we scan for ESNI key files (as produced
   by [``mk_esnikeys.c``](./mk_esnikeys.c) - we load all key pairs where we find
   matching <foo>.priv and <foo>.pub files with the right content that are not
   older than ssl.esnimaxage - this is basically how you enable ESNI

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
            2019-09-28 13:09:40: (mod_openssl.c.1088) SSL: loading esnikeydir  /home/stephen/code/openssl/esnistuff/esnikeydir for config item 0 
            2019-09-28 13:09:40: (mod_openssl.c.809) load_esnikeys:   /home/stephen/code/openssl/esnistuff/esnikeydir maxage:  10800 
            2019-09-28 13:09:40: (mod_openssl.c.857) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/ff01.pub 
            2019-09-28 13:09:40: (mod_openssl.c.857) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/e3.pub 
            2019-09-28 13:09:40: (mod_openssl.c.857) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/ff03.pub 
            2019-09-28 13:09:40: (mod_openssl.c.857) load_esnikeys worked for  /home/stephen/code/openssl/esnistuff/esnikeydir/e2.pub 

            ... then in another shell...
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

And the esnistuff/lighttpd/log/access.log file for ligtthpd said:

            ...
            127.0.0.1 foo.example.com - [28/Sep/2019:13:03:26 +0100] "GET /index.html HTTP/1.1" 200 458 "-" "-"
            ...

Yay!

## Next up...

- Refuse to load keys that are too old (inside ``load_esnikeys``)
- Figure out when/how to re-scan ESNI keys directory
- Add control to enable trial decryption


