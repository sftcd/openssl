
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

- HTTP on port 3000
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

##  Next up:

Try figure out how to turn on ESNI within the server!


