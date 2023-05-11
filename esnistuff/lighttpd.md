
# Playing with lighttpd for ECH

## May 2023 catch up

Just a couple of minor updates based on ECH API changes since last time.
I didn't push those upstream though. That'll come soon enough.

## March 2023 catch up

Goal is to rebase with upstream changes and ECH API changes.

- running on ubuntu 22.10
- rebased with upstream (ended up manually reapplying changes
  to ``mod_openssl.c`` as rebasing/merging was more of a pain)

            $ git clone https://github.com/sftd/lighttpd1.4 
            ...
            $ cd lighttpd1.4
            $ git checkout ECH-experimental
            Branch 'ECH-experimental' set up to track remote branch 'ECH-experimental' from 'origin'.
            Switched to a new branch 'ECH-experimental'
            $ ./autogen.sh 
            ... stuff ...
            $ ./configure --with-openssl=$HOME/code/openssl --with-openssl-libs=$HOME/code/openssl
            ... stuff ...
            $ make
            ... stuff ...

The script [``testlighttpd.sh``](./testlighttpd.sh) sets environment vars and
then runs lighttpd from the build, listening (for HTTPS only) on port 3443:

            $ ./testlighttpd.sh
            ...stuff...

If your lighttpd build is not in ``$HOME/code/lighttpd1.4`` then you can set the
``$LIGHTY`` environment variable to point to top of the lighttpd build tree.

``testlighthtpd.sh`` script runs the server in foreground so you'll need to ctrl-C
out of that, when done. (Valgrind reports some seemingly fixed sized leaks on exit,
not sure if that's my fault or not.)

I also added example.com, foo.example.com, bar.example.com and bat.example.com to
``/etc/hosts`` to match the setup in [``lighthttpdmin.conf``](lighthttpdmin.conf).

You can then use our wrapper for ``openssl s_client`` to access a web page:

            $ ./echcli.sh  -p 3443 -s localhost -H foo.example.com -c example.com -P `./pem2rr.sh -p d13.pem` -f index.html
            Running ./echcli.sh at 20230314-230824
            Assuming supplied ECH is encoded ECHConfigList or SVCB
            ./echcli.sh Summary: 
            Looks like ECH worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $ 

All that seems to work ok.

## August 2022 migration of defo.ie

- running on ubuntu 22.04
- pcre-devel package no longer there it seems, trying libpre3-dev
- build errors - looks like a rebase needed so did that, 
    TODO - committed changes but more testing needed

## September 2021 vesion: draft-13 of ECH

### Housekeeping, Clone and build

- I took the 2019 ESNI `code and put that into an ECH-and-ESNI branch.
- I added [gstrauss'](https://github.com/gstrauss/lighttpd1.4) fork as
  upstream
- So from now on, I'll be psusing any minor changes of mine to that
  branch.
- You should build this against the [ECH-draft-13a](https://github.com/sftcd/openssl/tree/ECH-draft-13a)
  branch of my OpenSSL fork, if that's built in ``$HOME/code/openssl`` then all should be well. If not,
  you'll need to adjust stuff.


            $ git clone https://github.com/sftd/lighttpd1.4 
            ...
            $ cd lighttpd1.4
            $ git checkout ECH-experimental
            Branch 'ECH-experimental' set up to track remote branch 'ECH-experimental' from 'origin'.
            Switched to a new branch 'ECH-experimental'
            $ ./autogen.sh 
            ... stuff ...
            # I don't have bzip2 dev/headers and want my own openssl build so...
            # The below may also need --without-zlib
            $ ./configure --with-openssl=$HOME/code/openssl --with-openssl-libs=$HOME/code/openssl --without-bzip2
            ... stuff ...
            $ make
            ... stuff ...


### Configure

I configured a lighthttpd running on draft-13.esni.defo.ie:9413

The lightttpd configuration is unchanged from the draft-10 case described below
except for the hostname and port having changed to that above.

## April 2021 version (outdated now)

Notes on ECH-enabling lighttpd-1.4 starting 20210404.  (Followed by earlier
notes about how I [ESNI-enabled](#ESNI-version) lighttpd-1.4 back in 2019.).

Acknowlegement: Glenn Strauss (a lighttpd dev) has been of enormous assistance
with ECH. Any errors below are not his though.

The plan is similar to how ESNI was handled: 

- Create a server configuration item for the directory within which ECHConfig
  PEM files can be found, then load all those into the server's ``SSL_CTX``,
with periodic re-loads (if file is new/modified) to support key rotation.
- We also support a way to make a specific virtual host "ECH only" by
  configuring a (presumably different) virtual host name to use, if ECH wasn't
successfully used in the ClientHello for that TLS session.
- There's some additional (compile time) logging that can be turned on.
- Finally, we provide a way to make ECH related information available to the
  environment for things like PHP.

## ESNI -> ECH 

- I made a "last" [commit](https://github.com/sftcd/lighttpd1.4/commit/38640bbcabff307c74a28bc6e61a1f5978973e78) in
  case we want to resurrect ESNI at some point.
- And then re-based with upstream.
- And then threw away the ESNI changes from ``src/mod_openssl.c`` which was the only
  source file modified for ESNI and started in on ECH - it looks like there are a lot of changes 
  to that file from upstream and given FF has dropped ESNI, not much point aiming to support both ECH and ESNI. 

## Clone

We're using Glenn Stauss' [ECH-experimental](https://github.com/gstrauss/lighttpd1.4/tree/ECH-experimental/) branch
for lighttpd, 

            $ git clone https://github.com/gstrauss/lighttpd1.4 lighttpd1.4-gstrauss
            ...
            $ cd lighttpd1.4-gstrauss
            $ git checkout ECH-experimental
            Branch 'ECH-experimental' set up to track remote branch 'ECH-experimental' from 'origin'.
            Switched to a new branch 'ECH-experimental'
            $

## Build

            $ ./autogen.sh 
            ... stuff ...
            # I don't have bzip2 dev/headers and want my own openssl build so...
            # The below may also need --without-zlib
            $ ./configure --with-openssl=$HOME/code/openssl --with-openssl-libs=$HOME/code/openssl --without-bzip2
            ... stuff ...
            $ make
            ... stuff ...

I wanted to turn off optimisation at one stage of debugging - to do that ``export CFLAGS="-g "`` before
running the configure script seems to do the trick.

## Configuration

Added new server configuration settings, under ssl.ech-opts:

- keydir - name of directory scanned for ``*.ech`` files that will be parsed/used if they contain a private key and ECHConfig
- refresh - frequency (in seconds) to re-check whether some PEM files need to be reloaded
- trial-decrypt - whether or not ECH trial decryption is enabled 

In addition there's a virtual host specific configuration item:

- ssl.non-ech-host - name of vhost to pretend was used if ECH wasn't successful (or not tried)

Those are reflected in the [``lighthttpdmin.conf``](lighthttpdmin.conf) config file used in
local testing.

## Testing on localhost

First you'll need a bunch of keys for ECH and TLS generally:

            $ cd $HOME/code/openssl/esnistuff
            $ make keys

The script [``testlighttpd.sh``](./testlighttpd.sh) sets environment vars and
then runs lighttpd from the build, listening (for HTTPS only) on port 3443:

            $ ./testlighttpd.sh

The ``testlighthtpd.sh`` script runs the server in foreground so you'll ned to ctrl-C
out of that, when done. (Valgrind reports a small fixed sized leak on exit there,
not sure if that's my fault or not.)

I also added example.com, foo.example.com, bar.example.com and bat.example.com to
``/etc/hosts`` to match the setup in [``lighthttpdmin.conf``](lighthttpdmin.conf).

You can then use our wrapper for ``openssl s_client`` to access a web page:

            $ ./echcli.sh -d -p 3443 -s localhost -H foo.example.com -c example.com -P `./pem2rr.sh -p echconfig-10.pem` -v -f index.html
            Running ./echcli.sh at 20210416-213418
            Assuming supplied ECH is RR value
            ./echcli.sh Valgrind
            Binary file /tmp/echtest72YF matches
            
            ./echcli.sh Summary: 
            Looks like it worked ok
            Binary file /tmp/echtest72YF matches
            $ 

Or, if you've built it, you can use our ECH-enabled curl:

            $ export ECHCONFIG=`./pem2rr.sh -p echconfig.pem`
            $ cd $HOME/code/curl
            $ src/curl https://foo.example.com:3443/index.html -v     --cacert  /home/stephen/code/openssl/esnistuff/cadir/oe.csr --echconfig $ECHCONFIG
            <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
            <html xmlns="http://www.w3.org/1999/xhtml">
            <head>
            <title>Lighttpd top page.</title>
            </head>
            <!-- Background white, links blue (unvisited), navy (visited), red
            (active) -->
            <body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
            vlink="#000080" alink="#FF0000">
            <p>This is the pretty dumb top page for testing. </p>
            
            </body>
            </html>

## Deployment under defo.ie

There's an instance of lighttpd on our test server, listening on port 9410, with the associated HTTPS
RRs in DNS. 

The (currently) fixed ECHConfig for that is:

            AEL+CgA+8QAgACCsEiogyYobxSGHLGd6uSDbuIbW05M41U37vsypEWdqZQAEAAEAAQAAAA1jb3Zlci5kZWZvLmllAAA=

There are 3 virtual hosts:

- cover.defo.ie:9410 - no ECHConfig published in DNS
- draft-10.esni.defo.ie:9410 - ECHConfig published in DNS
- draft-10-echonly.esni.defo.ie:9410 - ECHConfig published in DNS, won't be served unless ECH succeeded

(The -echonly host isn't currently working... investigating...)

A basic test using ``echcli.sh``:

            $ ./echcli.sh -p 9410 -s defo.ie -H draft-10.esni.defo.ie  -f index.html 
            Running ./echcli.sh at 20210416-223656
            ./echcli.sh Summary: 
            Looks like it worked ok
            Binary file /tmp/echtestlqdw matches
            $ 

Using our ECH-enabled curl:

            $ curl --echconfig AEL+CgA+8QAgACCsEiogyYobxSGHLGd6uSDbuIbW05M41U37vsypEWdqZQAEAAEAAQAAAA1jb3Zlci5kZWZvLmllAAA= https://draft-10.esni.defo.ie:9410/
            ... HTML follows...



# ESNI-version

Text below documents the 2019 ESNI setup. 

##  Build

- I made a [fork](https://github.com/sftcd/lighttpd1.4)

            $ ./autogen.sh 
            ... stuff ...
            # I don't have bzip2 dev/headers and want my own openssl build so...
            # The below may also need --without-zlib
            $ ./configure --with-openssl=$HOME/code/openssl --with-openssl-libs=$HOME/code/openssl --without-bzip2
            ... stuff ...
            $ make
            ... stuff ...

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

The server will re-load all ESNI keys found inside the configured directory
once every refresh period using ``SSL_esni_server_enable`` which will reload
the keys if the relevant files are new or were modified. Before doing that it
flushes all the ESNI keys loaded more than a refresh period ago via
``SSL_esni_server_flush_keys()``.  The upshot should be that the server
reflects the set of keys on disk.

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

## Letting web site know ESNI was used

I'll go for having a bit of PHP script inside index.html displaying
a check mark or cross, depending whether ESNI was used to access the
page or not. I'm following the relevant bits of these 
[instructions](https://www.howtoforge.com/tutorial/installing-lighttpd-with-php7-php-fpm-and-mysql-on-ubuntu-16.04-lts/).

- Install PHP if needed... (versions may be different, so 7.2 might be
  something else everywhere)

            $ sudo apt-get -y install php7.2-fpm php7.2

- Edit ``/etc/php/7.2/fpm/php.ini`` to uncomment ``cgi.fix_pathinfo=1``

- Edit your lighttpd config to include:

            server.modules += ( "mod_fastcgi" )
            fastcgi.server += ( ".php" =>
                    ((
                            "socket" => "/var/run/php/php7.2-fpm.sock",
                            "broken-scriptfilename" => "enable"
                    ))
            )

I then further modified the lighttpd server (in ``mod_openssl.c:esni_status2env``) 
so that some ESNI related settings are placed into the environment. Those can be
used by e.g. PHP scripts. 

Those are:

- ``SSL_ESNI_STATUS``: values can be: 
    - "not attempted" - if the client didn't include the TLS ClientHello extension at all
    - "success" - if it all worked (succesful ESNI decrypt)
    - "tried but failed" - something went wrong during attempted decryption
    - "worked but bad name" - this is a client-side error, if the TLS server cert didn't match the ESNI
    - "error getting ESNI status" - if the call to ``SSL_get_esni_status`` failed
- ``SSL_ESNI_HIDDEN``: will contain the actual ESNI used or "NONE" 
- ``SSL_ESNI_COVER``: will contain the cleartext SNI seen or "NONE"

Here's a PHP snippet that will display those:

            <?php
                function getRequestHeaders() {
                    $headers = array();
                    foreach($_SERVER as $key => $value) {
                        if (substr($key, 0, 9) <> 'SSL_ESNI_') {
                            continue;
                        }
                        $headers[$key] = $value;
                     }
                    return $headers;
                }
                
                $headers = getRequestHeaders();
                
                foreach ($headers as $header => $value) {
                    echo "$header: $value <br />\n";
                }
            ?>

For now, similar information is also written to the lighttpd error.log for
every request if logging is enabled. That has the result, the cover (if any)
and the hidden (if any) and looks like: 

            2019-09-30 16:18:02: (mod_openssl.c.462) esni_status:  success cover.defo.ie only.esni.defo.ie 
            2019-09-30 16:29:18: (mod_openssl.c.462) esni_status:  not attempted NULL NULL 
            2019-09-30 16:29:38: (mod_openssl.c.462) esni_status:  success NULL canbe.esni.defo.ie 

## Requiring that a VirtualHost only be accessible via ESNI

The basic idea here is to explore whether or not it's useful to mark a
VirtualHost as "ESNI only", i.e. to try deny it's existence if it's asked for via
cleartext SNI.  I'm very unsure if this is worthwhile but since it could be done, it may
be fun to play and see if it turns out to be useful. 

To that end we've added an "ssl.esnionly" label that can be in a lighttpd configuration
for a TLS listener. If that is present and if the relevant server.name is used in the
cleartext SNI (with or without ESNI) then the TLS connection will fail.
For example, in my [localhost test setup](lighttpdmin.conf) baz.example.com is
now maked "ESNI only" as is [only.esni.defo.ie](https://only.esni.defo.ie/) in
our test deployment. 

Failing this check is logged in the error log, e.g.:

            2019-10-07 21:33:33: (mod_openssl.c.531) esni_status:  not attempted cover: NULL hidden: NULL 
            2019-10-07 21:33:33: (mod_openssl.c.644) esnionly abuse for only.esni.defo.ie from 2001:DB8::bad
            2019-10-07 21:33:33: (mod_openssl.c.2130) SSL: 1 error:140000EA:SSL routines::callback failed 

That log line includes the requesting IP address for now.

## Some OpenSSL deprecations 

On 20191109 I re-merged my nginx fork with upstream, and then built against the
latest OpenSSL.  I had to fix up a couple of calls to one now-deprecated OpenSSL
function (``SSL_CTX_load_verify_locations``).

## Further improvement

- The check as to whether or not ESNI keys need to be re-loaded happens with
  each new TLS connection. (Actually loading keys only happens when the refresh
period has gone by.) There may well be a better way to trigger that check, e.g.
there is some timing-based code in ``server.c`` but putting OpenSSL-specific
code in there would seem wrong, so maybe come back to this later. 
- The interaction between "outside" key management and re-publication, coupled
  with the way I'm reloading keys caused a problem - initially keys were being
reloaded every 1200 seconds, but there was only 3 minutes between the time when
the "outside" key manager job generated new keys and the time when the
zonefactory (re-)publisher tested to see if they worked. So that test was
failing, resulting in the new keys not being published and things getting out
of whack. As a quick, temporary, fix, I'm reloading keys every 2 mins now, but
this just highlights the need for a different interface, e.g. sending a signal
that a reload is needed or something.

