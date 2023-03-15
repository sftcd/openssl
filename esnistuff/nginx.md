
# ECH-enabling Nginx

Notes on our proof-of-concept nginx with ECH integration.

## March 2023 Clone and Build

These are the updated notes from 20230315 for nginx with ECH.
(Slightly) tested on ubuntu 20.10, with latest nginx code.

First, you need a separate clone of our OpenSSL build (because nginx's build, in this
instantiation, re-builds OpenSSL and links static libraries, so we put that in a new
directory in order to avoid disturbing other builds):

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl.git openssl-for-nginx
            $ cd openssl-for-nginx
            $ git checkout ECH-draft-13c
            $ ./config -d
            ...stuff...
            $ make
            ...go for coffee...

Then you need nginx, and to switch to our ``ECH-experimental`` branch:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/nginx.git
            $ cd nginx
            $ git checkout ECH-experimental
            $ ./auto/configure --with-debug --prefix=nginx --with-http_ssl_module --with-openssl=$HOME/code/openssl-for-nginx  --with-openssl-opt="--debug"
            $ make
            ... go for coffee ...

To test, (configuration is in ``nginxmin-draft-13.con``):

            $ ./testnginx-draft-13.sh
            ...stuff...
            $ ./echcli.sh -p 5443 -s localhost -H foo.example.com  -P d13.pem -f index.html
            Running ./echcli.sh at 20230315-121742
            ./echcli.sh Summary: 
            Looks like ECH worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'
            $ 
            $ killall nginx # to stop daemon

Seems to work ok again.

## 2021 Clone and Build 

These are the updated notes from 20210912 for ECH draft-13.

First, you need a separate clone of our OpenSSL build (because nginx's build, in this
instantiation, re-builds OpenSSL and links static libraries, so we put that in a new
directory in order to avoid disturbing other builds):

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl.git openssl-for-nginx-draft-13
            $ cd openssl-for-nginx-draft-13
            $ git checkout ECH-draft-13a
            $ ./config -d
            ...stuff...
            $ make
            ...go for coffee...

Then you need nginx, and to switch to our ``ECH-experimental`` branch:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/nginx.git nginx-draft-13
            $ cd nginx-draft-13
            $ git checkout ECH-experimental
            $ ./auto/configure --with-debug --prefix=nginx --with-http_ssl_module --with-openssl=$HOME/code/openssl-for-nginx-draft-13  --with-openssl-opt="--debug"
            $ make
            ... go for coffee ...

## ECH configuration in Nginx

To turn on ECH - configure a directory (via ``ssl_echkeydir``) that contains
key files. I did the directory based approach first, as I'd used that with
``openssl s_server`` and [lighttpd](lighttpd.md).

I added an ECH key directory configuration setting that can be within the
``http`` stanza 
in the nginx config file. Then, with a bit of generic parameter handling
and the addition of a ``load_echkeys()`` function that's pretty much as done
for [lighttpd](./lighttpd.md).

The ``load_echkeys()`` function expects ECH key files to be in the configured
directory. It attempts to load all files matching ``<foo>.ech``
It skips any files that don't match that naming pattern or don't parse correctly.  

You can see that configuration setting, called ``ssl_echkeydir`` in our
test [nginxmin-draft-13.confg](nginxmin-draft-13.conf).

            $ ./testnginx-draft-13.sh
            ... stuff ...
            $ ./echcli.sh -p 5443 -s localhost -H foo.example.com  -P d13.pem 
            Running ./echcli.sh at 20210912-204750
            ./echcli.sh Summary: 
            Looks like it worked ok
            ECH: success: outer SNI: 'example.com', inner SNI: 'foo.example.com'

We log when keys are loaded or re-loaded. That's in the error log and looks like:

            2021/09/12 21:46:50 [notice] 164558#0: load_echkeys, worked for: /home/stephen/code/openssl/esnistuff/echkeydir/echconfig.pem.ech
            2021/09/12 21:46:50 [notice] 164558#0: load_echkeys, worked for: /home/stephen/code/openssl/esnistuff/echkeydir/d13.pem.ech
            2021/09/12 21:46:50 [notice] 164558#0: load_echkeys, total keys loaded: 2

We log when ECH is attempted, and works or fails, or if it's not tried. The
success case is at the NOTICE log level, whereas other events are just logged
at the INFO level. The success case in ``error.log`` looks like:

            2021/09/12 21:47:50 [notice] 164560#0: *1 ECH success outer_sni: example.com inner_sni: foo.example.com while SSL handshaking, client: 127.0.0.1, server: 0.0.0.0:5443


## Deployment 

We have an ECH draft-13 nginx instance running at [https://draft-13.esni.defo.ie:10413/](https://draft-13.esni.defo.ie:10413/)

The main defo.ie web server on port 443 is now also nginx with an ECH check page at 
[https://defo.ie/ech-check.php](https://defo.ie/ech-check.php).

## PHP variables

I added the following variables that are now visible to PHP code:

- ``SSL_ECH_STATUS`` - ``success`` means that others also mean what they say
- ``SSL_ECH_INNER_SNI`` - has value that was in inner CH SNI (or ``NONE``)
- ``SSL_ECH_OUTER_SNI`` - has value that was in outer CH SNI (or ``NONE``)

To see those using fastcgi you need to include the following in the relevant
bits of nginx config:

            fastcgi_param SSL_ECH_STATUS $ssl_ech_status;
            fastcgi_param SSL_ECH_INNER_SNI $ssl_ech_inner_sni;
            fastcgi_param SSL_ECH_OUTER_SNI $ssl_ech_outer_sni;

# ESNI

I have a first version of Nginx with ESNI enabled working. Not much tested 
and but it was pretty easy and seems to work.

## Clone and Build 

First, you need our OpenSSL build:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl.git openssl-for-nginx
            $ cd openssl-for-nginx
            $ ./config --debug
            ...stuff...
            $ make
            ...go for coffee...

Then you need nginx:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/nginx.git
            $ cd nginx
            $ ./auto/configure --with-debug --prefix=nginx --with-http_ssl_module --with-openssl=$HOME/code/openssl-for-nginx --with-openssl-opt="--debug"
            $ make
            ... go for coffee ...

- That builds openssl afresh (incl. a ``make config; make clean``) and then
  links static libraries from that build. Hence cloning the OpenSSL fork into
``openssl-for-nginx`` - if you've another OpenSSL build (say for
[lighttpd](./lighttpd.md) this build would mess that up. 
- The static libraries for OpenSSL end up below
  ``$HOME/code/openssl-for-nginx/.openssl``
- A ``make`` in the nginx directory doesn't detect code changes within OpenSSL.
  Bit brute-force but deleting that new ``.openssl`` directory gets you a
re-build. 
- End result is you need two clones of openssl if you want to build openssl
  shared objects (e.g. for lighttpd) and staticly for nginx. I mucked up a few
times when using the same source tree for both. I'm sure that can be improved,
but I've not figured out how yet.

## Generate TLS and ESNI keys

We have a couple of key generation scripts:

- [make-example-ca.sh](make-example-ca.sh) that generates a fake CA and TLS 
  server certs for example.com, foo.example.com and baz.example.com - that
  can be used for testing on localhost.
- [make-esnikeys.sh](make-esnikeys.sh) generates ESNI keys for local testing

(Note that I've not recently re-tested those, but bug me if there's a problem
and I'll check/fix.)

## Run nginx for localhost testing 

The "--prefix=nginx" setting in the nginx build is to match our [testnginx.sh](testnginx.sh)
script.  The [nginxmin.conf](nginxmin.conf) file that uses has a minimal configuration to 
match our localhost test setup.

            $ cd $HOME/code/openssl/esnistuff
            $ ./testnginx.sh
            ... prints stuff, spawns server and exits ...
            $ curl  --connect-to baz.example.com:443:localhost:5443 https://baz.example.com/index.html --cacert cadir/oe.csr 
            
            <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
            <html xmlns="http://www.w3.org...

If you'd prefer the server to not daemoise, there's a "daemon off;" line in
the config file you can uncomment. That's useful with valgrind or gdb.

Valgrind seems to be ok wrt leaks in various tests, though it's a little harder
to tell given the master/worker process model. Nothing definitely leaked
though. (And our tests are pretty basic so far.)

## ESNI configuration in Nginx

For now, we've got two different ways to turn on ESNI - by configuring
a directory that contains key files, or by configuring the names of
key files. I did the directory based approach first, as I'd used that
with ``openssl s_server`` and [lighttpd](lighttpd.md), but one of
the upstream maintainers wasn't keen on that so I added the file name
based approach as well. 

At the moment, I'm still in the process of testing the 2nd option there.

### Via ``ssl_esnikeydir``

I added an ESNI key directory configuration setting that can be within the
``http`` stanza (and maybe elsewhere too, I don't fully understand all that
yet;-) in the nginx config file. Then, with a bit of generic parameter handling
and the addition of a ``load_esnikeys()`` function that's pretty much as done
for [lighttpd](./lighttpd), ESNI... just worked!

The ``load_esnikeys()`` function expects ENSI key files to be in the configured
directory. It attempts to load all pairs of files with matching ``<foo>.priv``
and ``<foo>.pub`` file names. It should nicely skip any files that don't parse
correctly.  I *think* that may be implemented portably (I use ``ngx_read_dir``
now instead of ``readdir`` but more may be needed for it to work ok on win32,
needs checking.)

You can see that configuration setting, called ``ssl_esnikeydir`` in our
test [nginxmin.confg](nginxmin.conf).

            $ ./testnginx.sh
            ... stuff ...
            $ /testclient.sh -p 5443 -s localhost -H baz.example.com -c example.net -P esnikeydir/e3.pub
            Running ./testclient.sh at 20191012-125357
            ./testclient.sh Summary: 
            Looks like 1 ok's and 0 bad's.

We log when keys are loaded or re-loaded. That's in the error log and looks like:

            2019/10/12 14:32:13 [notice] 16953#0: load_esnikeys, worked for: /home/stephen/code/openssl/esnistuff/esnikeydir/ff01.pub
            2019/10/12 14:32:13 [notice] 16953#0: load_esnikeys, worked for: /home/stephen/code/openssl/esnistuff/esnikeydir/e3.pub
            2019/10/12 14:32:13 [notice] 16953#0: load_esnikeys, worked for: /home/stephen/code/openssl/esnistuff/esnikeydir/ff03.pub
            2019/10/12 14:32:13 [notice] 16953#0: load_esnikeys, worked for: /home/stephen/code/openssl/esnistuff/esnikeydir/e2.pub
            2019/10/12 14:32:13 [notice] 16953#0: load_esnikeys, total keys loaded: 4

Note that even though I see 3 occurrences of those log lines, we only end up
with 4 keys loaded as the library function checks whether files have already
been loaded. (Based on name and modification time, only - not the file content.)

We log when ESNI is attempted, and works or fails, or if it's not tried. The
success case is at the NOTICE log level, whereas other events are just logged
at the INFO level. That looks like:

            2019/10/13 14:50:29 [notice] 9891#0: *10 ESNI success cover: example.net hidden: foo.example.com while SSL handshaking, client: 127.0.0.1, server: 0.0.0.0:5443

### Via ``ssl_esnikeyfile``

The second option for loading ESNI keys is to have both public and private key
in one file and to load a bunch of those. This config setting can be
in the same places as ``ssl_esnikeydir``, that is, within the http settings
or below. (And I still don't grok all that stuff:-)

            ssl_esnikeyfile     esnikeydir/ff01.key;
            ssl_esnikeyfile     esnikeydir/ff03.key;

Since the files here are a mixture of private and public keys, we need both
to be PEM encoded. For no particularly good reason, the priavte key must be
first in the file. An example of such a file might be:

            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VuBCIEIEDyEDpfvLoFYQi4rNjAxAz7F/Dqydv5IFmcPpIyGNd8
            -----END PRIVATE KEY-----
            -----BEGIN ESNIKEY-----
            /wG+49mkACQAHQAgB8SUB952QOphcyUR1sAvnRhY9NSSETVDuon9/CvoDVYAAhMBAQQAAAAAXYZC
            TwAAAABdlBoPAAA=
            -----END ESNIKEY-----

I mailed the [TLS list](https://mailarchive.ietf.org/arch/msg/tls/hMOQpQ12IIzHfOHhQjSmjphKJ1g)
suggesting we standardise this format as part of the work on ESNI. Nobody
objected to doing that, so, for now, I've documented that wee bit of formatting 
in an [Internet-draft](https://tools.ietf.org/html/draft-farrell-tls-pemesni).

## Reloading ESNI keys

Nginx will reload its configuration if you send it a SIGHUP signal. That's easier
to use than we saw with lighttp, so if you change the set of keys in the ESNI key
directory then you can:

            $ kill -SIGHUP `cat nginx/logs/nginx.pid`

...and that does cause the ESNI key files to be reloaded nicely. If you add and
remove key files, that all seems ok, I guess because nginx cleans up (worker)
processses that have the keys in memory. (That's nicely a lot easier than with 
lighttpd:-) 

## PHP variables

As with lighttpd I added the following variables that are now visible to
PHP code:

- ``SSL_ENSI_STATUS`` - ``success`` means that others also mean what they say
- ``SSL_ESNI_HIDDEN`` - has value that was encrypted in ESNI (or ``NONE``)
- ``SSL_ESNI_COVER`` - has value that was seen in plaintext SNI (or ``NONE``)

To see those using fastcgi you need to include the following in the relevant
bits of nginx config:

            fastcgi_param SSL_ESNI_STATUS $ssl_esni_status;
            fastcgi_param SSL_ESNI_HIDDEN $ssl_esni_hidden;
            fastcgi_param SSL_ESNI_COVER $ssl_esni_cover;

## Some OpenSSL deprecations 

On 20191109 I re-merged my nginx fork with upstream, and then built against the
latest OpenSSL.  I had to fix up a couple of calls to now-deprecated OpenSSL
functions. I think I found non-deprecated alternatives for both. Those were:
    - ``SSL_CTX_load_verify_locations``
    - ``ERR_peek_error_line_data``

## TODO/Improvements...

- Figure out how to get nginx to use openssl as a shared object.
- It'd be better if the ``ssl_esnikeydir`` were a "global" setting probably
  (like ``error_log``) but I need to figure out how to get that to work still.
For now it seems it has to be inside the ``http`` stanza, and one occurrence of
the setting causes ``load_esnikeys()`` to be called three times in our test
setup which seems a little off. (It's ok though as we only really store keys
from different files.)



