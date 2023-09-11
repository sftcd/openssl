

# Building OpenSSL and curl with ECH support

## 2023 Version

2023-09-10 - So far, this has only even been checked via a basic test using ECH
when curl is also using DoH.  We also replicate the 2021 behaviour allowing
provision of ECHConfig values on the command line. (Those will be preferred to
values from HTTPS RRs, if supplied.) Of course, DO NOT USE this for anything
sensitive!

To build our OpenSSL fork:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl
            $ cd openssl
            $ git checkout ECH-draft-13c
            $ ./config 
            ... stuff ...
            $ make -j8
            ... stuff (maybe go for coffee) ...
            $

To build curl: clone the repo, checkout the branch, then run buildconf and
configure with abtruse settings:-) These are needed so the curl configure
script picks up our ECH-enabled OpenSSL build - configure checks that the ECH
functions are actually usable in the OpenSSL with which it's being built at
this stage. (Note: The ``LD_LIBRARY_PATH`` setting will be need whenever you
run this build of curl, e.g. after a logout/login, or a new shell.)

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/curl
            $ cd curl
            $ git checkout ECH-experimental
            $ autoreconf -fi
            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $ LDFLAGS="-L$HOME/code/openssl" ./configure --with-ssl=$HOME/code/openssl --enable-ech 
            ...lots of output...
              WARNING: ech ECH enabled but marked EXPERIMENTAL. Use with caution!
            $ make 
            ...lots more output...
 
If you don't get that warning at the end then ECH isn't enabled so go back some
steps and re-do whatever needs re-doing:-) If you want to debug curl then you
should add ``--enable-debug`` to the ``configure`` command.

### Using ECH and DoH

Curl has some support for using DoH for A/AAAA lookups so it was relatively easy
to add retrieval of HTTPS RRs in that situation. To use ECH and DoH together:

            $ cd $HOME/code/curl
            $ LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl --ech --doh-url https://1.1.1.1/dns-query https://defo.ie/ech-check.php
            ...
            SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
            ... 

The output snippet above is within the HTML for the web page, when things work.

The above works for https://defo.ie/ech-check.php,
https://draft-13.esni.defo.ie:8413/stats,
https://crypto.cloudflare.com/cdn-cgi/trace and https://tls-ech.dev so we seem
to have the basic thing functioning now.

### Supplying an ECHConfig on the command line

You can also supply the ECHConfig on the command line which may mean a bit of
cut'n'paste, e.g.:

            $ $ dig +short https defo.ie
            1 . ipv4hint=213.108.108.101 ech=AED+DQA8PAAgACD8WhlS7VwEt5bf3lekhHvXrQBGDrZh03n/LsNtAodbUAAEAAEAAQANY292ZXIuZGVmby5pZQAA ipv6hint=2a00:c6c0:0:116:5::10

Then paste the base64 encoded ECHConfig onto the curl command line:

            $ LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl --ech --echconfig AED+DQA8PAAgACD8WhlS7VwEt5bf3lekhHvXrQBGDrZh03n/LsNtAodbUAAEAAEAAQANY292ZXIuZGVmby5pZQAA https://defo.ie/ech-check.php
            ...
            SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
            ... 

The output snippet above is within the HTML for the web page.

If you paste in the wrong ECHConfig (it changes hourly) you'll get an error for now:

            $ LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl --ech --echconfig AED+DQA8yAAgACDRMQo+qYNsNRNj+vfuQfFIkrrUFmM4vogucxKj/4nzYgAEAAEAAQANY292ZXIuZGVmby5pZQAA https://defo.ie/ech-check.php
            curl: (35) OpenSSL/3.2.0: error:0A00054B:SSL routines::ech required

There is a reason to keep this command line option - for use before publishing
the ECHConfig in the DNS (e.g. see
[draft-ietf-tls-wkech](https://datatracker.ietf.org/doc/draft-ietf-tls-wkech/).

### Default settings

Curl has various ways to configure default settings, e.g. in ``$HOME/.curlrc``, so
one can set the DoH URL that way:

            $ cat ~/.curlrc
            doh-url=https://1.1.1.1/dns-query
            ech=TRUE
            $

And if you want to always use our OpenSSL build you can set ``LD_LIBRARY_PATH`` in the environment:

            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $

Note that when you do that, there can be a mismatch between OpenSSL versions
for applications that check that. A ``git push`` for example will fail so 
you should unset ``LD_LIBRARY_PATH`` before doing that or use a different
shell.

            $ git push
            OpenSSL version mismatch. Built against 30000080, you have 30200000
            ...

With all that the command line gets simpler:

            $ ./src/curl https://defo.ie/ech-check.php
            ...
            SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
            ... 

The ``--ech`` option is opportunistic, so will try to do ECH but won't fail if
the client e.g. can't find any ECHConfig values.  The ``--ech-hard`` option
hard-fails if there is no ECHConfig found in DNS, so for now, that's not a good
option to set as a default.


## 2021 Version

September 15th 2021.

Notes on an earlier version of this with Encrypted Server Name Indication
(ESNI), which is the precursor to ECH, are [below](#Notes).

Our OpenSSL fork with an ECH support branch is at:
[https://github.com/sftcd/openssl/](https://github.com/sftcd/openssl/).  

Our curl fork with an ECH support branch is at:
[https://github.com/niallor/curl/](https://github.com/niallor/curl/).

To build our OpenSSL fork:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl
            $ git checkout ECH-draft-13a
            $ ./config 
            ... stuff ...
            $ make -j8
            ... stuff (maybe go for coffee) ...
            $

To test that worked:

            $ cd $HOME/code/openssl/esnistuff
            $ ./echcli.sh -d
            ... lots of debug output...
            ./echcli.sh Summary: 
            Looks like it worked ok
            ECH: success: outer SNI: 'cloudflare-esni.com', inner SNI: 'crypto.cloudflare.com'
            $

To build curl: clone the repo, checkout the branch, then run buildconf and
configure with abtruse settings:-) These are needed so the curl configure
script picks up our ECH-enabled OpenSSL build - configure checks that the ECH
functions are actually usable in the OpenSSL with which it's being built at
this stage. (Note: The ``LD_LIBRARY_PATH`` setting will be need whenever you
run this build of curl, e.g. after a logout/login, or a new shell.)

            $ cd $HOME/code
            $ git clone https://github.com/niallor/curl.git
            $ cd curl
            $ git checkout draft-13a
            $ ./buildconf
            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $ LDFLAGS="-L$HOME/code/openssl" ./configure --with-ssl=$HOME/code/openssl --enable-ech 
            ...lots of output...
              WARNING: ech enabled but marked EXPERIMENTAL. Use with caution!
            $ make 
            ...lots more output...
 
If you don't get that warning at the end then ECH isn't enabled so go back some steps
and re-do whatever needs re-doing:-)

To test curl, using our draft-13 nginx server on defo.ie:

            $ src/curl --echconfig AED+DQA8AgAgACCuXw02/lUWxgMiwhhZzjkP11LxoTwi4TLxDH/gMtVBIQAEAAEAAQANY292ZXIuZGVmby5pZQAA https://draft-13.esni.defo.ie:10413/
            ... HTML output that includes: ...
            SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
            ...
            $ 

Some of our test configurations may require adding a ``-k`` to the above to
tell curl to ignore the TLS server cert check result.  For some reason curl
locally someetimes doesn't like the LetsEncrypt intermediate our server is
sending or something. (Will fix later, but it's not an ECH issue.)

# Notes on Building OpenSSl and curl with ESNI support

August 30th 2019.

These notes were produced as part of the OTF-funded [DEfO](https://defo.ie)
project.  Stephen Farrell (stephen.farrell@cs.tcd.ie) did the work on OpenSSL.
Niall O'Reilly (niall.oreilly+github@ucd.ie) did the work on curl.
If you find issues (and we expect you will) with this build, please feel free
to contact either of us at the above email addresses or using the info@defo.ie
alias.

## Repositories

Our OpenSSL fork with ESNI support is at: [https://github.com/sftcd/openssl/](https://github.com/sftcd/openssl/).
Our curl fork with ESNI support is at: [https://github.com/niallor/curl/](https://github.com/niallor/curl/).

For this build we've done initial testing with specific tagged versions of
those repos. Things should work ok if you build from the tip but we may break
that from time to time, so you're better off taking the tagged version
(probably:-). The tag we're using for this initial cut of both of our
OpenSSL and curl forks is "esni-2019-08-30" and is used in the ``git clone``
commands shown below.

We assume below that you checkout all repos below ``$HOME/code``. If you use
some other directory you'll need to adjust commands below, and most of our
OpenSSL test scripts (e.g. ``openssl/esnistuff/testclient.sh``) also assume that
``$HOME/code/openssl`` is the top directory (see note on the ``$TOP`` environment
variable below). 

If you prefer to build some other way (e.g. with objects not in the source
directory), this is made easy and documented in the OpenSSL distribution, but
not in the curl distribution.  Please consult the OpenSSL documentation for how
to do that. (It's not complicated, but there's no need to duplicate the
instructions here.)  For curl, you have to duplicate the entire repo tree (for
example, using tar), so it's only useful if you strongly prefer to keep a
really clean local copy of the repo.

We also assume that you have a development machine that can build vanilla
OpenSSL and curl - if not, you may need to install dependencies as you go.

## Building OpenSSL

- clone repo:

            $ cd $HOME/code
            $ git clone --branch esni-2019-08-30 https://github.com/sftcd/openssl

- make config:

            $ cd openssl
            $ ./config

- make:

            $ make
            ...go for coffee...
            $ cd esnistuff
            $ make

Now you can test that via our [testclient.sh](testclient.sh) wrapper script (also in the ``esnistuff`` directory)...

If you cloned OpenSSL somewhere other than ``$HOME/code``, you can export an
environment variable ``TOP`` and that will be used instead of
``$HOME/code/openssl``

This tests that ESNI works against the cloudflare deployment:

            $ ./testclient.sh -H ietf.org
            Running ./testclient.sh at 20190828-072413
            ./testclient.sh Summary: 
            Looks like 1 ok's and 0 bad's.
            
            $

This tests that ESNI works against our defo.ie deployment:

            $ ./testclient.sh -H only.esni.defo.ie -c cover.defo.ie 
            Running ./testclient.sh at 20190828-072453
            ./testclient.sh Summary: 
            Looks like 1 ok's and 0 bad's.

            $

If you add a ``-d`` to the above, you get lots and lots of debug output. 
If that ends with something like:

            ESNI: success: cover: cover.defo.ie, hidden: only.esni.defo.ie

...then all is well.

Test scripts in the ``esnistuff`` directory take a ``-h`` for help on other options
and there is a ``test-examples.md`` file with various example uses of the
``testclient.sh`` and ``testserver.sh`` scripts.  

## Building curl

- clone repo:

            $ cd $HOME/code
            $ git clone --branch esni-2019-08-30 https://github.com/niallor/curl.git
            $ cd curl

- run buildconf (takes a short while)

            $ ./buildconf

- run configure with abtruse settings:-) These are needed so the curl configure 
script picks up our ESNI-enabled OpenSSL build - configure checks that
the ESNI functions are actually usable in the OpenSSL with which it's being
built at this stage. (Note: The ``LD_LIBRARY_PATH`` setting will be need whenever
you use this build of curl, e.g. after a logout/login.)

            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $ LDFLAGS="-L$HOME/code/openssl" ./configure --with-ssl=$HOME/code/openssl --enable-esni --enable-debug
            ...lots of output...
              WARNING: esni enabled but marked EXPERIMENTAL. Use with caution!
 
If you don't get that warning at the end then ESNI isn't enabled so go back some steps
and re-do whatever needs re-doing:-)

- build it

            $ make
            ...go for coffee...

- test via a wrapper script...

            $ cp $HOME/code/openssl/esnistuff/curl-esni .
            $ ./curl-esni https://only.esni.defo.ie/stats
            ...lots of output...

If that appears to work ok, you can confirm it by re-directing
output to a file then grepping through that, so you could see
something like:

			$ ESNI_COVER="haha" ./curl-esni https://only.esni.defo.ie/stats >xx 2>&1
            $
			$ grep -i esni  xx
			curl-esni: 1 Found ESNI_COVER (haha)
			* Connected to only.esni.defo.ie (2a04:2e00:1:15::a) port 443 (#0)
			* Found ESNI parameters:
			*   flag ssl_enable_esni (SET)
			*   flag ssl_strict_esni (SET)
			*   STRING_ESNI_SERVER (only.esni.defo.ie)
			*   STRING_ESNI_COVER (haha)
			*   STRING_ESNI_ASCIIRR (/wHxhIoFACQAHQAgeDl90CzpQq1RPx7i+q1ZXMnXu/Me/d6ef/JxQHSNbEMAAhMBAQQAAAAAXWkSGAAAAABdaScwAAA=)
			* SSL_ESNI object version (ff01)
			* Found 1 ESNI key
			* Configured encrypted server name (ESNI) TLS extension
			*  subject: CN=esni.defo.ie
			*  subjectAltName: host "only.esni.defo.ie" matched cert's "*.esni.defo.ie"
			> Host: only.esni.defo.ie
			<h1>OpenSSL with ESNI</h1>
			ESNI success: cover: haha, hidden: only.esni.defo.ie
			    SNI/Hostname: only.esni.defo.ie
			    ESNI/encservername: only.esni.defo.ie
			    ESNI/covername: haha
			    ESNI/public_name is NULL

Of the last few lines there, the "ESNI success" output is the best
indicator of success. Note that this last invocation of the 
``curl-esni`` script demonstrates over-riding the default 
cleartext SNI (the ``ESNI_COVER``) via an environment 
variable.
