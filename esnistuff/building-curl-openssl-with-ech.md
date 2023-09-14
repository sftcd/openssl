

# Building OpenSSL and curl with ECH support

## 2023 Version

We've added support for ECH to a recent curl build. That can use HTTPS RRs
published in the DNS, if curl is using DoH, or else can accept the relevant
ECHConfig values from the command line.

This has not been tested. DO NOT USE!

But hopefully, this provides enough of a proof-of-concept to prompt an informed
discussion about a good path forward for ECH support in curl, when using
OpenSSL, or other TLS libraries, as those add ECH support.

### Build

To build our ECH-enabled OpenSSL fork:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/openssl
            $ cd openssl
            $ git checkout ECH-draft-13c
            $ ./config 
            ... stuff ...
            $ make -j8
            ... stuff (maybe go for coffee) ...
            $

To build our ECH-enabled curl fork, making use of the above:

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
 
If you don't get that WARNING at the end of the ``configure`` command, then ECH
isn't enabled, so go back some steps and re-do whatever needs re-doing:-) If you
want to debug curl then you should add ``--enable-debug`` to the ``configure``
command.

### Using ECH and DoH

Curl supports using DoH for A/AAAA lookups so it was relatively easy to add
retrieval of HTTPS RRs in that situation. To use ECH and DoH together:

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

We currently support the following new curl comand line arguments/options:

- ``--ech``: tells client to attempt ECH if possible (opportunistic) based on
  an HTTPS RR value found in the DNS, accessed using DoH
- ``--ech-hard``: tells client to attempt ECH as above or fail if that's not
  possible
- ``--echconfig``: supplies an ECHConfig from command line that will be used in
  preference to a value found in the answer to a DNS query for an HTTPS RR
- ``--echpublic``: over-rides the ``public_name`` from the ECHConfig with a
  name from the command line

Note that in the above "attempt ECH" means the client emitting a TLS
ClientHello with a "real" ECH extension, but that does not mean that the
relevant server will succeed in decrypting, as things can fail for other
reasons.

### Supplying an ECHConfig on the command line

To supply the ECHConfig on the command line, you might need a bit of
cut'n'paste, e.g.:

            $ dig +short https defo.ie
            1 . ipv4hint=213.108.108.101 ech=AED+DQA8PAAgACD8WhlS7VwEt5bf3lekhHvXrQBGDrZh03n/LsNtAodbUAAEAAEAAQANY292ZXIuZGVmby5pZQAA ipv6hint=2a00:c6c0:0:116:5::10

Then paste the base64 encoded ECHConfig onto the curl command line:

            $ LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl --ech --echconfig AED+DQA8PAAgACD8WhlS7VwEt5bf3lekhHvXrQBGDrZh03n/LsNtAodbUAAEAAEAAQANY292ZXIuZGVmby5pZQAA https://defo.ie/ech-check.php
            ...
            SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
            ... 

The output snippet above is within the HTML for the web page.

If you paste in the wrong ECHConfig (it changes hourly for ``defo.ie``) you'll
get an error like this:

            $ LD_LIBRARY_PATH=$HOME/code/openssl ./src/curl -vvv --ech --echconfig AED+DQA8yAAgACDRMQo+qYNsNRNj+vfuQfFIkrrUFmM4vogucxKj/4nzYgAEAAEAAQANY292ZXIuZGVmby5pZQAA https://defo.ie/ech-check.php
            ...
            * OpenSSL/3.2.0: error:0A00054B:SSL routines::ech required
            ...

There is a reason to keep this command line option - for use before publishing
the ECHConfig in the DNS (e.g. see
[draft-ietf-tls-wkech](https://datatracker.ietf.org/doc/draft-ietf-tls-wkech/)).

### Default settings

Curl has various ways to configure default settings, e.g. in ``$HOME/.curlrc``,
so one can set the DoH URL and enable ECH that way:

            $ cat ~/.curlrc
            doh-url=https://1.1.1.1/dns-query
            silent=TRUE
            ech=TRUE
            $

Note that when you use the system's curl command (rather than our ECH-enabled
build), it'll produce a warning that ``ech`` is an unknown option. If that's an
issue (e.g. if some script re-directs stdout and stderr somewhere) then adding
the ``silent=TRUE`` line above seems to fix the issue. (Though of course, yet
another script could depend on non-silent behaviour, so you'll have to figure
out what you prefer youself.)

And if you want to always use our OpenSSL build you can set ``LD_LIBRARY_PATH``
in the environment:

            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $

Note that when you do that, there can be a mismatch between OpenSSL versions
for applications that check that. A ``git push`` for example will fail so you
should unset ``LD_LIBRARY_PATH`` before doing that or use a different shell.

            $ git push
            OpenSSL version mismatch. Built against 30000080, you have 30200000
            ...

With all that setup as above the command line gets simpler:

            $ ./src/curl https://defo.ie/ech-check.php
            ...
            SSL_ECH_STATUS: success <img src="greentick-small.png" alt="good" /> <br/>
            ... 

The ``--ech`` option is opportunistic, so will try to do ECH but won't fail if
the client e.g. can't find any ECHConfig values.  The ``--ech-hard`` option
hard-fails if there is no ECHConfig found in DNS, so for now, that's not a good
option to set as a default.

### Code changes for ECH support when using DoH

All code changes are in a new ``ECH-experimental`` branch of our fork
([here](https://github.com/sftcd/curl/tree/ECH-experimental)) and are
``#ifdef`` protected via ``USE_ECH`` or ``USE_HTTPSRR``: 

- ``USE_HTTPSRR`` is used for HTTPS RR retrieval code that could be generically
  used should non-ECH uses for HTTPS RRs be identified, e.g. use of ALPN values
or IP address hints.

- ``USE_ECH`` protects ECH specific code, which is likely almost all also
  OpenSSL-specific. (Though some fragments should be usable for other TLS
libraries in future.)

There are various obvious code blocks for handling the new command line
arguments which aren't described here, but should be fairly clear.

The main functional change, as you'd expect, is in ``lib/vtls/openssl.c``
([here](https://github.com/sftcd/curl/blob/ECH-experimental/lib/vtls/openssl.c#L3768))
where an ECHConfig, if available from command line or DNS cache, is fed into
the OpenSSL library via the new APIs implemented in our OpenSSL fork for that
purpose.  This code also implements the opportunistic (``--ech``) or hard-fail
(``--ech-hard``) logic. (There's about 100 new LOC involved there.)

Other than that, the main additions are in ``lib/doh.c``
([here](https://github.com/sftcd/curl/blob/ECH-experimental/lib/doh.c#L418))
where we re-use ``dohprobe()`` to retrieve an HTTPS RR value for the target
domain.  If such a value is found, that's stored using a new ``store_https()``
function
([here](https://github.com/sftcd/curl/blob/ECH-experimental/lib/doh.c#L527)) in
a new field in the ``dohentry`` structure.

The qname for the DoH query is modified if the port number is not 443, as
defined in the SCVB specification.
([here](https://github.com/sftcd/curl/blob/ECH-experimental/lib/doh.c#L418))

When the DoH process has worked, ``Curl_doh_is_resolved()`` now also returns
the relevant HTTPS RR value in the ``Curl_dns_entry`` structure.
([here](https://github.com/sftcd/curl/blob/ECH-experimental/lib/doh.c#L1086))
That is later accessed when the TLS session is being established, if ECH is
enabled (from ``lib/vtls/openssl.c`` as described above).

A couple of things that need fixing, but that can probably be ignored for the
moment:

- As of now, memory handling for the HTTPS RR values just uses straight calls
  to ``malloc()`` and ``free()`` - those need to be replaced with whatever are
the right curl equivalents.

- There is also a new file ``lib/ech.c`` that implements a
  ``Curl_ech_is_ready()`` check, used from within ``lib/vtls/openssl.c`` - that
could probably be eliminated, as the actual checks are now also effectively
inline in ``lib/vtls/openssl.c`` (That's a bit of a hang-over from our 2021
code, but we've left it there for now.)

- We could easily add code to make use of an ``alpn=`` value found in an HTTPS
  RR, passing that on to OpenSSL for use as the "inner" ALPN value, but have
yet to do that.

Current limitations (more interesting than the above):

- Only the first HTTPS RR value retrieved is actually processed as described
  above, that could be extended in future, though picking the "right" HTTPS RR
could be non-trivial if multiple RRs are published - matching IP address hints
versus A/AAAA values might be a good basis for that. Last I checked though,
browsers supporting ECH didn't handle multiple HTTPS RRs well, though that
needs re-checking as it's been a while.

- It's unclear how one should handle any IP address hints found in an HTTPS RR.
  It may be that a bit of consideration of how "multi-CDN" deployments might
emerge would provide good answers there, but for now, it's not clear how best
curl might handle those values when present in the DNS.

- The SVCB/HTTPS RR specification supports a new "CNAME at apex" indirection
  ("aliasMode") - the current code takes no account of that at all. One could
envisage implementing the equivalent of following CNAMEs in such cases, but
it's not clear if that'd be a good plan. (As of now, chrome browsers don't seem
to have any support for that "aliasMode" and we've not checked Firefox for that
recently.)

- We have not investigated what related changes or additions might be needed
  for applications using libcurl, as opposed to use of curl as a command line
tool.

### Supporting ECH without DoH

All of the above only applies if DoH is being used.  There should be a use-case
for ECH when DoH is not used by curl - if a system stub resolver supports DoT
or DoH, then, considering only ECH and the network threat model, it would make
sense for curl to support ECH without curl itself using DoH.  The author for
example uses a combination of stubby+unbound as the system resolver listening
on localhost:53, so would fit this use-case.  That said, it's very unclear if
this is a niche that's worth trying to address. (The author is just as happy to
let curl use DoH to talk to the same public recursives that stubby might use:-)
But assuming this is a use-case we'd like to support...

If DoH is not being used by curl, it's not clear at this time how to provide
support for ECH. One option would seem to be to extend the ``c-ares`` library
to support HTTPS RRs, but in that case it's not now clear whether such changes
would be attractive to the ``c-ares`` maintainers, nor whether the "tag=value"
extensibility inherent in the HTTPS/SVCB specification is a good match for the
``c-ares`` approach of defining structures specific to decoded answers for each
supported RRtype.  We're also not sure how many downstream curl deployments
actually make use of the ``c-ares`` library, which would affect the utility of
such changes.  Another option might be to consider using some other generic DNS
library (such as the getdnsapi) that does support HTTPS RRs, but it's unclear
if such a library could or would be used by all or almost all curl builds and
downstream releases of curl.

### WolfSSL

Mailing list discussion indicates that WolfSSL also supports ECH and can be
used by curl, so we'll see if we can code up the ability to use either OpenSSL
or WolfSSL. For now, these are notes as we explore that. We're starting by
making a fork in case we find some changes are needed within WolfSSL:

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/wolfssl
            $ cd wolfssl
            $ ./autogen.sh
            $ ./configure --prefix=$HOME/code/wolfssl/inst --enable-ech --enable-debug --enable-opensslextra
            $ make
            $ make install

The install prefix (``inst``) in the above causes WolfSSL to be installed there
and we seem to need that for the curl configure command to work out.  The
``--enable-opensslextra`` turns out (after much faffing about;-) to be
important or else we get build problems with curl below.

Let's now try use that to build curl...

            $ cd $HOME/code
            $ git clone https://github.com/sftcd/curl
            $ cd curl
            $ git checkout ECH-experimental
            $ autoregen -fi
            $ ./configure --with-wolfssl=$HOME/code/wolfssl/inst --enable-ech
            $ make
            ...

We're not yet in a working state, but getting there. Right now, this
works with an ECHConfig supplied on the command line for CF but not
DEfO. So there's stuff to be done but next steps are obvious.

#### Changes to support WolfSSL

There are what seem like oddball differences:

- The DoH URL in``$HOME/.curlrc`` can use "1.1.1.1" for OpenSSL but has to be
  "one.one.one.one" for WolfSSL. The latter works for both, so ok, we'll change
  to that.
- There seems to be some difference in CA databases too - the WolfSSL version
  doesn't like defo.ie, wheraas the system and OpenSSL ones do. We can ignore
  that for our purposes though via ``--insecure`` but would need to fix for a
  PPA setup. (Browsers do like defo.ie's cert btw:-)

Then there are some functional code changes:

- tweak to ``configure.ac`` to check if WolfSSL has ECH or not 
- added code to ``lib/vtls/wolfssl.c`` mirroring what's described for the
  OpenSSL equivalent above.

And a few obvious ones:

- tweak to ``src/tool_cfgable.h`` to remove include of OpenSSL ``ech.h`` (wasn't needed anyway)

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
