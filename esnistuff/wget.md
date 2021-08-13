
# Integrating wget

20190227

I'm starting to play with integrating this openssl build into wget.
I've not yet added any new stuff to wget, just building for now.

- wget can be built with openssl, even though gnutls is the default
- wget has some concept of using c-ares for DNS lookups, which we'll
  need to get ESNIKeys value(s)

Before this goes much further we should create a fork just for
our own version control. But first, we should check out [wget2](https://gitlab.com/gnuwget/wget2.git)
as the wget-dev mailing list seems mostly about that.

## wget Preliminaries

- clone wget:

            $ cd $HOME/code
            $ git clone https://git.savannah.gnu.org/git/wget.git

- install c-ares 

            $ sudo apt install libc-ares-dev

- get ready... and... build:

            $ cd $HOME/code/wget
            $ ./bootstrap
            ...much ado about gnulib...
            $ export CPPFLAGS='-I $HOME/code/openssl/include'
            $ export LDFLAGS='-L$HOME/code/openssl/' 
            $ ./configure --with-ssl=openssl --with-libssl-prefix=$HOME/code/openssl/ --with-cares
            $ make

    That generates a warning we should be able to fix ...but does build.

            CC       openssl.o
            openssl.c: In function 'ssl_init':
            openssl.c:178:7: warning: 'OPENSSL_config' is deprecated [-Wdeprecated-declarations]
                   OPENSSL_config (NULL);
                   ^~~~~~~~~~~~~~
            In file included from /usr/include/openssl/ct.h:13:0,
                            from /usr/include/openssl/ssl.h:61,
                            from openssl.c:40:
            /usr/include/openssl/conf.h:92:1: note: declared here
            DEPRECATEDIN_1_1_0(void OPENSSL_config(const char *config_name))
            ^

    I added a ``#include <openssl/esni.h>`` to ``src/openssl.c`` to check if
    the build'll pick up my changes, and it does (now, after messing about with
    many variations that weren't the above:-).

    Incidentally, ``configure --help`` provides misleading guidance (see below). But
    it seems that while those are defined in the Makefiles, that doesn't get passed
    on to the ``gcc`` command line. Maybe I got it wrong though and there's a way to
    make it work that's better than the above.

            $ ./configure --help
            ...lots of output, including...
            OPENSSL_CFLAGS
              C compiler flags for OPENSSL, overriding pkg-config
            OPENSSL_LIBS
              linker flags for OPENSSL, overriding pkg-config

## wget2 Preliminaries

Having done the above, I'll now try a similar build with wget2 and see what I see...

- (for me:) install lzip:

            $ sudo apt install lzip

- clone wget2:

            $ cd $HOME/code
            $ git clone https://gitlab.com/gnuwget/wget2.git

- get ready... and... build:

    - ``configure --help`` seems similar to before so I'll immediately try what 
    worked above...
    - note that the build process is more finickity about spaces etc in the
    CPPFLAGS and LDFLAGS values below
      

            $ cd wget2
            $ ./bootstrap 
            ...much ado about gnulib...
            $ export CPPFLAGS="-I $HOME/code/openssl/include" 
            $ export LDFLAGS="-L$HOME/code/openssl/" 
            $ ./configure --with-openssl=yes --with-cares
            

    And that works.

Ahh - seems gnutls is the only option for TLS so far - OpenSSL can still be
used for librcrypto it seems but maybe nothing more, that appears to be
[in-work](https://gitlab.com/gnuwget/wget2/issues/401) but so far not done, so
that'll be all for wget2 for now.

## Coding 

All new ESNI code will be protected via ``#ifndef OPENSSL_NO_ESNI`` as
done within the OpenSSL library. 

## Command line arguments, and behaviour

Most of this will be modelled on what we did for ``openssl s_client`` with
the difference that ``wget`` has the ``c-ares`` DNS libarary so can try
fetch ESNIKeys values internally.

Our model here is that if ESNI is available, we'll use it. However, given
that we may need to specify a specific cover hostname might be needed, 
and that ESNI will be initially rare, we'll add a command line argument
``--esni`` that can take an optional covername. 

## Status (== quiescent:-)

Since I was seeing problems with OpenSSL compatibility, I've parked this
for the moment and will try see how things look with [curl](curl.md) for
a bit...

