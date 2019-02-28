
# Integrating wget

I'm starting to play with integrating this openssl build into wget.
I've not yet added any new stuff to wget, just building for now.

- wget can be built with openssl, even though gnutls is the default
- wget has some concept of using c-ares for DNS lookups, which we'll
  need to get ESNIKeys value(s)

## Preliminaries

- clone wget:

            $ cd $HOME/code
            $ git clone https://git.savannah.gnu.org/git/wget.git

- install c-ares 

            $ sudo apt install libc-ares-dev

- get ready... and... build:

            $ cd $HOME/code/wget
            $ ./bootstrap
            $ export CPPFLAGS='-I $HOME/code/openssl/include' 
            $ export LDFLAGS='-I $HOME/code/openssl/' 
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

    I added a ``#include <openssl/esni.h>`` to check if the build'll pick up
    my changes, and it does (now, after messing about with many variations 
    that weren't the above:-).

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


