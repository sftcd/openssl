
# Integrating curl

20190301

I'm starting to play with integrating this openssl build into curl.
I've not yet added any new stuff to curl, just building for now.

- curl can be built with openssl
- curl has some concept of using c-ares for DNS lookups, which we'll
  need to get ESNIKeys value(s)

Before this goes much further we should create a fork just for
our own version control. 

## curl Preliminaries

- clone curl:

            $ cd $HOME/code
            $ git clone https://github.com/curl/curl.git

- install c-ares (I did already for [wget](wget.md))

            $ sudo apt install libc-ares-dev

- get ready... and... build:

            $ cd $HOME/code/curl
            $ ./buildconf
            $  export LDFLAGS="-L$HOME/code/openssl"
            $ ./configure --with-ssl=$HOME/code/openssl --enable-ares
            $ make
            

    And that seems to work, I can at least run the resulting binary:

            $ export LD_LIBRARY_PATH=$HOME/code/openssl
            $ src/curl https://github.com/sftcd/openssl/blob/master/esnistuff/curl.md
            ... expected output, being this file:-) ...
