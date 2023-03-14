#!/bin/bash

set -x

# Run a lighttpd on localhost:3443 with foo.example.com accessible
# via ECH

# Note on testing - if you have our curl build locally, and foo.example.com
# is in your /etc/hosts, then:
#       $src/curl --echconfig AED+CgA8ogAgACCRR4BdUxMqi3p2QZxscc4yKK7SSEe6yvjD/XQcodPBLwAEAAEAAQAAAAtleGFtcGxlLmNvbQAA --cacert ../openssl/esnistuff/cadir/oe.csr https://foo.example.com:3443/index.html -v
#
# Replace the bas64 encoded stuff abouve with the right public key as
# needed.

OSSL="$HOME/code/openssl"
: ${LIGHTY:=$HOME/code/lighttpd1.4}
export TOP=$OSSL

export LD_LIBRARY_PATH=$OSSL

# make directories for lighttpd stuff if needed
mkdir -p $OSSL/esnistuff/lighttpd/logs
mkdir -p $OSSL/esnistuff/lighttpd/www
mkdir -p $OSSL/esnistuff/lighttpd/baz

# check for/make a home page for example.com and other virtual hosts
if [ ! -f $OSSL/esnistuff/lighttpd/www/index.html ]
then
    cat >$OSSL/esnistuff/lighttpd/www/index.html <<EOF

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

EOF
fi

# check for/make a slightly different home page for baz.example.com
if [ ! -f $OSSL/esnistuff/lighttpd/baz/index.html ]
then
    cat >$OSSL/esnistuff/lighttpd/baz/index.html <<EOF

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
<p>This is the pretty dumb top page for baz.example.com testing. </p>

</body>
</html>

EOF
fi

# set to run in foreground or as daemon -D => foreground
# unset =>daemon
FOREGROUND="-D "

# set to use valgrind, unset to not
VALGRIND="valgrind --leak-check=full --show-leak-kinds=all"
#VALGRIND="valgrind --leak-check=full --error-limit=1 --track-origins=yes"
# VALGRIND=""

echo "Executing: $VALGRIND $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpdmin.conf -m $LIGHTY/src/.libs"
$VALGRIND $LIGHTY/src/lighttpd $FOREGROUND -f $OSSL/esnistuff/lighttpdmin.conf -m $LIGHTY/src/.libs
