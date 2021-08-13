#!/bin/bash

set -x

#echo "Running $0 on $1"

if [[ $1 == *extensions* ]]
then
	cat $1 | sed -n '/ESNI_DOXY_START/,/ESNI_DOXY_END/p' 
elif [[ $1 == *s_client* ]]
then
	cat $1 | sed -n '/ESNI_DOXY_START/,/ESNI_DOXY_END/p' 
elif [[ $1 == *s_server* ]]
then
	cat $1 | sed -n '/ESNI_DOXY_START/,/ESNI_DOXY_END/p' 
else 
	cat $1
fi
