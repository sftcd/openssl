#!/bin/bash 

# Extract the values added to the transcript from a 
# trace file (when ech_ptranscript() is compiled in)

if [[ "$1" == "" ]]
then
    echo "No trace file input provided"
    echo "Syntax: $0 <tracefile>"
    exit 1
fi

if [[ ! -f $1 ]]
then
    echo "tracefile $1 doesn't exist"
    exit 2
fi

sed -n "/Adding this to transcript/,/^ECH TRACE/p" $1
