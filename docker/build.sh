#!/bin/sh

set -o errexit

for dir in full-32bit full-64bit min-32bit
do
    docker build $dir --tag=pstack-$dir
    docker run -v $PWD/..:/src pstack-$dir
done
