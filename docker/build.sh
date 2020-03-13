#!/bin/sh

set -o errexit

for dir in "$@"
do
    docker build $dir --tag=pstack-$dir
    docker run -v $PWD/..:/src pstack-$dir
done
