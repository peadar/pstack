#!/bin/sh

set -o errexit

for i in */Dockerfile
do
    dir=`dirname $i`
    docker build $dir --tag=pstack-$dir
    docker run -v $PWD/..:/src pstack-$dir
done
