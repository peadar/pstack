#!/bin/sh

if [ "$DOCKER" = "" ]; then
   DOCKER=docker
fi
set -o errexit

for dir in "$@"
do
    $DOCKER build $dir --tag=pstack-$dir
    $DOCKER run -v $PWD/..:/src pstack-$dir
done
