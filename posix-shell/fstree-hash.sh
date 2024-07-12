#!/bin/sh

# First parameter must be a valid path as the root of the tree to be hashed
if ! [ -e "$1" ]
then exit 1
fi
# Second, optional parameter may specify a hash algorithm.
# Its default is SHA2-256, which is the only valid hash algorithm according to BSI TR-03183-2.
case "$2" in
sha256|sha-256|sha2-256|"")
  hash-alg=sha256
  ;;
*)
  exit 2
  ;;
esac
