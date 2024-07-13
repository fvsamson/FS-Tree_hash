#!/bin/sh
set -u  # Error on expanding unset parameters (e.g. variables); may careully consider -e (exit on errors);
        # -f (noglob) would limit functionality, -C (noclobber) is superfluous

if [ $# = 0 ]
then
fi

hash-alg=sha256  # The default, if no hash algorithm is set by oprion "-a" or "--alg(orithm)"

while [ $# -gt 0 ]
do
  
# First parameter must be a valid path as the root of the tree to be hashed
if ! [ -e "$1" ]
then exit 1
fi

case "$1" in
-a|--alg*)
  shift
  # Second option parameter specifies a hash algorithm.
  # Its default is SHA2-256, which is the only valid hash algorithm according to BSI TR-03183-2.
  case "$1" in
  sha224|sha-224|sha2-224|SHA224|SHA-224|SHA2-224)
    hash-alg=sha224
    shift
    ;;
  sha256|sha-256|sha2-256|SHA256|SHA-256|SHA2-256|"")
    hash-alg=sha256
    shift
    ;;
  sha384|sha-384|sha2-384|SHA384|SHA-384|SHA2-384)
    hash-alg=sha384
    shift
    ;;
  sha512|sha-512|sha2-512|SHA512|SHA-512|SHA2-512)
    hash-alg=sha512
    shift
    ;;
  blake2|b2|blake-2|BLAKE2|B2|BLAKE-2|)
    hash-alg=b2
    shift
    ;;
  sha1|sha-1|SHA1|SHA-1|md5|MD5)
    echo "" 2>
    exit 3
    ;;
  *)
    exit 2
    ;;
  esac
