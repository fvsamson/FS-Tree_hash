#!/bin/sh
set -u  # Error on expanding unset parameters (e.g. variables); may carefully consider -e (exit on errors);
        # -f (noglob) would limit functionality, -C (noclobber) is superfluous
export POSIXLY_CORRECT=1  # Enhances portability (at the expense of special functionality which is not wanted here)

if [ $# = 0 ]
then
fi

hash_cmdln='sha256sum -b '  # The default, if no hash algorithm is set by option "-a" or "--alg(orithm)"
hash_text=SHA2-256
hash_broken=no

while [ $# -gt 1 ]
do
  

case "$1" in
  
-a*|--alg*)
  hash_param="$2"
  # Second option parameter specifies a hash algorithm.
  # Its default is SHA2-256, which is the only valid hash algorithm according to BSI TR-03183-2.
  case "$1" in
  sha224|sha-224|sha2-224|SHA224|SHA-224|SHA2-224)
    hash_cmdln='sha224sum -b '
    shift
    ;;
  sha256|sha-256|sha2-256|SHA256|SHA-256|SHA2-256)
    hash_cmdln='sha256sum -b '
    shift
    ;;
  sha384|sha-384|sha2-384|SHA384|SHA-384|SHA2-384)
    hash_cmdln='sha384sum -b '
    shift
    ;;
  sha512|sha-512|sha2-512|SHA512|SHA-512|SHA2-512)
    hash_cmdln='sha512sum -b '
    shift
    ;;
  blake2|b2|blake-2|BLAKE2|B2|BLAKE-2|)
    hash_cmdln='b2sum -b '
    shift
    ;;
  sha1|sha-1|SHA1|SHA-1)
    hash_broken=yes
    hash_cmdln='sha1sum -b '
    
    ;;
  md5|MD5)
    hash_broken=yes
    hash_cmdln='md5sum -b '
    
    ;;
  *)
    exit 2
    ;;
  esac
  echo "Mind that $hash_text is cryptographically broken and hence dangerous and discouraged." 2>
done

# The only non-option, hence last parameter must be a valid path as the root of the tree to be hashed
if ! [ -e "$1" ]
then exit 1
fi
