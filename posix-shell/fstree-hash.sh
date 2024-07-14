#!/bin/sh
set -uf  # Error on expanding unset parameters (e.g. variables) by "-u" and do not expand paths (noglob) by "-f";
         # may carefully consider -e (exit on errors); -C (noclobber) is superfluous
export POSIXLY_CORRECT=1  # Enhances portability (at the expense of special functionality which is not wanted here)

# List of supported hash algorithms, identifiers must correspond to a subset of those digest commands from
# "openssl list --digest-commands" which shared the option values of "openssl dgst -list".
# List positions are fixed (because used as an index) and initially roughly set corresponding to their date of release and
# hash length; consequently new algorithms must be appended to the extant list.
openssl_list="md5 sha1 sha224 sha256 sha384 sha512 sha512-224 sha512-256 sm3 blake2s256 blake2b512 shake128 shake256 sha3-224 sha3-256 sha3-384 sha3-512"
# Index:      1   2    3      4      5      6      7          8          9   10         11         12       13       14       15       16       17
# openssl list --digest-commands  | tr '\n' ' ' | tr -s ' '
# openssl dgst -list | cut -s -d '-' -f 2- | sed 's/ -//g' | tr '\n' ' ' | tr -s ' '

xsum_list="md5sum -b,sha1sum -b,sha224sum -b,sha256sum -b,sha384sum -b,sha512sum -b,no,no,no,no,no,no,no,no,no,no,no"
# Index:   1         2          3            4            5            6            7  8  9  10 11 12 13 14 15 16 17

shasum_list="no,shasum -b -a 1,shasum -b -a 224,shasum -b -a 256,shasum -b -a 384,shasum -b -a 512,shasum -b -a 512224,shasum -b -a 512256,no,no,no,no,no,no,no,no,no"
# Index:     1  2              3                4                5                6                7                   8                   9  10 11 12 13 14 15 16 17

tag_list="MD5 SHA1 SHA224 SHA256 SHA384 SHA512 SHA512/224 SHA512/256 SM3 BLAKE2s256 BLAKE2b512 SHAKE128 SHAKE256 SHA3-224 SHA3-256 SHA3-384 SHA3-512"
# Index:  1   2    3      4      5      6      7          8          9   10         11         12       13       14       15       16       17

txt_list="MD5 SHA-1 SHA-224 SHA-256 SHA-384 SHA-512 SHA-512/224 SHA-512/256 SM3 BLAKE2s256 BLAKE2b512 SHAKE128/128 SHAKE256/256 SHA3-224 SHA3-256 SHA3-384 SHA3-512"
# Index:  1   2     3       4       5       6       7           8           9   10         11         12           13           14       15       16       17

status_list="broken broken ok ok ok ok ok ok ok ok ok ok ok ok ok ok ok"
# Index:     1      2      3  4  5  6  7  8  9  10 11 12 13 14 15 16 17

cmd_list="openssl xsum shasum"  # Preferred order of commands to use.
                                # "xsum" means from GNU-coreutils, see https://github.com/coreutils/coreutils/blob/master/src/digest.c
                                # "shasum" addresses the Perl program.

# Default values
index=4  # Default is SHA-256, if no hash algorithm is set by option "-a" or "--alg(orithm)".
fstree_root=''  # An absolute or relative path to a directory, e.g. ".".
verbose=no
xargs_size=2000000  # Minimum value is 4096, see "xargs --show-limits".
postamble=no
tagged=no
input_nterm=no
output_nterm=no
input_stdin=no
# output_format=hex  # Other values may be "bin"
# read_mode=binary  # Other values may be "text" and "universal"

# Binary or text mode simply determines if the fopen call to the C-library is performed with the "b" flag for binary or not,
# see e.g. http://www.mrx.net/c/openmodes.html , https://unix.stackexchange.com/questions/127959/md5sum-command-binary-and-text-mode/127961#127961
# , https://www.quora.com/In-C-programming-what-happens-if-we-open-files-in-binary-mode-with-rb-option-but-the-files-were-not-binary
# or https://learn.microsoft.com/en-us/cpp/c-runtime-library/unicode-stream-i-o-in-text-and-binary-modes?view=msvc-170
# I.e. text files might be transformed while reading them in text mode into a UNIX-like format; thus on Unix systems text
# mode is a noop and hence equivalent to binary mode.
# In case of shasum's "universal mode" solely a CR/LF to LF conversion is performed when reading text files.
# Because fstree-hash's primary purpose is hashing SCM file-trees and the hashing command is fed by a pipeline, binary mode
# is the only mode used (in order to hash "as is", i.e. without any conversions).

if [ $# = 0 ]
then input_stdin=yes
fi

while [ $# -gt 0 ]
do
  case "$1" in
  -z|--zero)  # NULL-terminate output, instead of newline
    output_nterm=yes
    shift
    ;;
  -v|--verbose)
    verbose=yes
    shift
    ;;
  -t|--text)
    read_mode=text
    shift
    ;;
  --tag|--tagged)
    tagged=yes
    shift
    ;;
  -s*|--size*)
    x_size="${1#-?*=}"
    if [ "$x_size" = "$1" ]
    then
      x_size="$2"
      shift
    fi
    shift
    if [ "0$x_size" -eq "$x_size" ] 2>/dev/null
    then xargs_size="$x_size"
    else
      echo "Error: Size parameter $x_size is not a numeric value!"
      exit 3
    fi
    ;;
  -p|--postamble)  # XYZsum style output with "+" for binary mode, "_" for text mode and "u" for "universal mode"
    postamble=yes
    shift
    ;;
  -0|-n|--null)  # Input is NULL-terminated, instead of newline
    input_nterm=yes
    shift
    ;;
  -b|--binary)
    read_mode=binary
    shift
    ;;
  -a*|--alg*)
    hash_param="${1#-?*=}"
    if [ "$hash_param" = "$1" ]
    then
      hash_param="$2"
      shift
    fi
    shift
    # Second option parameter specifies a hash algorithm.
    # Its default is SHA2-256, which is the only valid hash algorithm according to BSI TR-03183-2.
    case "$hash_param" in
    md5|MD5)
      index=1
      ;;
    sha1|sha-1|SHA1|SHA-1)
      index=2
      ;;
    sha224|sha-224|sha2-224|SHA224|SHA-224|SHA2-224)
      index=3
      ;;
    sha256|sha-256|sha2-256|SHA256|SHA-256|SHA2-256)
      index=4
      ;;
    sha384|sha-384|sha2-384|SHA384|SHA-384|SHA2-384)
      index=5
      ;;
    sha512|sha-512|sha2-512|SHA512|SHA-512|SHA2-512)
      index=6
      ;;
    sha512?224|sha-512?224|sha2-512?224|SHA512?224|SHA-512?224|SHA2-512?224)
      index=7
      ;;
    sha512?256|sha-512?256|sha2-512?256|SHA512?256|SHA-512?256|SHA2-512?256)
      index=8
      ;;
    b2s|B2s|blake2s|BLAKE2s|Blake2s|b2s256|B2s256|blake2s256|BLAKE2s256|Blake2s256)
      index=10
      ;;
    b2|b2b|B2|B2b|blake2|blake2b|BLAKE2|BLAKE2b|Blake2|Blake2b|b2b512|B2b512|blake2b512|BLAKE2b512|Blake2b512)
      index=10
      ;;
    esac
    *)
      if [ $# = 1 ]  # Last positional parameter
      then
        if [ "$1" = "-" ]  # Explicitly read from STDin
        then
          input_stdin=yes
          shift
        elif [ -d "$1" ]  # Is a directory?
        then
          fstree_root="$1"
          shift
        else 
          echo "Error: Last parameter $1 is no valid option or directory path!" 2>
          exit 3
        fi
      else
        echo "Error: Parameter $1 is no valid option!" 2>
        exit 3
      fi
      ;;
    esac
done

if [ -z "$fstree_root" ]
then input_stdin=yes
fi

-----------------------------------------------------------------

  echo "Warning: Mind that $hash_text is cryptographically broken and hence dangerous and discouraged." 2>

# The only non-option, hence last parameter must be a valid path as the root of the tree to be hashed
if ! [ -e "$1" ]
then exit 1
fi

if ! set -o pipefail
then
  printf '%s\n' "Warning: Technically unable to abort, if one of the following, preparatory steps for the upgrade proper fails." | tee -a "$logfile" >&2
  printf '\n' | tee -a "$logfile" >&2
fi
