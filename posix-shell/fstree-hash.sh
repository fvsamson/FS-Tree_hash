#!/bin/sh
set -uf  # Error on expanding unset parameters (e.g. variables) by "-u" and do not expand paths (noglob) by "-f";
         # may carefully consider -e (exit on errors); -C (noclobber) is superfluous
export POSIXLY_CORRECT=1  # Enhances portability of some GNU utilities (at the expense of special functionality not wanted here)

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

status_list="broken broken ok ok ok ok ok ok ok ok ok ok ok ok ok ok ok"  # Valid values are "ok", "weak" and "broken".
# Index:     1      2      3  4  5  6  7  8  9  10 11 12 13 14 15 16 17

cmd_list="openssl xsum shasum"  # Preferred order of commands to use.
                                # "xsum" means from GNU-coreutils, see https://github.com/coreutils/coreutils/blob/master/src/digest.c
                                # "shasum" addresses the Perl program.

# Default values
index=4  # Default is SHA-256, if no hash algorithm is set by option "-a" or "--alg(orithm)".
fstree_root=''  # An absolute or relative path to a directory, e.g. ".", or from STDin.
xdev=no  # Do NOT cross over to other devices.
verbose=no
xargs_size=2000000  # Minimum value is 4096, see "xargs --show-limits" and https://www.in-ulm.de/~mascheck/various/argmax/
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
# is the only mode used (in order to hash "as is", i.e. without any conversions).  Furthermore, OpenSSL only supports binary mode.

if [ $# = 0 ]  # As the only non-option, the last parameter may be one or more valid paths as the root of the tree(s) to be hashed, "-" for reading these paths from STDin or not existing to achieve the same.
then input_stdin=yes
fi

# ToDo: Start using POSIX getopts
while [ $# -gt 0 ]  # Among other thigs, this avoids the ${1+"$@"} issue, see https://www.in-ulm.de/~mascheck/various/bourne_args/
do
  case "$1" in
  -z|--zero)  # NULL-terminate output, instead of newline
    output_nterm=yes
    shift
    ;;
  -x|--xdev)  # Cross over to other devices: Disables find option -xdev, which is applied by default
    xdev=yes
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
    # Its default is SHA-256, which is the only valid hash algorithm according to BSI TR-03183-2.
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
    sm3|SM3)
      index=9
      ;;
    b2s|B2s|blake2s|BLAKE2s|Blake2s|b2s256|B2s256|blake2s256|BLAKE2s256|Blake2s256)
      index=10
      ;;
    b2|b2b|B2|B2b|blake2|blake2b|BLAKE2|BLAKE2b|Blake2|Blake2b|b2b512|B2b512|blake2b512|BLAKE2b512|Blake2b512)
      index=11
      ;;
    *)
      echo "Error: $hash_param is not a valid hash algorithm identifier!" 2>
      exit 3
    esac
  -?|--*)
    echo "Error: Parameter $1 is not a valid option!" 2>
    exit 3
    ;;    
  *)  # First non-option encountered
    # number_non-opts=$# ; break  # Jump out of loop to process the non-option arguments
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
        echo "Error: Last parameter $1 is neither a path to a directory nor \"-\" to explicitly read from STDin!" 2>
        exit 3
      fi
    else
      echo "Error: Parameter $1 does not adhere to the short option format \"-?\" or the long option format \"--*\"!" 2>
      exit 3
    fi
    ;;
  esac
done

if [ -z "$fstree_root" ]
then input_stdin=yes
fi

-----------------------------------------------------------------

find -L . -type f -exec printf '%s\0' '{}' \;
is the POSIX equivalent to the GNU-find command line
find -P . -xtype f -print0

-xdev  Don't descend directories on other filesystems.  (Posix)

-noleaf       Do not optimize by assuming that directories contain 2 fewer subdirectories than their hard link count.  This  op‐
              tion is needed when searching filesystems that do not follow the Unix directory-link convention, such as CD-ROM or
              MS-DOS filesystems  (GNU find)

export LC_COLLATE=POSIX; find -P . -xtype f -print0 | sort -z | xargs -x -0 cat | sha256sum -b | cut -f 1 -d ' '

Trying with POSIX only options:
# Globbing must be on for the ls based variants by set +f or set +o noglob
find -L . -maxdepth 1 -type f -name "ab*" -exec ls -q '{}' \; | sort -u | sed -e 's/[^[:alnum:]+-./?_~]/\\\\&/g' -e "s/[\"$']/\\\\&/g" | xargs -E '' -I {} sh -c "cat {}"  # Works!
find -L . -maxdepth 1 -type f -name "ab*" -exec ls -q '{}' \; | sort -u | sed -e "s/[\"']/\\\\&/g" -e "s/?/\\'?\\'/g" | xargs -E '' -I {} cat {}  # Fail to let ? be quoted
find -L . -maxdepth 1 -type f -name "ab*" -exec ls -1q '{}' + | sort -u | sed -e 's/[^[:alnum:]+-./?_~]/\\\\&/g' -e "s/[\"$']/\\\\&/g" | xargs -E '' -I {} sh -c "cat {}"  # Works, supposedly faster

The "proper" way I fail to let the formatting characters become interpreted, but exactly that works with the ls based variants above?!?
find -L . -maxdepth 1 -type f -name "ab*" -exec printf '%s\0' '{}' \; | sed ':a;N;$!ba;s/\n/\\n/g' | tr '\0' '\n' | sort | sed -n l | sed -e 's/\([^\]\)\\\\n/\1\\n/g' -e 's/\$$//g' -e 's/[^[:alnum:]+-./?_~]/\\&/g' -e 's/["$]/\\\\&/g' -e 's/%/%%/g' | xargs -E '' -I {} sh -c "cat \"$(printf {})\""
find -L . -maxdepth 1 -type f -name "ab*" -exec printf '%s\0' '{}' \; | sed ':a;N;$!ba;s/\n/\\n/g' | tr '\0' '\n' | sort | sed -n l | sed -e 's/\([^\]\)\\\\n/\1\\n/g' -e 's/\$$//g' -e 's/[^[:alnum:]+-./?_~]/\\&/g' -e 's/%/%%/g' | xargs -E '' -I {} cat "$(printf {})"

Next, definitely better try.  Note that is it should be resaerched if the term `-e "s/[[:cntrl:]]/''&''/g"` shall better be omitted.
find -L . -maxdepth 1 -type f -name "ab*" -exec printf '%s\0' '{}' \; | tr '\0\n' '\n\0' | sort | tr '\0\n' '\n\0' | sed -e "s/'/'\\\''/g" | sed -e ':a;N;$!ba;s/\n/'\''$'\''\\n'\'''\''/g' | tr '\0\n' '\n\0' | sed -e "s/^/'/g" -e "s/$/'/g" -e 's/\a/'\''$'\''\\a'\'''\''/g' -e 's/\f/'\''$'\''\\f'\'''\''/g' -e 's/\r/'\''$'\''\\r'\'''\''/g' -e 's/\t/'\''$'\''\\t'\'''\''/g' -e 's/\v/'\''$'\''\\v'\'''\''/g' -e "s/[[:cntrl:]]/''&''/g"  # Output like GNU "ls -1q" @tty without xargs
find -L . -maxdepth 1 -type f -name "ab*" -exec printf '%s\0' '{}' \; | tr '\0\n' '\n\0' | sort | tr '\0\n' '\n\0' | sed -e "s/'/'\\\''/g" | sed -e ':a;N;$!ba;s/\n/'\''$'\''\\n'\'''\''/g' | tr '\0\n' '\n\0' | sed -e "s/^/'/g" -e "s/$/'/g" -e 's/\a/'\''$'\''\\a'\'''\''/g' -e 's/\f/'\''$'\''\\f'\'''\''/g' -e 's/\r/'\''$'\''\\r'\'''\''/g' -e 's/\t/'\''$'\''\\t'\'''\''/g' -e 's/\v/'\''$'\''\\v'\'''\''/g' -e "s/[[:cntrl:]]/''&''/g" | sed -e 's/[^[:alnum:]+-./?_~]/\\&/g' | xargs -E '' -I {} printf '%s\n' {}  # Output like GNU "ls -1q" @tty with xargs
find -L . -maxdepth 1 -type f -name "ab*" -exec printf '%s\0' '{}' \; | tr '\0\n' '\n\0' | sort | tr '\0\n' '\n\0' | sed -e "s/'/'\\\''/g" | sed -e ':a;N;$!ba;s/\n/'\''$'\''\\n'\'''\''/g' | tr '\0\n' '\n\0' | sed -e "s/^/'/g" -e "s/$/'/g" -e 's/\a/'\''$'\''\\a'\'''\''/g' -e 's/\f/'\''$'\''\\f'\'''\''/g' -e 's/\r/'\''$'\''\\r'\'''\''/g' -e 's/\t/'\''$'\''\\t'\'''\''/g' -e 's/\v/'\''$'\''\\v'\'''\''/g' -e "s/[[:cntrl:]]/''&''/g" | sed -e 's/[^[:alnum:]+-./?_~]/\\\\\\&/g' | xargs -E '' -I {} sh -c 'printf "%s\n" {}'  # Output like GNU "ls -1q" @tty with xargs in subshell

BUT overkill, because GNU "ls -1q" !@tty:
ls -1q ab* | cat  # !!!

Rest is tedious work: Let it be, because a better concept is known.

BTW, sed does handle NULL characters using this syntax:
echo -e "ab\ncd\nef" | tr '\n' '\0' | sed 's/\x0/\n/g'


  echo "Warning: Mind that $hash_text is cryptographically broken and hence dangerous and discouraged." 2>

if ! set -o posix  (bash etc.)

if ! set -o pipefail  (bash etc.)
then
  printf '%s\n' "Warning: Technically unable to abort, if one of the following, preparatory steps for the upgrade proper fails." | tee -a "$logfile" >&2
  printf '\n' | tee -a "$logfile" >&2
fi
