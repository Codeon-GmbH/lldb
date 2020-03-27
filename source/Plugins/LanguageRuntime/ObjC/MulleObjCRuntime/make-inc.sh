#! /bin/sh
#
# (c) 2017 code by Nat!
#

usage()
{
   cat << EOF >&2
Usage: make-inc.sh [input] [output]
EOF
   exit 1
}


escape_quotes()
{
   sed 's/\"/\\\"/g'
}


remove_cxx_comments()
{
   sed -e 's/\(.*\)\/\/.*/\1/'
}


remove_empty_lines()
{
   sed -e '/^[[:space:]]*$/d'
}


make_strings()
{
   # also kill leading and trailing whitespace
   sed -e 's/[[:space:]]*\(.*\)[[:space:]]*/"\1\\n"/'
}


convert()
{
#   echo "extern \\\"C\\\"\\\n\""
#   echo "\"{\\\n\""

   remove_cxx_comments | remove_empty_lines | escape_quotes | make_strings

#   echo "\"}\\\n\""
}


# use c string concatenation
main()
{
   case $# in
      0)
         convert
      ;;

      1)
         cat "$1" | convert
      ;;

      2)
         cat "$1" | convert > "$2"
      ;;

      *)
         usage
      ;;
   esac
}

main "$@"
