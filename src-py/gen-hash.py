#!/usr/bin/python3

import sys
import crypt

def main (argv=None):
    print(crypt.crypt(argv[1], crypt.mksalt(crypt.METHOD_SHA512)))
    return

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Error: arg 1 must be the password to hash. Stopping")
        sys.exit(1)
         
    sys.exit(main(sys.argv))

#echo $1
#python3 -c $1 'import crypt; import sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA512)))'                                                   
