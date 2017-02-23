#!/usr/bin/python3

"""
Copyright (C) 2017 Canonical Ltd

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
* Authored by:
 Kyle Nitzsche <kyle.nitzsche@canonical.com>
"""

import sys
import argparse
import subprocess
import crypt
import json
import time
from datetime import datetime, timedelta
import json
from snapcraft import storeapi

#TODO: arg help i18n'd

def parseargs(argv=None):
    parser = argparse.ArgumentParser(
        prog=argv[0],
        description=('Create a "signed-asserts" file for the provided key. You must first snapcraft login to the account to which the key is registered.'),
        )
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    required = parser.add_argument_group('Required arguments')
    required.add_argument('-k', '--key', required=True,
        help=('The name of the snapcraft key to use to sign the system user assertion. The key must exist locally and be reported by "snapcraft keys". The key must also be registered.')
        )
    args = parser.parse_args()
    return args

def ssoAccount():
    try:
        store = storeapi.StoreClient()
        return store.get_account_information()
    except:
        print("Error: You do not appear to be logged in. Try 'snapcraft login'")
        return False

def key_fingerprint(key, account):    
    # ensure store reports key
    if len(account['account_keys']) > 0:
        for k in account['account_keys']:
            if k['name'] == key:
                return k['public-key-sha3-384']
    print("Error: key '{}' is not reported by the store as one of your registered and local keys. Please use snapcraft create-key KEY' or 'snapcraft register-key KEY' and 'snapcraft keys' as needed".format(key))
    return False

def accountAssert(id):
    cmd = ['snap', 'known', '--remote', 'account', 'account-id={}'.format(id)]
    res = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    signed = str(res,'utf-8')
    if "type: account\n" not in signed:
        print("Error: problems getting assertion for this account")
        return False 
    return(signed)

def accountKeyAssert(id):
    cmd = ['snap', 'known', '--remote', 'account-key', 'public-key-sha3-384={}'.format(id)]
    res = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    signed = str(res,'utf-8')
    if "type: account-key\n" not in signed:
        print("Error: problems getting assertion for this account-key")
        return False
    return(signed)

def isLocalKey(key):
    cmd = ['snap', 'keys']
    res = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    lines = str(res,'utf-8').split('\n')
    for line in lines:
        if key in line:
            return True
    print("Error: key '{}' is not a local key. Please use snapcraft create-key' and then 'snapcraft register-key'".format(key))
    return False

def main(argv=None):
    PROGRAM = argv[0]
    args = parseargs(argv)
    # quit if not snapcraft logged in
    account = ssoAccount()
    if not account:
        sys.exit(1)
    # quit if key is not registered
    selfSignKey = key_fingerprint(args.key, account)
    if not selfSignKey:
        sys.exit(1)
    # quit if key does is not local
    if not isLocalKey(args.key):
        sys.exit(1)

    if args.verbose:
        print("==== Args and related:")
        print("Account-Id: ", json.dumps(account, sort_keys=True, indent=4))
        print("Key: ", args.key)
        print("Key Fingerprint: ", selfSignKey)
        print("")

    accountSigned = accountAssert(account['account_id']) 
    if args.verbose:
        print("==== Account signed:")
        print(accountSigned)

    accountKeySigned = accountKeyAssert(selfSignKey) 
    if args.verbose:
        print("==== Account Key signed:")
        print(accountKeySigned)
    
    signed = accountSigned + "\n" + accountKeySigned

    filename = "signed-asserts"
    try:
        with open(filename, 'w') as out:
            out.write(signed)
        print("Done: {} created.".format(filename))
    except Exception as e:
        print("Error: Cannot create {}. {}.".format(filename, e))

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
