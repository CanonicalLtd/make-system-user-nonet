# make-system-user-nonet

keys dir
-------

This directory should contain the contents of a gpg dir, for example ~/.snap/gnupg/*

This gpg dir must contain a snapcraft registered key.

When built, the keys are included in the snap.

WARNING: Do not add and commit the files. Doing so compromises the security of the keys. 

NOTE: keys/ are copied to ~/snap/

canned dir
----------

This directory must contain a single file named signed-asserts that consists of two signed assertions concatentated (with an empty line between them):

* The signed account assertion for the account that will sign the system-user assertion

* The signed account-key assertion for the key registered to that account that will
  sign the system-user assertinos

These assertions MUST be for the account/account-key associated with the key in keys/ dir.

When built, this file is included in the snap.

WARNING: Do not add and commit the file.

You can run the get-signed-asserts.py script to generate this signed-asserts file, for example:

    $ ./get-signed-asserts.py -k mykey 
    Done: signed-asserts created.

Build and run
------------

Build: snapcraft 

Install: sudo snapcraft install THESNAP --classic --dangerous

NOTE: run with sudo

Run:  sudo make-system-user-nonet.run


