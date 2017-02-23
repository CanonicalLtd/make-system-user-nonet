# make-system-user-nonet


keys dir
-------

This directory should contain the contents of a gpg dir, for example ~/.snap/gnupg/*


When built, the keys are included in the snap.

WARNING: Do not add and commit the files. Doing so compromises the security of the keys. 

canned dir
----------


This directory must contain a single file named signed-asserts that consists of two signed assertions concatentated (with an empty line between them):

* The signed account assertion for the account that will sign the system-user assertion

* The signed account-key assertion for the key registered to that account that will
  sign the system-user assertinos

These assertions MUST be for the account/account-key associated with the key in keys/ dir.

When built, this file is included in the snap.

WARNING: Do not add and commit the file.


TODO
----

Add a script to create the concatenated signed assertions
