The Red October encryption model
==========================

Red October is a system for encrypting and decrypting data using the
two-person rule [1]_. It is intended for securing data where the
requirement that multiple individuals agree to decrypt the data.

Users have a public keypair generated for them (either RSA or elliptic
curve); users never have access to this key directly. Instead, their
key is protected using a passphrase supplied to scrypt.

The server encrypts data by using these public keys and an access
policy: the server generates a random symmetric key, and uses the
access control policy (either two-person or MSP [2_]) to encrypt the
key appropriately. The encryptor can add additional information,
called labels, that must also be supplied for the decryption to
succeed.

A user is said to "delegate" [3]_ their key to the server in order to
decrypt data, in which case they supply their password to the
server. The server then decrypts their private key; when a decryption
is requested later, if this decrypted key is still valid (delegations
can expire or otherwise be invalidated based on certain constraints),
the server can use this to perform a decryption.


Notes:
-----

.. [1] https://en.wikipedia.org/wiki/Two-man_rule

.. [2] MSP is a monotone span program; they are introduced in the paper
       http://www.math.ias.edu/~avi/PUBLICATIONS/MYPAPERS/KW93/proc.pdf.
       The high-level overview is that it permits more complex access
       policies such as Alice and (Bob or Carol): Alice is always needed
       for decryption, and one of Bob or Carol is needed to decrypt.

.. [3] Delegations are covered more in-depth in the "delegation.txt"
       file.
