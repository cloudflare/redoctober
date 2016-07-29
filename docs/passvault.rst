The Red October PassVault
=========================

Package: passvault

See also: model.txt

The PassVault structure stores the user records [1]_ for the vault, as
well as the version of vault structure, the vault's ID [2]_, and an
HMAC key.

User records store the user's encryption key, the Scrypt hash and salt
for the user's password, and some metadata about the user. The
metadata is currently only used to store the user's HipChat name; in
the future, it could be used to support multiple notification
backends. They also provide support for returning the user's
encryption key and password validation.

The vault structure is responsible for the management of user records,
such as changing passwords and adding records.

.. [1] In the ``passvault`` package, these records are called
       `PasswordRecords <https://godoc.org/github.com/cloudflare/redoctober/passvault#PasswordRecord>`_.

.. [2] The vault ID is a randomly (using the OS cryptographic RNG)
       generated 32-bit signed integer that is used to identify the
       vault. This is used when decrypting as a sanity check to make
       sure that the ciphertext was encrypted using this vault.


