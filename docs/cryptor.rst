The Cryptor package
===================

or, How RO actually encrypts and decrypts
-----------------------------------------

The Cryptor uses the ``EncryptedData`` structure for ciphertexts, the
``passvault`` for user records. The ``keycache`` package provides a
cache for actively-delegated keys.

See also: passvault.txt

Encryption:

	1. Create a new EncryptedData structure.
	   - The version is set to the default version compiled into
             Red October.
	   - The vault ID recorded in the EncryptedData is checked
             against the vault's ID. This is a sanity check to help
             catch the case where data was encrypted to a different
             vault. This is not a security mechanism, it's to help
	     users in multi-redoctober instances.
	   - Generate a random AES CBC IV.
	   - Generate a random AES key.
	2. The AES encryption key is wrapped to the appropriate users
           based on the access structure provided. This results in a
	   number of keys wrapped to users.
	3. The plaintext is encrypted with AES-CBC (no HMAC is applied
           yet).
	4. Any labels provided are added to the structure.
	5. An HMAC-SHA1 is computed over the following:
	   1. The string version of the vault version,
	   2. the string version of the vault ID,
	   3. the sorted wrapped keys (writing the user name and key),
	   4. the IV,
	   5. the encrypted data, and
	   6. the sorted labels.
	6. This HMAC is stored in the ``Signature`` field of the
           ``EncryptedData`` structure.
	7. The structure is "locked" with the HMAC key:
	   1. The structure is serialised to JSON.
	   2. An HMAC is computed over the serialised JSON.
	   3. The structure is replaced with another ``EncryptedData`` structure:
	      + Version ← -1
	      + Data ← serialised JSON
	      + Signature ← the HMAC

