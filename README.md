# RubyVault (0.0.1)

An application that allows one to create an archive to which different files can be added by anyone holding a public key of the archive, while it can be extracted only with a private key.

## Features

* Uses RSA and AES-256 for encryption, similar to GPG.
* Archives have flat file structure, allowing up to 4096 entries.

## TODO

* All kinds of failure conditions (archive is full, archive structure is malformed, keys mismatch, etc).
* Tamper proofing, to ensure that files cannot be removed by anyone without compromising the whole archive.
* More flexible ways to add information about the archive (currently only "id" and "name" are supported options).

## Contributing

It's a hobby project, and is probably never going to be widely used. But if you're interested and your name is not Jia Tan, contributions are welcome - fork & create a pull request.
