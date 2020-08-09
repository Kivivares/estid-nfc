# EstID NFC
A Python 3 example of performing PACE with the Estonian ID card and reading the personal data file on the card.
This example works for the latest generation Estonian ID cards and digital identity cards released after December 2018.

As an example, the reading of personal data file with and without secure messaging have been implemented.
Although secure messaging is required for contactless mode, it can still be used in contact mode with a standard reader.

## Required packages
- pyscard - smartcard IO
- pycryptodome - for cryptographic functions
- ecdsa - ECC
