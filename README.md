# Crypto C library 

[![Build Status](https://travis-ci.org/thiagoh/crypto-c.svg)](https://travis-ci.org/thiagoh/crypto-c)

This library is intented to encrypt and decrypt data

## Usage

```
unsigned char* iv = "0123456789123456"; //128 bits
unsigned char* key = "01234567891234567890123456789012"; // 256 bits

const char* plaintext = "the fox jumped over the lazy dog";

The default cipher mode is CBC and algorithm is 3DES_EDE 

cryptoc_data ciphertext = cryptoc_encrypt_iv(plaintext, strlen(plaintext), key, iv, &len);

if (ciphertext.error) {
  // do something on error
  printf("%s", ciphertext.errorMessage);
}

cryptoc_data newplaintext = cryptoc_decrypt_iv(ciphertext, strlen(ciphertext), key, iv, &newlen);

if (newplaintext.error) {
  // do something on error
  printf("%s", newplaintext.errorMessage);
}

// if there are no errors...

ciphertext.first; // data encrypted
ciphertext.second; // length

newplaintext.first; // data unencrypted
newplaintext.second; // length

```

## build process

```
./build.sh

mkdir build
cd build
rm -rf ./* 
cmake --debug-output .. 
make -j 4
``` 


