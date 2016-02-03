# Crypto C library 

[![Build Status](https://travis-ci.org/thiagoh/crypto-c.svg)](https://travis-ci.org/thiagoh/crypto-c)
[![view on github](https://img.shields.io/node/v/crypto-c.svg)](https://github.com/thiagoh/crypto-c)

This library is intented to encrypt and decrypt data

## Usage

```
unsigned char* iv = "0123456789123456"; //128 bits
unsigned char* key = "01234567891234567890123456789012"; // 256 bits

int iv_length = 16;
int key_length = 32;

const char* plaintext = "the fox jumped over the lazy dog";

The default cipher mode is CBC and algorithm is 3DES_EDE 

// fix to use shared pointer 
cryptoc_data ciphertext = cryptoc_encrypt_iv(plaintext, strlen(plaintext), key, key_length, iv, iv_length, &len);

if (ciphertext.error) {
  // do something on error
  printf("%s", ciphertext.errorMessage);
}

// fix to use shared pointer 
cryptoc_data newplaintext = cryptoc_decrypt_iv(ciphertext, strlen(ciphertext), key, key_length, iv,  iv_length, &newlen);

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
``` 

## Valgrind tests

``` 
valgrind --tool=memcheck --leak-check=full --show-reachable=yes --track-origins=yes ./build/test/test_cryptoc
``` 
