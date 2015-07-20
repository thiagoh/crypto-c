/*
 * Crypto.h
 *
 *  Created on: Jul 2, 2015
 *      Author: thiagoh
 */

#ifndef SRC_CRYPTO_H_
#define SRC_CRYPTO_H_

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>

typedef enum { false = 0, true = 1} bool;

typedef struct {
	unsigned char* data;
	int length;
	bool error;
	const char* errorMessage;
} crypto_data;

typedef enum {
	ECB_MODE, CBC_MODE, CFB_MODE, OFB_MODE, STREAM_CIPHER
} crypto_mode_type;

typedef enum {
	CRYPTO_ENC_NULL,
//	Null cipher: does nothing.

#ifndef OPENSSL_NO_AES

	CRYPTO_AES_128_CBC, CRYPTO_AES_128_ECB, CRYPTO_AES_128_CFB, CRYPTO_AES_128_OFB,
//	AES with a 128-bit key in CBC, ECB, CFB and OFB modes respectively.

	CRYPTO_AES_192_CBC, CRYPTO_AES_192_ECB, CRYPTO_AES_192_CFB, CRYPTO_AES_192_OFB,
//	AES with a 192-bit key in CBC, ECB, CFB and OFB modes respectively.

	CRYPTO_AES_256_CBC, CRYPTO_AES_256_ECB, CRYPTO_AES_256_CFB, CRYPTO_AES_256_OFB,
//	AES with a 256-bit key in CBC, ECB, CFB and OFB modes respectively.

#endif

	CRYPTO_DES_CBC, CRYPTO_DES_ECB, CRYPTO_DES_CFB, CRYPTO_DES_OFB,
//	DES in CBC, ECB, CFB and OFB modes respectively.

	CRYPTO_DES_EDE_CBC, CRYPTO_DES_EDE, CRYPTO_DES_EDE_OFB, CRYPTO_DES_EDE_CFB,
//	Two key triple DES in CBC, ECB, CFB and OFB modes respectively.

	CRYPTO_DES_EDE3_CBC, CRYPTO_DES_EDE3, CRYPTO_DES_EDE3_OFB, CRYPTO_DES_EDE3_CFB,
//	Three key triple DES in CBC, ECB, CFB and OFB modes respectively.

	CRYPTO_DESX_CBC,
//	DESX algorithm in CBC mode.

	CRYPTO_RC4,
//	RC4 stream cipher. This is a variable key length cipher with default key length 128 bits.

	CRYPTO_RC4_40,
//	RC4 stream cipher with 40 bit key length. This is obsolete and new code should use EVP_rc4() and the EVP_CIPHER_CTX_set_key_length() function.

#ifndef OPENSSL_NO_IDEA

	CRYPTO_IDEA_CBC, CRYPTO_IDEA_ECB, CRYPTO_IDEA_CFB, CRYPTO_IDEA_OFB,
//	IDEA encryption algorithm in CBC, ECB, CFB and OFB modes respectively.

#endif

	CRYPTO_RC2_CBC, CRYPTO_RC2_ECB, CRYPTO_RC2_CFB, CRYPTO_RC2_OFB,
//	RC2 encryption algorithm in CBC, ECB, CFB and OFB modes respectively. This is a variable key length cipher with an additional parameter called "effective key bits" or "effective key length". By default both are set to 128 bits.

	CRYPTO_RC2_40_CBC, CRYPTO_RC2_64_CBC,
//	EVP_CIPHER_CTX_set_key_length() and EVP_CIPHER_CTX_ctrl() to set the key length and effective key length.

	CRYPTO_BF_CBC, CRYPTO_BF_ECB, CRYPTO_BF_CFB, CRYPTO_BF_OFB,
//	Blowfish encryption algorithm in CBC, ECB, CFB and OFB modes respectively. This is a variable key length cipher.

#ifndef OPENSSL_NO_CAST

	CRYPTO_CAST5_CBC, CRYPTO_CAST5_ECB, CRYPTO_CAST5_CFB, CRYPTO_CAST5_OFB,
//	CAST encryption algorithm in CBC, ECB, CFB and OFB modes respectively. This is a variable key length cipher.

#endif

#ifndef OPENSSL_NO_RC5

	CRYPTO_RC5_32_12_16_CBC, CRYPTO_RC5_32_12_16_ECB, CRYPTO_RC5_32_12_16_CFB, CRYPTO_RC5_32_12_16_OFB,
//	RC5 encryption algorithm in CBC, ECB, CFB and OFB modes respectively. This is a variable key length cipher with an additional "number of rounds" parameter. By default the key length is set to 128 bits and 12 rounds.

#endif

#ifndef OPENSSL_NO_AES

	CRYPTO_AES_128_GCM, CRYPTO_AES_192_GCM, CRYPTO_AES_256_GCM,
//	AES Galois Counter Mode (GCM) for 128, 192 and 256 bit keys respectively. These ciphers require additional control operations to function correctly: see the "GCM and OCB modes" section below for details.

	CRYPTO_AES_128_CCM, CRYPTO_AES_192_CCM, CRYPTO_AES_256_CCM,
//	AES Counter with CBC-MAC Mode (CCM) for 128, 192 and 256 bit keys respectively. These ciphers require additional control operations to function correctly: see CCM mode section below for details.

#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
	CRYPTO_AES_128_CBC_HMAC_SHA1,

	CRYPTO_AES_256_CBC_HMAC_SHA1
#endif

#endif

} crypto_cipher_type;

crypto_data crypto_encrypt(crypto_cipher_type type, unsigned char *key, unsigned char* iv, unsigned char* plaintext, int plaintextLength);
crypto_data crypto_decrypt(crypto_cipher_type type, unsigned char *key, unsigned char* iv, unsigned char* ciphertext, int ciphertextLength);

#endif /* SRC_CRYPTO_H_ */
