/*
 * Crypto.h
 *
 *  Created on: Jul 2, 2015
 *      Author: thiagoh
 */

#ifndef SRC_CRYPTOC_H_
#define SRC_CRYPTOC_H_

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
} cryptoc_data;

typedef enum {
	ECB_MODE, CBC_MODE, CFB_MODE, OFB_MODE, STREAM_CIPHER
} cryptoc_mode_type;

typedef enum {
	CRYPTOC_ENC_NULL,
//	Null cipher: does nothing.

#ifndef OPENSSL_NO_AES

	CRYPTOC_AES_128_CBC, CRYPTOC_AES_128_ECB, CRYPTOC_AES_128_CFB, CRYPTOC_AES_128_OFB,
//	AES with a 128-bit key in CBC, ECB, CFB and OFB modes respectively.

	CRYPTOC_AES_192_CBC, CRYPTOC_AES_192_ECB, CRYPTOC_AES_192_CFB, CRYPTOC_AES_192_OFB,
//	AES with a 192-bit key in CBC, ECB, CFB and OFB modes respectively.

	CRYPTOC_AES_256_CBC, CRYPTOC_AES_256_ECB, CRYPTOC_AES_256_CFB, CRYPTOC_AES_256_OFB,
//	AES with a 256-bit key in CBC, ECB, CFB and OFB modes respectively.

#endif

	CRYPTOC_DES_CBC, CRYPTOC_DES_ECB, CRYPTOC_DES_CFB, CRYPTOC_DES_OFB,
//	DES in CBC, ECB, CFB and OFB modes respectively.

	CRYPTOC_DES_EDE_CBC, CRYPTOC_DES_EDE, CRYPTOC_DES_EDE_OFB, CRYPTOC_DES_EDE_CFB,
//	Two key triple DES in CBC, ECB, CFB and OFB modes respectively.

	CRYPTOC_DES_EDE3_CBC, CRYPTOC_DES_EDE3, CRYPTOC_DES_EDE3_OFB, CRYPTOC_DES_EDE3_CFB,
//	Three key triple DES in CBC, ECB, CFB and OFB modes respectively.

	CRYPTOC_DESX_CBC,
//	DESX algorithm in CBC mode.

	CRYPTOC_RC4,
//	RC4 stream cipher. This is a variable key length cipher with default key length 128 bits.

	CRYPTOC_RC4_40,
//	RC4 stream cipher with 40 bit key length. This is obsolete and new code should use EVP_rc4() and the EVP_CIPHER_CTX_set_key_length() function.

#ifndef OPENSSL_NO_IDEA

	CRYPTOC_IDEA_CBC, CRYPTOC_IDEA_ECB, CRYPTOC_IDEA_CFB, CRYPTOC_IDEA_OFB,
//	IDEA encryption algorithm in CBC, ECB, CFB and OFB modes respectively.

#endif

	CRYPTOC_RC2_CBC, CRYPTOC_RC2_ECB, CRYPTOC_RC2_CFB, CRYPTOC_RC2_OFB,
//	RC2 encryption algorithm in CBC, ECB, CFB and OFB modes respectively. This is a variable key length cipher with an additional parameter called "effective key bits" or "effective key length". By default both are set to 128 bits.

	CRYPTOC_RC2_40_CBC, CRYPTOC_RC2_64_CBC,
//	EVP_CIPHER_CTX_set_key_length() and EVP_CIPHER_CTX_ctrl() to set the key length and effective key length.

	CRYPTOC_BF_CBC, CRYPTOC_BF_ECB, CRYPTOC_BF_CFB, CRYPTOC_BF_OFB,
//	Blowfish encryption algorithm in CBC, ECB, CFB and OFB modes respectively. This is a variable key length cipher.

#ifndef OPENSSL_NO_CAST

	CRYPTOC_CAST5_CBC, CRYPTOC_CAST5_ECB, CRYPTOC_CAST5_CFB, CRYPTOC_CAST5_OFB,
//	CAST encryption algorithm in CBC, ECB, CFB and OFB modes respectively. This is a variable key length cipher.

#endif

#ifndef OPENSSL_NO_RC5

	CRYPTOC_RC5_32_12_16_CBC, CRYPTOC_RC5_32_12_16_ECB, CRYPTOC_RC5_32_12_16_CFB, CRYPTOC_RC5_32_12_16_OFB,
//	RC5 encryption algorithm in CBC, ECB, CFB and OFB modes respectively. This is a variable key length cipher with an additional "number of rounds" parameter. By default the key length is set to 128 bits and 12 rounds.

#endif

#ifndef OPENSSL_NO_AES

	CRYPTOC_AES_128_GCM, CRYPTOC_AES_192_GCM, CRYPTOC_AES_256_GCM,
//	AES Galois Counter Mode (GCM) for 128, 192 and 256 bit keys respectively. These ciphers require additional control operations to function correctly: see the "GCM and OCB modes" section below for details.

	CRYPTOC_AES_128_CCM, CRYPTOC_AES_192_CCM, CRYPTOC_AES_256_CCM,
//	AES Counter with CBC-MAC Mode (CCM) for 128, 192 and 256 bit keys respectively. These ciphers require additional control operations to function correctly: see CCM mode section below for details.

#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
	CRYPTOC_AES_128_CBC_HMAC_SHA1,

	CRYPTOC_AES_256_CBC_HMAC_SHA1
#endif

#endif

} cryptoc_cipher_type;

cryptoc_data cryptoc_encrypt(cryptoc_cipher_type type, unsigned char *key, unsigned char* iv, unsigned char* plaintext, int plaintextLength);
cryptoc_data cryptoc_decrypt(cryptoc_cipher_type type, unsigned char *key, unsigned char* iv, unsigned char* ciphertext, int ciphertextLength);

#endif /* SRC_CRYPTOC_H_ */
