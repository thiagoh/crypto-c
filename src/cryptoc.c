/*
 * Crypto.cpp
 *
 *  Created on: Jul 2, 2015
 *      Author: thiagoh
 */

#include <cryptoc.h>
#include <string.h>

static void cryptoc_handle_errors(cryptoc_data* data) {

	int errorcode = ERR_peek_error();

	data->error = true;

	if (errorcode == 0) {
		ERR_print_errors_fp(stderr);
		return;
	}

	const char* reason = ERR_reason_error_string(errorcode);
	const char* lib_error = ERR_lib_error_string(errorcode);

	char* errormsg = (char*) malloc(sizeof(char) * (10 + strlen(reason) + strlen(lib_error)));
	sprintf(errormsg, "error: %d %s. reason: %s", errorcode, reason, lib_error);

	data->errorMessage = errormsg;

	ERR_print_errors_fp(stderr);
}

static void _finally(EVP_CIPHER_CTX *ctx) {

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	/* Removes all digests and ciphers */
	EVP_cleanup();

	/* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
	CRYPTO_cleanup_all_ex_data();

	/* Remove error strings */
	ERR_free_strings();
}

static const EVP_CIPHER* get_cipher_type(cryptoc_cipher_type type) {

	if (type == CRYPTOC_ENC_NULL) {
		return EVP_enc_null();

#ifndef OPENSSL_NO_AES

	} else if (type == CRYPTOC_AES_128_CBC) {
		return EVP_aes_128_cbc();

	} else if (type == CRYPTOC_AES_128_ECB) {
		return EVP_aes_128_ecb();

	} else if (type == CRYPTOC_AES_128_CFB) {
		return EVP_aes_128_cfb();

	} else if (type == CRYPTOC_AES_128_OFB) {
		return EVP_aes_128_ofb();

	} else if (type == CRYPTOC_AES_192_CBC) {
		return EVP_aes_192_cbc();

	} else if (type == CRYPTOC_AES_192_ECB) {
		return EVP_aes_192_ecb();

	} else if (type == CRYPTOC_AES_192_CFB) {
		return EVP_aes_192_cfb();

	} else if (type == CRYPTOC_AES_192_OFB) {
		return EVP_aes_192_ofb();

	} else if (type == CRYPTOC_AES_256_CBC) {
		return EVP_aes_256_cbc();

	} else if (type == CRYPTOC_AES_256_ECB) {
		return EVP_aes_256_ecb();

	} else if (type == CRYPTOC_AES_256_CFB) {
		return EVP_aes_256_cfb();

	} else if (type == CRYPTOC_AES_256_OFB) {
		return EVP_aes_256_ofb();

	} else if (type == CRYPTOC_AES_128_GCM) {
		return EVP_aes_128_gcm();

	} else if (type == CRYPTOC_AES_192_GCM) {
		return EVP_aes_192_gcm();

	} else if (type == CRYPTOC_AES_256_GCM) {
		return EVP_aes_256_gcm();

	} else if (type == CRYPTOC_AES_128_CCM) {
		return EVP_aes_128_ccm();

	} else if (type == CRYPTOC_AES_192_CCM) {
		return EVP_aes_192_ccm();

	} else if (type == CRYPTOC_AES_256_CCM) {
		return EVP_aes_256_ccm();

#if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
	} else if (type == CRYPTOC_AES_128_CBC_HMAC_SHA1) {
		return EVP_aes_128_cbc_hmac_sha1();

	} else if (type == CRYPTOC_AES_256_CBC_HMAC_SHA1) {
		return EVP_aes_256_cbc_hmac_sha1();
#endif

#endif

	} else if (type == CRYPTOC_DES_CBC) {
		return EVP_des_cbc();

	} else if (type == CRYPTOC_DES_ECB) {
		return EVP_des_ecb();

	} else if (type == CRYPTOC_DES_CFB) {
		return EVP_des_cfb();

	} else if (type == CRYPTOC_DES_OFB) {
		return EVP_des_ofb();

	} else if (type == CRYPTOC_DES_EDE_CBC) {
		return EVP_des_cbc();

	} else if (type == CRYPTOC_DES_EDE) {
		return EVP_des_ede();

	} else if (type == CRYPTOC_DES_EDE_OFB) {
		return EVP_des_ede_ofb();

	} else if (type == CRYPTOC_DES_EDE_CFB) {
		return EVP_des_ede_cfb();

	} else if (type == CRYPTOC_DES_EDE3_CBC) {
		return EVP_des_ede3_cbc();

	} else if (type == CRYPTOC_DES_EDE3) {
		return EVP_des_ede3();

	} else if (type == CRYPTOC_DES_EDE3_OFB) {
		return EVP_des_ede3_ofb();

	} else if (type == CRYPTOC_DES_EDE3_CFB) {
		return EVP_des_ede3_cfb();

	} else if (type == CRYPTOC_DESX_CBC) {
		return EVP_desx_cbc();

	} else if (type == CRYPTOC_RC4) {
		return EVP_rc4();

	} else if (type == CRYPTOC_RC4_40) {
		return EVP_rc4_40();

#ifndef OPENSSL_NO_IDEA

	} else if (type == CRYPTOC_IDEA_CBC) {
		return EVP_idea_cbc();

	} else if (type == CRYPTOC_IDEA_ECB) {
		return EVP_idea_ecb();

	} else if (type == CRYPTOC_IDEA_CFB) {
		return EVP_idea_cfb();

	} else if (type == CRYPTOC_IDEA_OFB) {
		return EVP_idea_ofb();

#endif

	} else if (type == CRYPTOC_RC2_CBC) {
		return EVP_rc2_cbc();

	} else if (type == CRYPTOC_RC2_ECB) {
		return EVP_rc2_ecb();

	} else if (type == CRYPTOC_RC2_CFB) {
		return EVP_rc2_cbc();

	} else if (type == CRYPTOC_RC2_OFB) {
		return EVP_rc2_ofb();

	} else if (type == CRYPTOC_RC2_40_CBC) {
		return EVP_rc2_40_cbc();

	} else if (type == CRYPTOC_RC2_64_CBC) {
		return EVP_rc2_64_cbc();

	} else if (type == CRYPTOC_BF_CBC) {
		return EVP_bf_cbc();

	} else if (type == CRYPTOC_BF_ECB) {
		return EVP_bf_ecb();

	} else if (type == CRYPTOC_BF_CFB) {
		return EVP_bf_cfb();

	} else if (type == CRYPTOC_BF_OFB) {
		return EVP_bf_ofb();

#ifndef OPENSSL_NO_CAST

	} else if (type == CRYPTOC_CAST5_CBC) {
		return EVP_cast5_cbc();

	} else if (type == CRYPTOC_CAST5_ECB) {
		return EVP_cast5_ecb();

	} else if (type == CRYPTOC_CAST5_CFB) {
		return EVP_cast5_cfb();

	} else if (type == CRYPTOC_CAST5_OFB) {
		return EVP_cast5_ofb();

#endif

#ifndef OPENSSL_NO_RC5

	} else if (type == CRYPTOC_RC5_32_12_16_CBC) {
		return EVP_rc5_32_12_16_cbc();

	} else if (type == CRYPTOC_RC5_32_12_16_ECB) {
		return EVP_rc5_32_12_16_ecb();

	} else if (type == CRYPTOC_RC5_32_12_16_CFB) {
		return EVP_rc5_32_12_16_cfb();

	} else if (type == CRYPTOC_RC5_32_12_16_OFB) {
		return EVP_rc5_32_12_16_ofb();

#endif
	} else {
		return EVP_enc_null();
	}
}

cryptoc_data cryptoc_encrypt(cryptoc_cipher_type type, const unsigned char *key, const unsigned char* plaintext, int plaintextLength) {

	return cryptoc_encrypt_iv(type, key, NULL, plaintext, plaintextLength);
}

cryptoc_data cryptoc_decrypt(cryptoc_cipher_type type, const unsigned char *key, const unsigned char* ciphertext, int ciphertextLength) {

	return cryptoc_decrypt_iv(type, key, NULL, ciphertext, ciphertextLength);
}

cryptoc_data cryptoc_encrypt_iv(cryptoc_cipher_type type, const unsigned char *key, const unsigned char* iv, const unsigned char* plaintext, int plaintextLength) {

	return cryptoc_encrypt_iv_aad(type, key, iv, NULL, 0, plaintext, plaintextLength);
}

cryptoc_data cryptoc_decrypt_iv(cryptoc_cipher_type type, const unsigned char *key, const unsigned char* iv, const unsigned char* ciphertext, int ciphertextLength) {

	return cryptoc_decrypt_iv_aad(type, key, iv, NULL, 0, NULL, 0, ciphertext, ciphertextLength);
}

cryptoc_data cryptoc_encrypt_iv_aad(cryptoc_cipher_type type, const unsigned char *key, const unsigned char* iv, unsigned char *aad,
		int aad_len, const unsigned char* plaintext, int plaintextLength) {

	cryptoc_data p;
	p.error = false;
	p.errorMessage = 0;
	p.data = 0;
	p.tag = 0;
	p.tagLength = 0;

	if (!plaintext) {
		p.error = true;
		char s[60];
		sprintf(s, "Plaintext must be defined");
		p.errorMessage = s;
		return p;
	}

	if (plaintextLength < 0) {
		p.error = true;
		char s[60];
		sprintf(s, "Plaintext length must be positive");
		p.errorMessage = s;
		return p;
	}

	if (strlen((char*) key) > EVP_MAX_KEY_LENGTH) {
		p.error = true;
		char s[60];
		sprintf(s, "Error: Key length is greater than the maxminum %d", EVP_MAX_KEY_LENGTH);
		p.errorMessage = s;
		return p;
	}

	// https://www.openssl.org/docs/crypto/EVP_CIPHER_CTX_set_key_length.html
	unsigned char* ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * (plaintextLength + EVP_MAX_BLOCK_LENGTH));
	int tag_length = 16;

	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

	EVP_CIPHER_CTX *ctx;

	//	int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);
	//	int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);

	//https://www.openssl.org/docs/crypto/EVP_CIPHER_CTX_set_key_length.html
	//OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
	//OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		cryptoc_handle_errors(&p);

	if (p.error) {
		_finally(ctx);
		return p;
	}

	const EVP_CIPHER* cipher = get_cipher_type(type);
	unsigned int cipher_iv_length = (unsigned int) EVP_CIPHER_iv_length(cipher);
	unsigned int iv_length = cipher_iv_length;
	unsigned char* effective_iv = (unsigned char*) malloc(cipher_iv_length);

	if (cipher_iv_length > 0) {

		if (iv == NULL) {
			p.error = true;
			char s[60];
			sprintf(s, "Error: The iv cannot be null");
			p.errorMessage = s;
			_finally(ctx);
			return p;
		}

		if (strlen((char*) iv) < cipher_iv_length) {
			p.error = true;
			char s[60];
			sprintf(s, "Error: The iv cannot be lower than %d");
			p.errorMessage = s;
			_finally(ctx);
			return p;
		}

		if (strlen((char*) iv) > cipher_iv_length) {
			fprintf(stderr, "Warn: The iv cannot be greater than %d so it was truncated\n", cipher_iv_length);

			strncpy((char*) effective_iv, (const char*) iv, cipher_iv_length);
			effective_iv[cipher_iv_length] = '\0';
			iv_length = strlen((char*) effective_iv);
		} else {
			strcpy((char*) effective_iv, (const char*) iv);
			iv_length = strlen((char*) effective_iv);
		}
	}

	unsigned long cipher_mode = EVP_CIPHER_mode(cipher);
	unsigned char* tag;

	if (cipher_mode == EVP_CIPH_CCM_MODE || cipher_mode == EVP_CIPH_GCM_MODE) {

		/**
		 * CCM and GCM documentation
		 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_CCM_mode
		 */

		tag = (unsigned char*) malloc(sizeof(unsigned char) * (tag_length));

		if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
			cryptoc_handle_errors(&p);

		if (p.error) {
			_finally(ctx);
			return p;
		}

		if (cipher_mode == EVP_CIPH_CCM_MODE) {
			if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_length, NULL))
				cryptoc_handle_errors(&p);
		} else if (cipher_mode == EVP_CIPH_GCM_MODE) {
			if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length, NULL))
				cryptoc_handle_errors(&p);
		}

		if (p.error) {
			_finally(ctx);
			return p;
		}

		if (cipher_mode == EVP_CIPH_CCM_MODE) {
			/* Set tag length */
			EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_length, NULL);
		}

		if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, effective_iv))
			cryptoc_handle_errors(&p);

	} else {

		if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, effective_iv))
			cryptoc_handle_errors(&p);
	}

	if (p.error) {
		_finally(ctx);
		return p;
	}

	if (cipher_mode == EVP_CIPH_CCM_MODE) {

		if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintextLength))
			cryptoc_handle_errors(&p);

		if (p.error) {
			_finally(ctx);
			return p;
		}
	}

	if (aad_len > 0) {
		if (cipher_mode == EVP_CIPH_CCM_MODE || cipher_mode == EVP_CIPH_GCM_MODE) {
			/* Provide any AAD data. This can be called zero or one times as required */
			if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
				cryptoc_handle_errors(&p);

			if (p.error) {
				_finally(ctx);
				return p;
			}
		}
	}

	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintextLength))
		cryptoc_handle_errors(&p);

	if (p.error) {
		_finally(ctx);
		return p;
	}

	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		cryptoc_handle_errors(&p);

	if (p.error) {
		_finally(ctx);
		return p;
	}

	ciphertext_len += len;

	if (cipher_mode == EVP_CIPH_CCM_MODE || cipher_mode == EVP_CIPH_GCM_MODE) {

		/* Get the tag */
		if (cipher_mode == EVP_CIPH_CCM_MODE) {
			if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_length, tag))
				cryptoc_handle_errors(&p);
		} else if (cipher_mode == EVP_CIPH_GCM_MODE) {
			if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_length, tag))
				cryptoc_handle_errors(&p);
		}

		if (p.error) {
			_finally(ctx);
			return p;
		}

		p.tag = tag;
		p.tagLength = tag_length;
	}

	_finally(ctx);

	p.error = false;
	p.data = ciphertext;
	p.length = ciphertext_len;

	return p;
}

cryptoc_data cryptoc_decrypt_iv_aad(cryptoc_cipher_type type, const unsigned char *key, const unsigned char* iv, unsigned char *aad,
		int aad_len, unsigned char *tag, int tagLength, const unsigned char* ciphertext, int ciphertextLength) {

	cryptoc_data p;
	p.error = false;
	p.errorMessage = 0;
	p.data = 0;
	p.tag = 0;
	p.tagLength = 0;

	if (!ciphertext) {
		p.error = true;
		char s[60];
		sprintf(s, "Cipher text must be defined");
		p.errorMessage = s;
		return p;
	}

	if (ciphertextLength < 0) {
		p.error = true;
		char s[60];
		sprintf(s, "Cipher text length must be positive");
		p.errorMessage = s;
		return p;
	}

	if (strlen((char*) key) > EVP_MAX_KEY_LENGTH) {
		p.error = true;
		char s[60];
		sprintf(s, "Error: Key length is greater than the maxminum %d", EVP_MAX_KEY_LENGTH);
		p.errorMessage = s;
		return p;
	}

	unsigned char* plaintext = (unsigned char*) malloc(sizeof(unsigned char) * (ciphertextLength + EVP_MAX_BLOCK_LENGTH));

	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

	EVP_CIPHER_CTX *ctx;

	int len;
	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		cryptoc_handle_errors(&p);

	if (p.error) {
		_finally(ctx);
		return p;
	}

	const EVP_CIPHER* cipher = get_cipher_type(type);
	unsigned int cipher_iv_length = (unsigned int) EVP_CIPHER_iv_length(cipher);
	unsigned int iv_length = cipher_iv_length;
	unsigned char* effective_iv = (unsigned char*) malloc(cipher_iv_length);

	if (cipher_iv_length > 0) {

		if (iv == NULL) {
			p.error = true;
			char s[60];
			sprintf(s, "Error: The iv cannot be null");
			p.errorMessage = s;
			_finally(ctx);
			return p;
		}

		if (strlen((char*) iv) < cipher_iv_length) {
			p.error = true;
			char s[60];
			sprintf(s, "Error: The iv cannot be lower than %d", EVP_MAX_IV_LENGTH);
			p.errorMessage = s;
			_finally(ctx);
			return p;
		}

		if (strlen((char*) iv) > cipher_iv_length) {
			fprintf(stderr, "Warn: The iv cannot be greater than %d so it was truncated\n", cipher_iv_length);

			strncpy((char*) effective_iv, (const char*) iv, cipher_iv_length);
			effective_iv[cipher_iv_length] = '\0';
			iv_length = strlen((char*) effective_iv);
		} else {
			strcpy((char*) effective_iv, (const char*) iv);
			iv_length = strlen((char*) effective_iv);
		}
	}

	unsigned long cipher_mode = EVP_CIPHER_mode(cipher);

	if (cipher_mode == EVP_CIPH_CCM_MODE || cipher_mode == EVP_CIPH_GCM_MODE) {

		/**
		 * CCM and GCM documentation
		 * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_CCM_mode
		 */

		if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
			cryptoc_handle_errors(&p);

		if (p.error) {
			_finally(ctx);
			return p;
		}

		if (cipher_mode == EVP_CIPH_CCM_MODE) {
			if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_length, NULL))
				cryptoc_handle_errors(&p);
		} else if (cipher_mode == EVP_CIPH_GCM_MODE) {
				if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length, NULL))
					cryptoc_handle_errors(&p);
			}

		if (p.error) {
			_finally(ctx);
			return p;
		}

		if (cipher_mode == EVP_CIPH_CCM_MODE) {
			if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tagLength, tag))
				cryptoc_handle_errors(&p);
		} else if (cipher_mode == EVP_CIPH_GCM_MODE) {
			if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLength, tag))
				cryptoc_handle_errors(&p);
		}

		if (p.error) {
			_finally(ctx);
			return p;
		}

		if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, effective_iv))
			cryptoc_handle_errors(&p);

	} else {

		if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, effective_iv))
			cryptoc_handle_errors(&p);
	}

	if (p.error) {
		_finally(ctx);
		return p;
	}

	if (cipher_mode == EVP_CIPH_CCM_MODE) {

		if (1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertextLength))
			cryptoc_handle_errors(&p);

		if (p.error) {
			_finally(ctx);
			return p;
		}
	}

	if (aad_len > 0) {
		if (cipher_mode == EVP_CIPH_CCM_MODE || cipher_mode == EVP_CIPH_GCM_MODE) {
			/* Provide any AAD data. This can be called zero or more times as required */
			if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
				cryptoc_handle_errors(&p);

			if (p.error) {
				_finally(ctx);
				return p;
			}
		}
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextLength))
		cryptoc_handle_errors(&p);

	if (p.error) {
		_finally(ctx);
		return p;
	}

	plaintext_len = len;

	if (cipher_mode != EVP_CIPH_CCM_MODE) {

		/* Finalise the decryption. Further plaintext bytes may be written at
		 * this stage.
		 */
		if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
			cryptoc_handle_errors(&p);

		if (p.error) {
			_finally(ctx);
			return p;
		}

		plaintext_len += len;
	}

	_finally(ctx);

	//plaintext[plaintext_len] = '\0';

	p.error = false;
	p.data = plaintext;
	p.length = plaintext_len;

	return p;
}

//
// General encryption and decryption function example using FILE I/O and AES128 with a 128-bit key:
//
//int do_crypt(FILE *in, FILE *out, int do_encrypt)
//{
///* Allow enough space in output buffer for additional block */
//unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
//int inlen, outlen;
//EVP_CIPHER_CTX ctx;
///* Bogus key and IV: we'd normally set these from
//* another source.
//*/
//unsigned char key[] = "0123456789abcdeF";
//unsigned char iv[] = "1234567887654321";
//
///* Don't set key or IV right away; we want to check lengths */
//EVP_CIPHER_CTX_init(&ctx);
//EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
//	   do_encrypt);
//OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
//OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);
//
///* Now we can set key and IV */
//EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);
//
//for(;;)
//	   {
//	   inlen = fread(inbuf, 1, 1024, in);
//	   if(inlen <= 0) break;
//	   if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen))
//			   {
//			   /* Error */
//			   EVP_CIPHER_CTX_cleanup(&ctx);
//			   return 0;
//			   }
//	   fwrite(outbuf, 1, outlen, out);
//	   }
//if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen))
//	   {
//	   /* Error */
//	   EVP_CIPHER_CTX_cleanup(&ctx);
//	   return 0;
//	   }
//fwrite(outbuf, 1, outlen, out);
//
//EVP_CIPHER_CTX_cleanup(&ctx);
//return 1;
//}
