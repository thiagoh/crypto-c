/*
 * Crypto.cpp
 *
 *  Created on: Jul 2, 2015
 *      Author: thiagoh
 */

#include <crypto.h>
#include <string.h>

static void crypto_handle_errors(crypto_data* data) {

	int errorcode = ERR_peek_error();
	const char* reason = ERR_reason_error_string(errorcode);
	const char* lib_error = ERR_lib_error_string(errorcode);

	char* errormsg = (char*) malloc(sizeof(char*) * (10 + strlen(reason) + strlen(lib_error)));
	sprintf(errormsg, "error: %d %s. reason: %s", errorcode, reason, lib_error);

	data->errorMessage = errormsg;
	data->error = true;

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

crypto_data crypto_encrypt(unsigned char* plaintext, int plaintextLength, unsigned char *key, unsigned char* iv) {

	crypto_data p;
	p.error = false;

	if (!plaintext) {
		p.error = true;
		p.errorMessage = "Plaintext must be defined";
		return p;
	}

	if (plaintextLength < 0) {
		p.error = true;
		p.errorMessage = "Plaintext length must be positive";
		return p;
	}

	if (strlen((char*) key) > EVP_MAX_KEY_LENGTH) {
		p.error = true;
		char s[60];
		sprintf(s, "Error: Key length is greater than the maxminum %d", EVP_MAX_KEY_LENGTH);
		p.errorMessage = s;
		return p;
	}

	if (strlen((char*) iv) > EVP_MAX_IV_LENGTH) {
		fprintf(stderr, "Warn: IV length is greater than the maxminum %d", EVP_MAX_IV_LENGTH);
	}

	//https://www.openssl.org/docs/crypto/EVP_CIPHER_CTX_set_key_length.html
	unsigned char* ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * (plaintextLength + EVP_MAX_BLOCK_LENGTH));

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
		crypto_handle_errors(&p);

	if (p.error != 0) {
		_finally(ctx);
		return p;
	}

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		crypto_handle_errors(&p);

	if (p.error != 0) {
		_finally(ctx);
		return p;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintextLength))
		crypto_handle_errors(&p);

	if (p.error != 0) {
		_finally(ctx);
		return p;
	}

	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		crypto_handle_errors(&p);

	if (p.error != 0) {
		_finally(ctx);
		return p;
	}

	ciphertext_len += len;

	_finally(ctx);

	p.error = false;
	p.data = ciphertext;
	p.length = ciphertext_len;

	return p;
}

crypto_data crypto_decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char *key, unsigned char* iv) {

	crypto_data p;
	p.error = false;

	if (!ciphertext) {
		p.error = true;
		p.errorMessage = "Cipher text must be defined";
		return p;
	}

	if (ciphertextLength < 0) {
		p.error = true;
		p.errorMessage = "Cipher text length must be positive";
		return p;
	}

	if (strlen((char*) key) > EVP_MAX_KEY_LENGTH) {
		p.error = true;
		char s[60];
		sprintf(s, "Error: Key length is greater than the maxminum %d", EVP_MAX_KEY_LENGTH);
		p.errorMessage = s;
		return p;
	}

	if (strlen((char*) iv) > EVP_MAX_IV_LENGTH) {
		fprintf(stderr, "Warn: IV length is greater than the maxminum %d", EVP_MAX_IV_LENGTH);
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
		crypto_handle_errors(&p);

	if (p.error != 0) {
		_finally(ctx);
		return p;
	}

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		crypto_handle_errors(&p);

	if (p.error != 0) {
		_finally(ctx);
		return p;
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextLength))
		crypto_handle_errors(&p);

	if (p.error != 0) {
		_finally(ctx);
		return p;
	}

	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		crypto_handle_errors(&p);

	if (p.error != 0) {
		_finally(ctx);
		return p;
	}

	plaintext_len += len;

	_finally(ctx);

	plaintext[plaintext_len] = '\0';

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
