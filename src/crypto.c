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

	unsigned char* ciphertext = malloc(sizeof(unsigned char) * (plaintextLength + 16));

	/* Load the human readable error strings for libcrypto */
	ERR_load_crypto_strings();

	/* Load all digest and cipher algorithms */
	OpenSSL_add_all_algorithms();

	/* Load config file, and other important initialisation */
	OPENSSL_config(NULL);

	EVP_CIPHER_CTX *ctx;

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

	unsigned char* plaintext = malloc(sizeof(unsigned char) * (ciphertextLength));

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
