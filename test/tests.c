#include <string.h>
#include "time.h"
#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <cryptoc.h>

/* Use the unit test allocators */
#define UNIT_TESTING 1
const int LOOP_TESTING_TIMES = 50;

static void gen_random(unsigned char *s, const int len) {

    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%*()_+{^'`^~[]{};:.>,</?\\\"'";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = '\0';
}

/* A test case that does nothing and succeeds. */
static void null_test_success(void **state) {

    (void) state; /* unused */
}

static void _test_success(cryptoc_cipher_type type, const unsigned char *key, int keyLength, const unsigned char *plain, int plainLength) {

	cryptoc_data cipheredData = cryptoc_encrypt(type, key, keyLength, plain, plainLength);
	if (cipheredData.error) {
		fail_msg("%s", cipheredData.errorMessage);
		assert_false(cipheredData.error);
	}

	cryptoc_data decipheredData = cryptoc_decrypt(type, key, keyLength, cipheredData.data, cipheredData.length);
	if (decipheredData.error) {
		fail_msg("%s", decipheredData.errorMessage);
		assert_false(decipheredData.error);
	}

	assert_int_equal(strlen((char*) plain), decipheredData.length);
	assert_int_equal(strncmp((const char*)plain, (const char*)decipheredData.data, strlen((char*)plain)), 0);
}

static void _test_success_loop(cryptoc_cipher_type type, int times) {

	int i;
	unsigned char rkey[32];
	unsigned char rplain[1024];

	for (i = 0; i < times; i++) {

		memset(rkey, 0, 32* sizeof(unsigned char));
		memset(rplain, 0, 1024* sizeof(unsigned char));

		gen_random(rkey, 32);
		gen_random(rplain, 1024);

		_test_success(type, rkey, 32, rplain, 1024);
	}
}

static void _test_success_iv(cryptoc_cipher_type type, const unsigned char *key, int keyLength, const unsigned char *iv, int ivLength, const unsigned char *plain, int plainLength) {

	cryptoc_data cipheredData = cryptoc_encrypt_iv(type, key, keyLength, iv, ivLength, plain, plainLength);
	if (cipheredData.error) {
		fail_msg("%s", cipheredData.errorMessage);
		assert_false(cipheredData.error);
		return;
	}

	cryptoc_data decipheredData = cryptoc_decrypt_iv(type, key, keyLength, iv, ivLength, cipheredData.data, cipheredData.length);
	if (decipheredData.error) {
		fail_msg("%s", decipheredData.errorMessage);
		assert_false(decipheredData.error);
		return;
	}

	assert_int_equal(strlen((char*) plain), decipheredData.length);
	size_t len = strlen((char*)plain);
	assert_int_equal(strncmp((const char*)plain, (const char*)decipheredData.data, len), 0);

	free(cipheredData.data);
	free(cipheredData.errorMessage);
	free(cipheredData.tag);

	free(decipheredData.data);
	free(decipheredData.errorMessage);
	free(decipheredData.tag);
}

static void _test_success_base64(const unsigned char *plain, int length) {

	// http://stackoverflow.com/questions/13378815/base64-length-calculation
	unsigned char* dataEncoded = (unsigned char*) malloc(sizeof(unsigned char) * (4 * length/3));
	int dataEncodedLen = cryptoc_base64_encode(plain, length, dataEncoded);

	unsigned char* dataDecoded = (unsigned char*) malloc(sizeof(unsigned char) * dataEncodedLen);
	int dataDecodedLen = cryptoc_base64_decode(dataEncoded, dataEncodedLen, dataDecoded);

	assert_int_equal(length, dataDecodedLen);
	assert_int_equal(strncmp((const char*)plain, (const char*)dataDecoded, length), 0);

	free(dataEncoded);
	free(dataDecoded);
}

static void _test_success_loop_iv(cryptoc_cipher_type type, int iv_length, int times) {

	int i;
	unsigned char rkey[32];
	unsigned char riv[32];
	unsigned char rplain[1024];

	for (i = 0; i < times; i++) {

		memset(rkey, 0, 32* sizeof(unsigned char));
		memset(riv, 0, iv_length* sizeof(unsigned char));
		memset(rplain, 0, 1024* sizeof(unsigned char));

		gen_random(rkey, 32);
		gen_random(riv, iv_length);
		gen_random(rplain, 1024);

		_test_success_iv(type, rkey, 32, riv, iv_length, rplain, 1024);
	}
}

static void _test_success_loop_base64_encoded(int times) {

	int i;
	unsigned char rkey[32];

	for (i = 0; i < times; i++) {

		memset(rkey, 0, 32* sizeof(unsigned char));

		gen_random(rkey, 32);

		_test_success_base64(rkey, 32);
	}
}

static void _test_success_iv_aad(cryptoc_cipher_type type, const unsigned char *key, int keyLength, const unsigned char *iv, int ivLength, const unsigned char *plain, int plainLength) {

	cryptoc_data cipheredData = cryptoc_encrypt_iv_aad(type, key, keyLength, iv, ivLength, NULL, 0, plain, plainLength);
	if (cipheredData.error) {
		fail_msg("%s", cipheredData.errorMessage);
		assert_false(cipheredData.error);
		return;
	}

	cryptoc_data decipheredData = cryptoc_decrypt_iv_aad(type, key, keyLength, iv, ivLength, NULL, 0, cipheredData.tag, cipheredData.tagLength, cipheredData.data, cipheredData.length);
	if (decipheredData.error) {
		fail_msg("%s", decipheredData.errorMessage);
		assert_false(decipheredData.error);
		return;
	}

	assert_int_equal(strlen((char*) plain), decipheredData.length);
	size_t len = strlen((char*)plain);
	assert_int_equal(strncmp((const char*)plain, (const char*)decipheredData.data, len), 0);

	free(cipheredData.data);
	free(cipheredData.errorMessage);
	free(cipheredData.tag);

	free(decipheredData.data);
	free(decipheredData.errorMessage);
	free(decipheredData.tag);
}

static void _test_success_loop_iv_aad(cryptoc_cipher_type type, int iv_length, int times) {

	int i;
	unsigned char rkey[32];
	unsigned char riv[32];
	unsigned char rplain[1024];

	for (i = 0; i < times; i++) {

		memset(rkey, 0, 32* sizeof(unsigned char));
		memset(riv, 0, iv_length* sizeof(unsigned char));
		memset(rplain, 0, 1024* sizeof(unsigned char));

		gen_random(rkey, 32);
		gen_random(riv, iv_length);
		gen_random(rplain, 1024);

		_test_success_iv_aad(type, rkey, 32, riv, iv_length, rplain, 1024);
	}
}

//////////
//////////   DES(EDE)
//////////

static void test_success_DESX_CBC(void **state) {
	_test_success_loop_iv(CRYPTOC_DESX_CBC, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_CBC(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_CBC, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_CFB(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_CFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_ECB(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_ECB, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_OFB(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_OFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_EDE_CBC(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_EDE_CBC, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_EDE_CFB(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_EDE_CFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_EDE_OFB(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_EDE_OFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_EDE3(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_EDE3, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_EDE3_CBC(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_EDE3_CBC, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_EDE3_CFB(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_EDE3_CFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_DES_EDE3_OFB(void **state) {
	_test_success_loop_iv(CRYPTOC_DES_EDE3_OFB, 16, LOOP_TESTING_TIMES);
}

//////////
//////////   AES
//////////

static void test_success_AES_128_CBC(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_128_CBC, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_128_CCM(void **state) {
	_test_success_loop_iv_aad(CRYPTOC_AES_128_CCM, 12, LOOP_TESTING_TIMES);
}
static void test_success_AES_128_CFB(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_128_CFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_128_GCM(void **state) {
	_test_success_loop_iv_aad(CRYPTOC_AES_128_GCM, 12, LOOP_TESTING_TIMES);
}
static void test_success_AES_128_OFB(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_128_OFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_128_ECB(void **state) {
	_test_success_loop(CRYPTOC_AES_128_ECB, LOOP_TESTING_TIMES);
}

static void test_success_AES_192_CBC(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_192_CBC, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_192_CCM(void **state) {
	_test_success_loop_iv_aad(CRYPTOC_AES_192_CCM, 12, LOOP_TESTING_TIMES);
}
static void test_success_AES_192_CFB(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_192_CFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_192_GCM(void **state) {
	_test_success_loop_iv_aad(CRYPTOC_AES_192_GCM, 12, LOOP_TESTING_TIMES);
}
static void test_success_AES_192_OFB(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_192_OFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_192_ECB(void **state) {
	_test_success_loop(CRYPTOC_AES_192_ECB, LOOP_TESTING_TIMES);
}

static void test_success_AES_256_CBC(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_256_CBC, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_256_CCM(void **state) {
	_test_success_loop_iv_aad(CRYPTOC_AES_256_CCM, 12, LOOP_TESTING_TIMES);
}
static void test_success_AES_256_CFB(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_256_CFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_256_GCM(void **state) {
	_test_success_loop_iv_aad(CRYPTOC_AES_256_GCM, 12, LOOP_TESTING_TIMES);
}
static void test_success_AES_256_OFB(void **state) {
	_test_success_loop_iv(CRYPTOC_AES_256_OFB, 16, LOOP_TESTING_TIMES);
}
static void test_success_AES_256_ECB(void **state) {
	_test_success_loop(CRYPTOC_AES_256_ECB, LOOP_TESTING_TIMES);
}

static void test_success_base64_encoded(void **state) {
	_test_success_loop_base64_encoded(LOOP_TESTING_TIMES);
}
/* A test case that does something with errors. */
static void simple_test(void **state) {

	long current_time;
	time(&current_time);

	/*
	 * Those values from key and iv were generated by this Gist
	 * https://gist.github.com/thiagoh/e0613341a5769620a2f1
	 */

	unsigned char* ivEncoded = (unsigned char *) "dGFyZ2V0AAA=";
	unsigned char* key= (unsigned char *) "The fox jumped over the lazy dog";
	unsigned char* dataEncoded = (unsigned char *) "n9gA+WnWgju5CagPlvgzMg==";

	unsigned char* dataDecoded = (unsigned char*) malloc(sizeof(unsigned char) * strlen((const char*)dataEncoded));
	int dataDecodedLen = cryptoc_base64_decode(dataEncoded, strlen((const char*)dataEncoded), dataDecoded);

	unsigned char* ivDecoded = (unsigned char*) malloc(sizeof(unsigned char) * strlen((const char*)ivEncoded));
	int ivDecodedLen = cryptoc_base64_decode(ivEncoded, strlen((const char*)ivEncoded), ivDecoded);

	cryptoc_data decipheredData = cryptoc_decrypt_iv(CRYPTOC_DES_EDE3_CBC, key, strlen((char*) key), ivDecoded, ivDecodedLen, dataDecoded, dataDecodedLen);

	if (decipheredData.error) {
		fail_msg("This data could not be decrypted");
	}

	assert_false(decipheredData.error);
}
/* A test case that does something with errors. */
static void simple_test_error(void **state) {

	long current_time;
	time(&current_time);

	unsigned char *key = (unsigned char *) "any256bitkey_chars_to_complete_0";
	unsigned char* plain = (unsigned char *) "The fox jumped over the lazy dog";

	cryptoc_data decipheredData = cryptoc_decrypt(CRYPTOC_AES_192_CBC, key, strlen((char*) key), plain, strlen((char*) plain));

	if (!decipheredData.error) {
		fail_msg("This plain text could not be decrypted");
	}

	assert_true(decipheredData.error);
}

int main(void) {

	long current_time;
	time(&current_time);

	printf("Test initialization... %ld", current_time);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
        cmocka_unit_test(simple_test),
		cmocka_unit_test(test_success_base64_encoded),

		cmocka_unit_test(test_success_DESX_CBC),
		cmocka_unit_test(test_success_DES_CBC),
		cmocka_unit_test(test_success_DES_CFB),
		cmocka_unit_test(test_success_DES_ECB),
		cmocka_unit_test(test_success_DES_OFB),
		cmocka_unit_test(test_success_DES_EDE_CBC),
		cmocka_unit_test(test_success_DES_EDE_CFB),
		cmocka_unit_test(test_success_DES_EDE_OFB),
		cmocka_unit_test(test_success_DES_EDE3),
		cmocka_unit_test(test_success_DES_EDE3_CBC),
		cmocka_unit_test(test_success_DES_EDE3_CFB),
		cmocka_unit_test(test_success_DES_EDE3_OFB),

		cmocka_unit_test(test_success_AES_128_CBC),
		cmocka_unit_test(test_success_AES_128_CCM),
		cmocka_unit_test(test_success_AES_128_CFB),
		cmocka_unit_test(test_success_AES_128_ECB),
		cmocka_unit_test(test_success_AES_128_GCM),
		cmocka_unit_test(test_success_AES_128_OFB),

		cmocka_unit_test(test_success_AES_192_CBC),
		cmocka_unit_test(test_success_AES_192_CCM),
		cmocka_unit_test(test_success_AES_192_CFB),
		cmocka_unit_test(test_success_AES_192_ECB),
		cmocka_unit_test(test_success_AES_192_GCM),
		cmocka_unit_test(test_success_AES_192_OFB),

		cmocka_unit_test(test_success_AES_256_CBC),
		cmocka_unit_test(test_success_AES_256_CCM),
		cmocka_unit_test(test_success_AES_256_CFB),
		cmocka_unit_test(test_success_AES_256_ECB),
		cmocka_unit_test(test_success_AES_256_GCM),
		cmocka_unit_test(test_success_AES_256_OFB),
        cmocka_unit_test(simple_test_error),
    };

    int results = cmocka_run_group_tests(tests, NULL, NULL);

	time(&current_time);
    printf("Test teardown %ld", current_time);

    return results;
}
