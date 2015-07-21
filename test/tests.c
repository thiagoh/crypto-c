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
const int LOOP_TESTING_TIMES = 200;

static unsigned char* gen_random(const int len) {

	unsigned char *s = (unsigned char*) malloc(sizeof(unsigned char*) * (len + 1));

    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%*()_+{^'`^~[]{};:.>,</?\\\"'";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = '\0';
    return s;
}

/* A test case that does nothing and succeeds. */
static void null_test_success(void **state) {

    (void) state; /* unused */
}

static void _test_success(cryptoc_cipher_type type, const unsigned char *key, const unsigned char *plain) {

	cryptoc_data cipheredData = cryptoc_encrypt(type, key, plain, strlen((char*) plain));
	if (cipheredData.error) {
		fail_msg("%s", cipheredData.errorMessage);
		assert_false(cipheredData.error);
	}

	cryptoc_data decipheredData = cryptoc_decrypt(type, key, cipheredData.data, cipheredData.length);
	if (decipheredData.error) {
		fail_msg("%s", decipheredData.errorMessage);
		assert_false(decipheredData.error);
	}

	assert_int_equal(strlen((char*) plain), decipheredData.length);
	assert_int_equal(strncmp((const char*)plain, (const char*)decipheredData.data, strlen((char*)plain)), 0);
}

static void _test_success_loop(cryptoc_cipher_type type, int times) {

	/* A 256 bit key */
	static const unsigned char *key = (unsigned char *) "any256bitkey_chars_to_complete_0";

	static const unsigned char* plain = (unsigned char *) "Se hoje é o dia das crianças... Ontem eu disse: o dia da criança é o dia da mãe, dos pais, das professoras, mas também é o dia dos animais, sempre que você olha uma criança, há sempre uma figura oculta, que é um cachorro atrás. O que é algo muito importante!"; //"the fox jumped over the lazy dog";

	_test_success(type, key, plain);

	int i;
	/* A 256 bit key */
	unsigned char *rkey;
	unsigned char* rplain;

	for (i = 0; i < times; i++) {

		rkey = gen_random(32);
		rplain = gen_random(1024);

		_test_success(type, rkey, rplain);
	}
}

static void _test_success_iv(cryptoc_cipher_type type, const unsigned char *key, const unsigned char *iv, const unsigned char *plain) {

	cryptoc_data cipheredData = cryptoc_encrypt_iv(type, key, iv, plain, strlen((char*) plain));
	if (cipheredData.error) {
		fail_msg("%s", cipheredData.errorMessage);
		assert_false(cipheredData.error);
	}

	cryptoc_data decipheredData = cryptoc_decrypt_iv(type, key, iv, cipheredData.data, cipheredData.length);
	if (decipheredData.error) {
		fail_msg("%s", decipheredData.errorMessage);
		assert_false(decipheredData.error);
	}

	assert_int_equal(strlen((char*) plain), decipheredData.length);
	assert_int_equal(strncmp((const char*)plain, (const char*)decipheredData.data, strlen((char*)plain)), 0);
}

static void _test_success_loop_iv(cryptoc_cipher_type type, int iv_length, int times) {

	int i;
	/* A 256 bit key */
	unsigned char *rkey;
	unsigned char *riv;
	unsigned char* rplain;

	for (i = 0; i < times; i++) {

		rkey = gen_random(32);
		riv = gen_random(iv_length);
		rplain = gen_random(1024);

		_test_success_iv(type, rkey, riv, rplain);
	}
}

static void _test_success_iv_aad(cryptoc_cipher_type type, const unsigned char *key, const unsigned char *iv, const unsigned char *plain) {

	cryptoc_data cipheredData = cryptoc_encrypt_iv_aad(type, key, iv, NULL, 0, plain, strlen((char*) plain));
	if (cipheredData.error) {
		fail_msg("%s", cipheredData.errorMessage);
		assert_false(cipheredData.error);
	}

	cryptoc_data decipheredData = cryptoc_decrypt_iv_aad(type, key, iv, NULL, 0, cipheredData.tag, cipheredData.tagLength, cipheredData.data, cipheredData.length);
	if (decipheredData.error) {
		fail_msg("%s", decipheredData.errorMessage);
		assert_false(decipheredData.error);
	}

	assert_int_equal(strlen((char*) plain), decipheredData.length);
	assert_int_equal(strncmp((const char*)plain, (const char*)decipheredData.data, strlen((char*)plain)), 0);
}

static void _test_success_loop_iv_aad(cryptoc_cipher_type type, int iv_length, int times) {

	int i;
	/* A 256 bit key */
	unsigned char *rkey;
	unsigned char *riv;
	unsigned char* rplain;

	for (i = 0; i < times; i++) {

		rkey = gen_random(32);
		riv = gen_random(iv_length);
		rplain = gen_random(1024);

		_test_success_iv_aad(type, rkey, riv, rplain);
	}
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

/* A test case that does something with errors. */
static void simple_test_error(void **state) {

	long current_time; // real call is required here
	time(&current_time);

	/* A 256 bit key */
	unsigned char *key = (unsigned char *) "any256bitkey_chars_to_complete_0";

	unsigned char* plain = (unsigned char *) "Se hoje é o dia das crianças... Ontem eu disse: o dia da criança é o dia da mãe, dos pais, das professoras, mas também é o dia dos animais, sempre que você olha uma criança, há sempre uma figura oculta, que é um cachorro atrás. O que é algo muito importante!"; //"the fox jumped over the lazy dog";

	cryptoc_data decipheredData = cryptoc_decrypt(CRYPTOC_AES_192_CBC, key, plain, strlen((char*) plain));
	if (!decipheredData.error) {
		fail_msg("This plain text could not be decrypted");
	}

	assert_true(decipheredData.error);
}

int main(void) {

	long current_time; // real call is required here
	time(&current_time);

	printf("Test initialization... %ld", current_time);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(null_test_success),
		cmocka_unit_test(test_success_AES_192_CBC),
		cmocka_unit_test(test_success_AES_192_CCM),
		cmocka_unit_test(test_success_AES_192_CFB),
		cmocka_unit_test(test_success_AES_192_ECB),
		cmocka_unit_test(test_success_AES_192_GCM),
		cmocka_unit_test(test_success_AES_192_OFB),
        cmocka_unit_test(simple_test_error),
    };

    int results = cmocka_run_group_tests(tests, NULL, NULL);

	time(&current_time);
    printf("Test teardown %ld", current_time);

    return results;
}
