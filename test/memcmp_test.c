/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "testutil.h"

#define DATA_MAX_SIZE 100
#define DATA_MAX_OFFSET 32

#define DATA_PTR(p) \
  (char*)((((uintptr_t)p + 4096) & -(uintptr_t)4096) - DATA_MAX_OFFSET)

static int test_memcmp(void)
{
	// assert(DATA_MAX_OFFSET < 4096);
	// assert(DATA_MAX_SIZE < 4096);

    // Allocate 2 x 4KB pages (x86-64) and place the data at DATA_MAX_OFFSET
    // bytes before the end of the first page (should work regardless of
	// alignment returned by OPENSSL_malloc).
    //
    // This is just to test CRYPTO_memcmp behavior close to the page boundary.
    //
    // NOTE: This test is not checking read access violation, it only tests
    // correctness of the result for different alignment and sizes.

    char* buffer_a = OPENSSL_malloc(4096 * 2);
    char* buffer_b = OPENSSL_malloc(4096 * 2);

    char* data_a = DATA_PTR(buffer_a);
    char* data_b = DATA_PTR(buffer_b);
    int result = 0;

    // Set up two arrays with identical data.
	for (int i = 0; i < DATA_MAX_SIZE + DATA_MAX_OFFSET; ++i) {
		int v = 'A' + (i % 32);  // ['A'; 'a')
		data_a[i] = v;
		data_b[i] = v;
	}

    if (CRYPTO_memcmp(data_a, data_b, 0)) {
	   TEST_info("CRYPTO_memcmp failed for 0 length case\n");
		goto end;
	}

    for (int size = 1; size < DATA_MAX_SIZE; size++) {
		for (int offset = 0; offset < DATA_MAX_OFFSET; offset++) {
			char* a = data_a + offset;
			char* b = data_b + offset;

			// "Poison" bytes before and after data range to verify that those
        	// bytes aren't affecting CRYPTO_memcmp result.
			char a_before = a[-1];
			char a_after = a[size];
			a[-1] = '0';
			a[size] = '1';
			char b_before = b[-1];
			char b_after = b[size];
			b[-1] = '0';
			b[size] = '1';

			if (CRYPTO_memcmp(a, b, size)) {
				TEST_info("False negative. size=%d, offset=%d\n",
					size, offset);
				goto end;
			}

			for (int byte_index = 0; byte_index < size; byte_index++) {
				char prev = a[byte_index];
				a[byte_index] = prev + 1;

				if (!CRYPTO_memcmp(a, b, size)) {
					TEST_info("False positive. size=%d, offset=%d, index=%d\n",
						size, offset, byte_index);
					goto end;
				}

				a[byte_index] = prev;
			}

		     a[-1] = a_before;
		     a[size] = a_after;
		     b[-1] = b_before;
		     b[size] = b_after;
		}
	}

	result = 1;
end:
	OPENSSL_free(buffer_a);
	OPENSSL_free(buffer_b);

	return result;
}

int setup_tests(void)
{
	ADD_TEST(test_memcmp);
	return 1;
}

