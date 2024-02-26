/*
 * TODO: main tests for stealthy ECH (SECH) 
 *
 * Author:  Neimhin (nrobinso@tcd.ie)
 * Date:    2024-02-21
 *
 * ====================================================================
 * Copyright (c) $(date +%Y) The OpenSSL Project.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 * 
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 * 
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 * 
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 * 
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#define OPENSSL_UNIT_TEST

/* #include header for interface under test */

#include "testutil.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(OPENSSL_NO_UNIT_TEST)

/* Add test code as per
 * http://wiki.openssl.org/index.php/How_To_Write_Unit_Tests_For_OpenSSL#Style
 */

typedef struct test_fixture
	{
	const char* test_case_name;
	} TEST_FIXTURE;

static TEST_FIXTURE set_up(const char* const test_case_name)
	{
	TEST_FIXTURE fixture;
	int setup_ok = 1;
	memset(&fixture, 0, sizeof(fixture));
	fixture.test_case_name = test_case_name;

	/* Allocate memory owned by the fixture, exit on error */

	if (!setup_ok)
		{
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
		}
	return fixture;
	}

static void tear_down(TEST_FIXTURE fixture)
	{
	ERR_print_errors_fp(stderr);
	/* Free any memory owned by the fixture, etc. */
	}

static int execute(TEST_FIXTURE fixture)
	{
	int result = 0;
	/* Execute the code under test, make assertions, format and print errors,
 	 * return zero on success and one on error */
	if (result != 0)
		{
		printf("** %s failed **\n--------\n", fixture.test_case_name);
		}
	return result;
	}

static int test_REPLACE_ME_WITH_A_MEANINGFUL_NAME()
	{
	SETUP_TEST_FIXTURE(TEST_FIXTURE, set_up);
	/* Do test case-specific set up; set expected return values and
 	 * side effects */
	EXECUTE_TEST(execute, tear_down);
	}

int main(int argc, char *argv[])
	{
	int result = 0;

	SSL_library_init();
	SSL_load_error_strings();

	ADD_TEST(test_REPLACE_ME_WITH_A_MEANINGFUL_NAME);

	result = run_tests(argv[0]);
	ERR_print_errors_fp(stderr);
	return result;
	}

#else /* OPENSSL_NO_UNIT_TEST*/

int main(int argc, char *argv[])
	{
	return EXIT_SUCCESS;
	}
#endif /* OPENSSL_NO_UNIT_TEST */

