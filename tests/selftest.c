/* selftest.c --- Self-tests for Yubico client library.
 *
 * Written by Simon Josefsson <simon@josefsson.org>.
 * Copyright (c) 2006-2012 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "ykclient.h"
#include <stdio.h>
#include <assert.h>

#include <curl/curl.h>

#include "b64/cencode.h"
#include "b64/cdecode.h"

#define TEST(xX) printf ("\nTest %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__); \
  printf xX; \
  printf ("\n")

void
test_v1_validation(int client_id, char *client_b64key)
{
  ykclient_t *ykc;
  int ret;

  TEST(("init self"));
  ret = ykclient_init (&ykc);
  printf ("ykclient_init (%d): %s\n", ret, ykclient_strerror (ret));
  assert(ret == YKCLIENT_OK);

  ykclient_set_url_template
    (ykc, "http://api.yubico.com/wsapi/verify?id=%d&otp=%s");

  TEST(("null client_id, expect REPLAYED_OTP"));
  ykclient_set_verify_signature(ykc, 0);
  ykclient_set_client (ykc, client_id, 0, NULL);

#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert(ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  /* Test signed request. When signing requests to a v1 service, we must clear the nonce first. */

  TEST(("signed request, expect REPLAYED_OTP"));
  ykclient_set_verify_signature(ykc, 1);
  ykclient_set_client_b64 (ykc, client_id, client_b64key);
  ykclient_set_nonce(ykc, NULL);

#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert(ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  ykclient_done (&ykc);
}

void
test_base64 (void)
{
  base64_encodestate encode;
  base64_decodestate decode;
  char b64dig[64];
  char buf[64];
  int size1, size2;
  int ret;

  TEST(("test base64 encoding"));
  base64_init_encodestate(&encode);
  size1 = base64_encode_block("foo", 3, b64dig, &encode);
  size2 = base64_encode_blockend(&b64dig[size1], &encode);
  b64dig[size1 + size2 - 1] = '\0';

  printf("b64 encode: %s, expected: Zm9v\n", b64dig);
  ret = strcmp(b64dig, "Zm9v");
  assert(ret == 0);

  TEST(("test base64 decoding"));
  base64_init_decodestate(&decode);
  base64_decode_block ("YmxhaG9uZ2E=", 12, buf, &decode);

  printf("b64 decode: %s, expexted: blahonga\n", buf);
  ret = strcmp(buf, "blahonga");
  assert(ret == 0);
}

int
main (void)
{
  int client_id = 1851;
  char client_key[] = {
    0xa0, 0x15, 0x5b, 0x36, 0xde, 0xc8, 0x65, 0xe8, 0x59, 0x19,
    0x1f, 0x7d, 0xae, 0xfa, 0xbc, 0x77, 0xa4, 0x59, 0xd4, 0x33
  };
  char *client_hexkey = "a0155b36dec865e859191f7daefabc77a459d433";
  char *client_b64key = "oBVbNt7IZehZGR99rvq8d6RZ1DM=";
  ykclient_t *ykc;
  int ret;

  curl_global_init(CURL_GLOBAL_ALL);

  TEST(("init self"));
  ret = ykclient_init (&ykc);
  printf ("ykclient_init (%d): %s\n", ret, ykclient_strerror (ret));
  assert(ret == YKCLIENT_OK);

  TEST(("null client_id, expect REPLAYED_OTP"));
  ykclient_set_verify_signature(ykc, 0);
  ykclient_set_client (ykc, client_id, 0, NULL);

#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert(ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("client_id set(20), correct client_key, expect REPLAYED_OTP"));
  ykclient_set_client (ykc, client_id, 20, client_key);

#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("wrong client_id set(10), correct client_key, expect BAD_SIGNATURE"));
  ykclient_set_client (ykc, client_id, 10, client_key);

#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_BAD_SIGNATURE);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("invalid client_id set(a), correct client_key, expect HEX_DECODE_ERROR"));
  ret = ykclient_set_client_hex (ykc, client_id, "a");
  printf ("ykclient_set_client_hex (%d): %s\n", ret, ykclient_strerror (ret));
  assert (ret == YKCLIENT_HEX_DECODE_ERROR);

  TEST(("invalid client_id set(xx), correct client_key, expect HEX_DECODE_ERROR"));
  ret = ykclient_set_client_hex (ykc, client_id, "xx");
  printf ("ykclient_set_client_hex (%d): %s\n", ret, ykclient_strerror (ret));
  assert (ret == YKCLIENT_HEX_DECODE_ERROR);

  TEST(("hex client_id set, correct client_key, expect OK"));
  ret = ykclient_set_client_hex (ykc, client_id, client_hexkey);
  printf ("ykclient_set_client_hex (%d): %s\n", ret, ykclient_strerror (ret));
  assert (ret == YKCLIENT_OK);

#ifndef TEST_WITHOUT_INTERNET
  TEST(("validation request, expect REPLAYED_OTP"));
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("set deadbeef client_id, expect OK"));
  ret = ykclient_set_client_hex (ykc, client_id, "deadbeef");
  printf ("ykclient_set_client_hex (%d): %s\n", ret, ykclient_strerror (ret));
  assert (ret == YKCLIENT_OK);

#ifndef TEST_WITHOUT_INTERNET
  TEST(("validation request, expect BAD_SIGNATURE"));
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_BAD_SIGNATURE);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("b64 set deadbeef client_id, expect OK"));
  ret = ykclient_set_client_b64 (ykc, client_id, "deadbeef");
  printf ("ykclient_set_client_b64 (%d): %s\n", ret, ykclient_strerror (ret));
  assert (ret == YKCLIENT_OK);

#ifndef TEST_WITHOUT_INTERNET
  /* When the server dislikes our signature, it will sign the response with a
     NULL key, so the API call will fail with BAD_SERVER_SIGNATURE even though
     the server returned status=BAD_SIGNATURE.
  */
  TEST(("validation request, expect BAD_SERVER_SIGNATURE"));
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_BAD_SERVER_SIGNATURE);
#else
  printf ("Test SKIPPED\n");
#endif

#ifndef TEST_WITHOUT_INTERNET
  /* Now, disable our checking of the servers signature to get the error
     the server returned (server will use 00000 as key when signing this
     error response).
  */
  TEST(("validation request, expect BAD_SIGNATURE"));
  ykclient_set_verify_signature (ykc, 0);
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_BAD_SIGNATURE);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("b64 set client_b64key, expect OK"));
  ret = ykclient_set_client_b64 (ykc, client_id, client_b64key);
  printf ("ykclient_set_client_b64 (%d): %s\n", ret, ykclient_strerror (ret));
  assert (ret == YKCLIENT_OK);

#ifndef TEST_WITHOUT_INTERNET
  TEST(("validation request, expect REPLAYED_OTP"));
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("set WS 2.0 URL template"));
  /* Set one URL and run tests with that. */
  ykclient_set_url_template
    (ykc, "http://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s");

#ifndef TEST_WITHOUT_INTERNET
  TEST(("validation request, expect REPLAYED_OTP"));
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("yubikey_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  ykclient_set_verify_signature(ykc, 1);

  TEST(("validation request with valid signature, expect REPLAYED_OTP"));
  // Check a genuine signature.
  ykclient_set_client (ykc, client_id, 20, client_key);
#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("validation request with bad key, expect YKCLIENT_BAD_SERVER_SIGNATURE"));
  // Check a genuine signature with a truncated key.
  ykclient_set_client (ykc, client_id, 10, client_key);
#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_BAD_SERVER_SIGNATURE);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("Set and use several V2.0 URLs"));
  const char *templates[] = {
    "http://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
    "http://api2.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
    "http://api3.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
    "http://api4.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
    "http://api5.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
  };
  ykclient_set_url_templates(ykc, 5, templates);
  ykclient_set_client (ykc, client_id, 20, client_key);
#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  ykclient_done (&ykc);

  TEST(("strerror 0"));
  printf ("strerror(0): %s\n", ykclient_strerror (0));
  ret = strcmp(ykclient_strerror (0), "Success"); assert (ret == 0);

  TEST(("strerror BAD_OTP"));
  printf ("strerror(BAD_OTP): %s\n", ykclient_strerror (YKCLIENT_BAD_OTP));
  ret = strcmp(ykclient_strerror (YKCLIENT_BAD_OTP), "Yubikey OTP was bad (BAD_OTP)"); assert (ret == 0);

  test_v1_validation(client_id, client_b64key);

  test_base64();

  printf ("All tests passed\n");

  curl_global_cleanup();

  return 0;
}
