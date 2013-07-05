/* selftest.c --- Self-tests for Yubico client library.
 *
 * Written by Simon Josefsson <simon@josefsson.org>.
 * Copyright (c) 2006-2013 Yubico AB
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert(ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  ykclient_done (&ykc);
}

#if 0
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

/* test cases for HMAC-SHA1 from rcs 2202 */
void
test_hmac (void)
{
  int res;
  uint8_t result[USHAMaxHashSize];

  unsigned char text1[] = "Hi There";
  unsigned char key1[20];
  memset(key1, 0x0b, 20);
  uint8_t expected1[] = {0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00};

  unsigned char text2[] = "what do ya want for nothing?";
  unsigned char key2[] = "Jefe";
  uint8_t expected2[] = {0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79};

  unsigned char text3[50];
  memset(text3, 0xdd, 50);
  unsigned char key3[20];
  memset(key3, 0xaa, 20);
  uint8_t expected3[] = {0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f, 0x63, 0xf1, 0x75, 0xd3};

  unsigned char text4[50];
  memset(text4, 0xcd, 50);
  unsigned char key4[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  uint8_t expected4[] = {0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6, 0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50, 0xc8, 0x6c, 0x2d, 0x72, 0x35, 0xda};

  unsigned char text5[] = "Test With Truncation";
  unsigned char key5[20];
  memset(key5, 0x0c, 20);
  uint8_t expected5[] = {0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f, 0xe7, 0xf2, 0x7b, 0xe1, 0xd5, 0x8b, 0xb9, 0x32, 0x4a, 0x9a, 0x5a, 0x04};

  unsigned char text6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
  unsigned char key6[80];
  memset(key6, 0xaa, 80);
  uint8_t expected6[] = {0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95, 0x70, 0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55, 0xed, 0x40, 0x21, 0x12};

  unsigned char text7[] = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
  unsigned char key7[80];
  memset(key7, 0xaa, 80);
  uint8_t expected7[] = {0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78, 0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c, 0x78, 0x08, 0xbb, 0xff, 0x1a, 0x91};

  TEST(("HMAC-SHA1 case 1"));
  res = hmac (SHA1, text1, 8, key1, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected1, 20) == 0);

  TEST(("HMAC-SHA1 case 2"));
  res = hmac (SHA1, text2, 28, key2, 4, result);
  assert(res == 0);
  assert(memcmp(result, expected2, 20) == 0);

  TEST(("HMAC-SHA1 case 3"));
  res = hmac (SHA1, text3, 50, key3, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected3, 20) == 0);

  TEST(("HMAC-SHA1 case 4"));
  res = hmac (SHA1, text4, 50, key4, 25, result);
  assert(res == 0);
  assert(memcmp(result, expected4, 20) == 0);

  TEST(("HMAC-SHA1 case 5"));
  res = hmac (SHA1, text5, 20, key5, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected5, 20) == 0);

  TEST(("HMAC-SHA1 case 6"));
  res = hmac (SHA1, text6, 54, key6, 80, result);
  assert(res == 0);
  assert(memcmp(result, expected6, 20) == 0);

  TEST(("HMAC-SHA1 case 7"));
  res = hmac (SHA1, text7, 73, key7, 80, result);
  assert(res == 0);
  assert(memcmp(result, expected7, 20) == 0);
}
#endif

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

  if (strcmp (YKCLIENT_VERSION_STRING, ykclient_check_version (NULL)) != 0)
    {
      printf ("version mismatch %s != %s\n",YKCLIENT_VERSION_STRING,
	      ykclient_check_version (NULL));
      return 1;
    }

  if (ykclient_check_version (YKCLIENT_VERSION_STRING) == NULL)
    {
      printf ("version NULL?\n");
      return 1;
    }

  if (ykclient_check_version ("99.99.99") != NULL)
    {
      printf ("version not NULL?\n");
      return 1;
    }

  printf ("ykclient version: header %s library %s\n",
	  YKCLIENT_VERSION_STRING, ykclient_check_version(NULL));

  ret = ykclient_global_init ();
  assert (ret == YKCLIENT_OK);

  TEST(("init self"));
  ret = ykclient_init (&ykc);
  printf ("ykclient_init (%d): %s\n", ret, ykclient_strerror (ret));
  assert(ret == YKCLIENT_OK);

  TEST(("null client_id, expect REPLAYED_OTP"));
  ykclient_set_verify_signature(ykc, 0);
  ykclient_set_client (ykc, client_id, 0, NULL);

#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert(ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("client_id set(20), correct client_key, expect REPLAYED_OTP"));
  ykclient_set_client (ykc, client_id, 20, client_key);

#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("wrong client_id set(10), correct client_key, expect BAD_SIGNATURE"));
  ykclient_set_client (ykc, client_id, 10, client_key);

#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
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

#if 0
  test_base64();

  test_hmac();
#endif

  printf ("All tests passed\n");

  ykclient_global_done();

  return 0;
}
