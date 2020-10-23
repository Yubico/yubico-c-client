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
#include "sha.h"
#include "cencode.h"
#include "cdecode.h"

#include <stdio.h>
#include <assert.h>

#define TEST(xX) printf ("\nTest %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__); \
  printf xX; \
  printf ("\n")

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

/* test cases for HMAC-SHA1 from rfc 2202 */
void
test_hmac (void)
{
  int res;
  uint8_t result[USHAMaxHashSize];

  unsigned char text1[] = "Hi There";
  unsigned char key1[20];
  memset(key1, 0x0b, 20);
  uint8_t expected1[] = {0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2,
			 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46,
			 0xbe, 0x00};
  uint8_t expected1_sha224[] = {0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19,
				0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f,
				0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f,
				0x53, 0x68, 0x4b, 0x22};
  uint8_t expected1_sha256[] = {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
				0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
				0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
				0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
  uint8_t expected1_sha384[] = {0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62,
				0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f,
				0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
				0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c,
				0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f,
				0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6};
  uint8_t expected1_sha512[] = {0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d,
				0x4f, 0xf0, 0xb4, 0x24,	0x1a, 0x1d, 0x6c, 0xb0,
				0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
				0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde,
				0xda, 0xa8, 0x33, 0xb7,	0xd6, 0xb8, 0xa7, 0x02,
				0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
				0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70,
				0x2e, 0x69, 0x6c, 0x20,	0x3a, 0x12, 0x68, 0x54};

  unsigned char text2[] = "what do ya want for nothing?";
  unsigned char key2[] = "Jefe";
  uint8_t expected2[] = {0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2,
			 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a,
			 0x7c, 0x79};
  uint8_t expected2_sha224[] = {0xa3, 0x0e, 0x01, 0x09, 0x8b, 0xc6, 0xdb, 0xbf,
				0x45, 0x69, 0x0f, 0x3a,	0x7e, 0x9e, 0x6d, 0x0f,
				0x8b, 0xbe, 0xa2, 0xa3, 0x9e, 0x61, 0x48, 0x00,
				0x8f, 0xd0, 0x5e, 0x44};
  uint8_t expected2_sha256[] = {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
				0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
				0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
				0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43};
  uint8_t expected2_sha384[] = {0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31,
				0x61, 0x7f, 0x78, 0xd2, 0xb5, 0x8a, 0x6b, 0x1b,
				0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47,
				0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22, 0x44, 0x5e,
				0x8e, 0x22, 0x40, 0xca,	0x5e, 0x69, 0xe2, 0xc7,
				0x8b, 0x32, 0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49};
  uint8_t expected2_sha512[] = {0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2,
				0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56, 0xe0, 0xa3,
				0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6,
				0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54,
				0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a,
				0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd,
				0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b,
				0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37};

  unsigned char text3[50];
  memset(text3, 0xdd, 50);
  unsigned char key3[20];
  memset(key3, 0xaa, 20);
  uint8_t expected3[] = {0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91,
			 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f, 0x63, 0xf1,
			 0x75, 0xd3};
  uint8_t expected3_sha224[] = {0x7f, 0xb3, 0xcb, 0x35, 0x88, 0xc6, 0xc1, 0xf6,
				0xff, 0xa9, 0x69, 0x4d,	0x7d, 0x6a, 0xd2, 0x64,
				0x93, 0x65, 0xb0, 0xc1, 0xf6, 0x5d, 0x69, 0xd1,
				0xec, 0x83, 0x33, 0xea};
  uint8_t expected3_sha256[] = {0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
				0x85, 0x4d, 0xb8, 0xeb,	0xd0, 0x91, 0x81, 0xa7,
				0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
				0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe};
  uint8_t expected3_sha384[] = {0x88, 0x06, 0x26, 0x08, 0xd3, 0xe6, 0xad, 0x8a,
				0x0a, 0xa2, 0xac, 0xe0,	0x14, 0xc8, 0xa8, 0x6f,
				0x0a, 0xa6, 0x35, 0xd9, 0x47, 0xac, 0x9f, 0xeb,
				0xe8, 0x3e, 0xf4, 0xe5, 0x59, 0x66, 0x14, 0x4b,
				0x2a, 0x5a, 0xb3, 0x9d,	0xc1, 0x38, 0x14, 0xb9,
				0x4e, 0x3a, 0xb6, 0xe1, 0x01, 0xa3, 0x4f, 0x27};
  uint8_t expected3_sha512[] = {0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84,
				0xef, 0xb0, 0xf0, 0x75, 0x6c, 0x89, 0x0b, 0xe9,
				0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36,
				0x55, 0xf8, 0x3e, 0x33, 0xb2, 0x27, 0x9d, 0x39,
				0xbf, 0x3e, 0x84, 0x82,	0x79, 0xa7, 0x22, 0xc8,
				0x06, 0xb4, 0x85, 0xa4, 0x7e, 0x67, 0xc8, 0x07,
				0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26,
				0x74, 0x27, 0x88, 0x59, 0xe1, 0x32, 0x92, 0xfb};

  unsigned char text4[50];
  memset(text4, 0xcd, 50);
  unsigned char key4[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
			  0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
			  0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
  uint8_t expected4[] = {0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6, 0xbc,
			 0x84, 0x14, 0xf9, 0xbf, 0x50, 0xc8, 0x6c, 0x2d, 0x72,
			 0x35, 0xda};
  uint8_t expected4_sha224[] = {0x6c, 0x11, 0x50, 0x68, 0x74, 0x01, 0x3c, 0xac,
				0x6a, 0x2a, 0xbc, 0x1b, 0xb3, 0x82, 0x62, 0x7c,
				0xec, 0x6a, 0x90, 0xd8, 0x6e, 0xfc, 0x01, 0x2d,
				0xe7, 0xaf, 0xec, 0x5a};
  uint8_t expected4_sha256[] = {0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e,
				0xa4, 0xcc, 0x81, 0x98,	0x99, 0xf2, 0x08, 0x3a,
				0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
				0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b};
  uint8_t expected4_sha384[] = {0x3e, 0x8a, 0x69, 0xb7, 0x78, 0x3c, 0x25, 0x85,
				0x19, 0x33, 0xab, 0x62,	0x90, 0xaf, 0x6c, 0xa7,
				0x7a, 0x99, 0x81, 0x48, 0x08, 0x50, 0x00, 0x9c,
				0xc5, 0x57, 0x7c, 0x6e, 0x1f, 0x57, 0x3b, 0x4e,
				0x68, 0x01, 0xdd, 0x23,	0xc4, 0xa7, 0xd6, 0x79,
				0xcc, 0xf8, 0xa3, 0x86, 0xc6, 0x74, 0xcf, 0xfb};
  uint8_t expected4_sha512[] = {0xb0, 0xba, 0x46, 0x56, 0x37, 0x45, 0x8c, 0x69,
				0x90, 0xe5, 0xa8, 0xc5,	0xf6, 0x1d, 0x4a, 0xf7,
				0xe5, 0x76, 0xd9, 0x7f, 0xf9, 0x4b, 0x87, 0x2d,
				0xe7, 0x6f, 0x80, 0x50, 0x36, 0x1e, 0xe3, 0xdb,
				0xa9, 0x1c, 0xa5, 0xc1, 0x1a, 0xa2, 0x5e, 0xb4,
				0xd6, 0x79, 0x27, 0x5c, 0xc5, 0x78, 0x80, 0x63,
				0xa5, 0xf1, 0x97, 0x41, 0x12, 0x0c, 0x4f, 0x2d,
				0xe2, 0xad, 0xeb, 0xeb, 0x10, 0xa2, 0x98, 0xdd};

  unsigned char text5[] = "Test With Truncation";
  unsigned char key5[20];
  memset(key5, 0x0c, 20);
  uint8_t expected5[] = {0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f, 0xe7,
			 0xf2, 0x7b, 0xe1, 0xd5, 0x8b, 0xb9, 0x32, 0x4a, 0x9a,
			 0x5a, 0x04};
  uint8_t expected5_sha224[] = {0x0e, 0x2a, 0xea, 0x68, 0xa9, 0x0c, 0x8d, 0x37,
				0xc9, 0x88, 0xbc, 0xdb,	0x9f, 0xca, 0x6f, 0xa8};
  uint8_t expected5_sha256[] = {0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0,
				0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b};
  uint8_t expected5_sha384[] = {0x3a, 0xbf, 0x34, 0xc3, 0x50, 0x3b, 0x2a, 0x23,
				0xa4, 0x6e, 0xfc, 0x61,	0x9b, 0xae, 0xf8, 0x97};
  uint8_t expected5_sha512[] = {0x41, 0x5f, 0xad, 0x62, 0x71, 0x58, 0x0a, 0x53,
				0x1d, 0x41, 0x79, 0xbc,	0x89, 0x1d, 0x87, 0xa6};

  /* RFC 2202 only requires 80 but RFC 4231 needs 131 so we make the key buffer 131 bytes */
  unsigned char text6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
  unsigned char key6[131];
  memset(key6, 0xaa, 131);
  uint8_t expected6[] = {0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95,
			 0x70, 0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55, 0xed, 0x40,
			 0x21, 0x12};
  uint8_t expected6_sha224[] = {0x95, 0xe9, 0xa0, 0xdb, 0x96, 0x20, 0x95, 0xad,
				0xae, 0xbe, 0x9b, 0x2d, 0x6f, 0x0d, 0xbc, 0xe2,
				0xd4, 0x99, 0xf1, 0x12, 0xf2, 0xd2, 0xb7, 0x27,
				0x3f, 0xa6, 0x87, 0x0e};
  uint8_t expected6_sha256[] = {0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
				0x0d, 0x8a, 0x26, 0xaa,	0xcb, 0xf5, 0xb7, 0x7f,
				0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
				0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54};
  uint8_t expected6_sha384[] = {0x4e, 0xce, 0x08, 0x44, 0x85, 0x81, 0x3e, 0x90,
				0x88, 0xd2, 0xc6, 0x3a,	0x04, 0x1b, 0xc5, 0xb4,
				0x4f, 0x9e, 0xf1, 0x01, 0x2a, 0x2b, 0x58, 0x8f,
				0x3c, 0xd1, 0x1f, 0x05, 0x03, 0x3a, 0xc4, 0xc6,
				0x0c, 0x2e, 0xf6, 0xab,	0x40, 0x30, 0xfe, 0x82,
				0x96, 0x24, 0x8d, 0xf1, 0x63, 0xf4, 0x49, 0x52};
  uint8_t expected6_sha512[] = {0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb,
				0xb7, 0x14, 0x93, 0xc1,	0xdd, 0x7b, 0xe8, 0xb4,
				0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1,
				0x12, 0x1b, 0x01, 0x37, 0x83, 0xf8, 0xf3, 0x52,
				0x6b, 0x56, 0xd0, 0x37,	0xe0, 0x5f, 0x25, 0x98,
				0xbd, 0x0f, 0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52,
				0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec,
				0x8b, 0x91, 0x5a, 0x98,	0x5d, 0x78, 0x65, 0x98};

  /* RFC 2202 test case 7 differs quite a lot from the rfc 4231 testcase 7 so they
   * will be kept separate
   */
  unsigned char text7[] = "Test Using Larger Than Block-Size Key and Larger "
    "Than One Block-Size Data";
  unsigned char key7[80];
  memset(key7, 0xaa, 80);
  uint8_t expected7[] = {0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78, 0x6d,
			 0x6b, 0xba, 0xa7, 0x96, 0x5c, 0x78, 0x08, 0xbb, 0xff,
			 0x1a, 0x91};

  unsigned char text7_rfc4231[] = "This is a test using a larger than "
    "block-size key and a larger than block-size data. The key needs to be "
    "hashed before being used by the HMAC algorithm.";
  unsigned char key7_rfc4231[131];
  memset(key7_rfc4231, 0xaa, 131);

  uint8_t expected7_sha224[] = {0x3a, 0x85, 0x41, 0x66, 0xac, 0x5d, 0x9f, 0x02,
				0x3f, 0x54, 0xd5, 0x17, 0xd0, 0xb3, 0x9d, 0xbd,
				0x94, 0x67, 0x70, 0xdb, 0x9c, 0x2b, 0x95, 0xc9,
				0xf6, 0xf5, 0x65, 0xd1};
  uint8_t expected7_sha256[] = {0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb,
				0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44,
				0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
				0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2};
  uint8_t expected7_sha384[] = {0x66, 0x17, 0x17, 0x8e, 0x94, 0x1f, 0x02, 0x0d,
				0x35, 0x1e, 0x2f, 0x25, 0x4e, 0x8f, 0xd3, 0x2c,
				0x60, 0x24, 0x20, 0xfe, 0xb0, 0xb8, 0xfb, 0x9a,
				0xdc, 0xce, 0xbb, 0x82, 0x46, 0x1e, 0x99, 0xc5,
				0xa6, 0x78, 0xcc, 0x31, 0xe7, 0x99, 0x17, 0x6d,
				0x38, 0x60, 0xe6, 0x11, 0x0c, 0x46, 0x52, 0x3e};
  uint8_t expected7_sha512[] = {0xe3, 0x7b, 0x6a, 0x77, 0x5d, 0xc8, 0x7d, 0xba,
				0xa4, 0xdf, 0xa9, 0xf9, 0x6e, 0x5e, 0x3f, 0xfd,
				0xde, 0xbd, 0x71, 0xf8, 0x86, 0x72, 0x89, 0x86,
				0x5d, 0xf5, 0xa3, 0x2d, 0x20, 0xcd, 0xc9, 0x44,
				0xb6, 0x02, 0x2c, 0xac, 0x3c, 0x49, 0x82, 0xb1,
				0x0d, 0x5e, 0xeb, 0x55, 0xc3, 0xe4, 0xde, 0x15,
				0x13, 0x46, 0x76, 0xfb, 0x6d, 0xe0, 0x44, 0x60,
				0x65, 0xc9, 0x74, 0x40, 0xfa, 0x8c, 0x6a, 0x58};

  TEST(("HMAC-SHA1 case 1"));
  res = hmac (SHA1, text1, 8, key1, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected1, 20) == 0);

  TEST(("HMAC-SHA-224 case 1"));
  res = hmac (SHA224, text1, 8, key1, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected1_sha224, sizeof(expected1_sha224)) == 0);

  TEST(("HMAC-SHA-256 case 1"));
  res = hmac (SHA256, text1, 8, key1, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected1_sha256, sizeof(expected1_sha256)) == 0);

  TEST(("HMAC-SHA-384 case 1"));
  res = hmac (SHA384, text1, 8, key1, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected1_sha384, sizeof(expected1_sha384)) == 0);

  TEST(("HMAC-SHA-512 case 1"));
  res = hmac (SHA512, text1, 8, key1, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected1_sha512, sizeof(expected1_sha512)) == 0);

  TEST(("HMAC-SHA1 case 2"));
  res = hmac (SHA1, text2, 28, key2, 4, result);
  assert(res == 0);
  assert(memcmp(result, expected2, 20) == 0);

  TEST(("HMAC-SHA-224 case 2"));
  res = hmac (SHA224, text2, 28, key2, 4, result);
  assert(res == 0);
  assert(memcmp(result, expected2_sha224, sizeof(expected2_sha224)) == 0);

  TEST(("HMAC-SHA-256 case 2"));
  res = hmac (SHA256, text2, 28, key2, 4, result);
  assert(res == 0);
  assert(memcmp(result, expected2_sha256, sizeof(expected2_sha256)) == 0);

  TEST(("HMAC-SHA-384 case 2"));
  res = hmac (SHA384, text2, 28, key2, 4, result);
  assert(res == 0);
  assert(memcmp(result, expected2_sha384, sizeof(expected2_sha384)) == 0);

  TEST(("HMAC-SHA-512 case 2"));
  res = hmac (SHA512, text2, 28, key2, 4, result);
  assert(res == 0);
  assert(memcmp(result, expected2_sha512, sizeof(expected1_sha512)) == 0);

  TEST(("HMAC-SHA1 case 3"));
  res = hmac (SHA1, text3, 50, key3, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected3, 20) == 0);

  TEST(("HMAC-SHA-224 case 3"));
  res = hmac (SHA224, text3, 50, key3, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected3_sha224, sizeof(expected3_sha224)) == 0);

  TEST(("HMAC-SHA-256 case 3"));
  res = hmac (SHA256, text3, 50, key3, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected3_sha256, sizeof(expected3_sha256)) == 0);

  TEST(("HMAC-SHA-384 case 3"));
  res = hmac (SHA384, text3, 50, key3, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected3_sha384, sizeof(expected3_sha384)) == 0);

  TEST(("HMAC-SHA-512 case 3"));
  res = hmac (SHA512, text3, 50, key3, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected3_sha512, sizeof(expected3_sha512)) == 0);

  TEST(("HMAC-SHA1 case 4"));
  res = hmac (SHA1, text4, 50, key4, 25, result);
  assert(res == 0);
  assert(memcmp(result, expected4, 20) == 0);

  TEST(("HMAC-SHA-224 case 4"));
  res = hmac (SHA224, text4, 50, key4, 25, result);
  assert(res == 0);
  assert(memcmp(result, expected4_sha224, sizeof(expected4_sha224)) == 0);

  TEST(("HMAC-SHA-256 case 4"));
  res = hmac (SHA256, text4, 50, key4, 25, result);
  assert(res == 0);
  assert(memcmp(result, expected4_sha256, sizeof(expected4_sha256)) == 0);

  TEST(("HMAC-SHA-384 case 4"));
  res = hmac (SHA384, text4, 50, key4, 25, result);
  assert(res == 0);
  assert(memcmp(result, expected4_sha384, sizeof(expected4_sha384)) == 0);

  TEST(("HMAC-SHA-512 case 4"));
  res = hmac (SHA512, text4, 50, key4, 25, result);
  assert(res == 0);
  assert(memcmp(result, expected4_sha512, sizeof(expected4_sha512)) == 0);

  TEST(("HMAC-SHA1 case 5"));
  res = hmac (SHA1, text5, 20, key5, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected5, 20) == 0);

  TEST(("HMAC-SHA-224 case 5"));
  res = hmac (SHA224, text5, 20, key5, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected5_sha224, sizeof(expected5_sha224)) == 0);

  TEST(("HMAC-SHA-256 case 5"));
  res = hmac (SHA256, text5, 20, key5, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected5_sha256, sizeof(expected5_sha256)) == 0);

  TEST(("HMAC-SHA-384 case 5"));
  res = hmac (SHA384, text5, 20, key5, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected5_sha384, sizeof(expected5_sha384)) == 0);

  TEST(("HMAC-SHA-512 case 5"));
  res = hmac (SHA512, text5, 20, key5, 20, result);
  assert(res == 0);
  assert(memcmp(result, expected5_sha512, sizeof(expected5_sha512)) == 0);

  /* the SHA1 test from rfc 2202 uses 80 bytes keysize */
  TEST(("HMAC-SHA1 case 6"));
  res = hmac (SHA1, text6, 54, key6, 80, result);
  assert(res == 0);
  assert(memcmp(result, expected6, 20) == 0);

  /* The tests from RFC 4231 uses a 131 bytes key (a key larger
   * than 128 bytes (= block-size of SHA-384 and SHA-512).
   */
  TEST(("HMAC-SHA-224 case 6"));
  res = hmac (SHA224, text6, 54, key6, 131, result);
  assert(res == 0);
  assert(memcmp(result, expected6_sha224, sizeof(expected6_sha224)) == 0);

  TEST(("HMAC-SHA-256 case 6"));
  res = hmac (SHA256, text6, 54, key6, 131, result);
  assert(res == 0);
  assert(memcmp(result, expected6_sha256, sizeof(expected6_sha256)) == 0);

  TEST(("HMAC-SHA-384 case 6"));
  res = hmac (SHA384, text6, 54, key6, 131, result);
  assert(res == 0);
  assert(memcmp(result, expected6_sha384, sizeof(expected6_sha384)) == 0);

  TEST(("HMAC-SHA-512 case 6"));
  res = hmac (SHA512, text6, 54, key6, 131, result);
  assert(res == 0);
  assert(memcmp(result, expected6_sha512, sizeof(expected6_sha512)) == 0);

  TEST(("HMAC-SHA1 case 7"));
  res = hmac (SHA1, text7, 73, key7, 80, result);
  assert(res == 0);
  assert(memcmp(result, expected7, 20) == 0);

  TEST(("HMAC-SHA-224 case 7"));
  res = hmac (SHA224, text7_rfc4231, strlen(text7_rfc4231), key7_rfc4231,
	      sizeof(key7_rfc4231), result);
  assert(res == 0);
  assert(memcmp(result, expected7_sha224, sizeof(expected7_sha224)) == 0);

  TEST(("HMAC-SHA-256 case 7"));
  res = hmac (SHA256, text7_rfc4231, strlen(text7_rfc4231), key7_rfc4231,
	      sizeof(key7_rfc4231), result);
  assert(res == 0);
  assert(memcmp(result, expected7_sha256, sizeof(expected7_sha256)) == 0);

  TEST(("HMAC-SHA-384 case 7"));
  res = hmac (SHA384, text7_rfc4231, strlen(text7_rfc4231), key7_rfc4231,
	      sizeof(key7_rfc4231), result);
  assert(res == 0);
  assert(memcmp(result, expected7_sha384, sizeof(expected7_sha384)) == 0);

  TEST(("HMAC-SHA-512 case 7"));
  res = hmac (SHA512, text7_rfc4231, strlen(text7_rfc4231), key7_rfc4231,
	      sizeof(key7_rfc4231), result);
  assert(res == 0);
  assert(memcmp(result, expected7_sha512, sizeof(expected7_sha512)) == 0);
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
    (ykc, "https://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s");

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

  TEST(("Set and use OLD V2.0 URL"));
  const char *templates[] = {
    "https://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
  };
  ykclient_set_url_templates(ykc, 1, templates);
  ykclient_set_client (ykc, client_id, 20, client_key);
#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("Set and use NEW V2.0 URL"));
  const char *bases[] = {
    "https://api.yubico.com/wsapi/2.0/verify",
  };
  ykclient_set_url_bases(ykc, 1, bases);
  ykclient_set_client (ykc, client_id, 20, client_key);
#ifndef TEST_WITHOUT_INTERNET
  ret = ykclient_request (ykc, "ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  assert (ret == YKCLIENT_REPLAYED_OTP);
#else
  printf ("Test SKIPPED\n");
#endif

  TEST(("Set a mix of bad and good URLs"));
  const char *bad_bases[] = {
    "https://api2.example.com/wsapi/2.0/verify",
    "https://api3.example.com/wsapi/2.0/verify",
    "https://api4.example.com/wsapi/2.0/verify",
    "https://api5.example.com/wsapi/2.0/verify",
    "https://api.yubico.com/wsapi/2.0/verify",
  };
  ykclient_set_url_bases(ykc, 5, bad_bases);
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

  test_base64();

  test_hmac();

  printf ("All tests passed\n");

  ykclient_global_done();

  return 0;
}
