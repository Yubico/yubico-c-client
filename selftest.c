/* selftest.c --- Self-tests for Yubico client library.
 *
 * Written by Simon Josefsson <simon@josefsson.org>.
 * Copyright (c) 2006, 2007, 2008, 2009 Yubico AB
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

#include <ykclient.h>
#include <stdio.h>

int
main (void)
{
  int client_id = 1851;
  char client_key[] = {
    0xa0, 0x15, 0x5b, 0x36, 0xde, 0xc8, 0x65, 0xe8, 0x59, 0x19,
    0x1f, 0x7d, 0xae, 0xfa, 0xbc, 0x77, 0xa4, 0x59, 0xd4, 0x33
  };
  ykclient_t *ykc;
  int ret;

  ret = ykclient_init (&ykc);
  printf ("ykclient_init (%d): %s\n", ret, ykclient_strerror (ret));
  if (ret != YKCLIENT_OK)
    return 1;

  ykclient_set_client (ykc, client_id, 0, NULL);

  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  if (ret != YKCLIENT_REPLAYED_OTP)
    return 1;

  ykclient_set_client (ykc, client_id, 20, client_key);

  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("ykclient_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  if (ret != YKCLIENT_REPLAYED_OTP)
    return 1;

  /* Same URL used by library, somewhat silly but still verifies the
     code path. */
  ykclient_set_url_template
    (ykc, "http://api.yubico.com/wsapi/verify?id=%d&otp=%s");

  ret = ykclient_request (ykc, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");
  printf ("yubikey_request (%d): %s\n", ret, ykclient_strerror (ret));
  printf ("used url: %s\n", ykclient_get_last_url (ykc));
  if (ret != YKCLIENT_REPLAYED_OTP)
    return 1;

  ykclient_done (&ykc);

  printf ("strerror(0): %s\n", ykclient_strerror (0));
  printf ("strerror(BAD_OTP): %s\n", ykclient_strerror (YKCLIENT_BAD_OTP));

  return 0;
}
