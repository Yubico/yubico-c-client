/* selftest.c --- Self-tests for Yubico client library.
 *
 * Written by Simon Josefsson <simon@josefsson.org>.
 * Copyright (c) 2006, 2007, 2008 Yubico AB
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

#include <libykclient.h>
#include <stdio.h>

int
main (void)
{
  yubikey_client_t c;
  int ret;

  c = yubikey_client_init ();

  yubikey_client_set_info (c, 16, 6, "foobar");

  ret = yubikey_client_request (c, "dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh");

  printf ("return code (%d): %s\n", ret, yubikey_client_strerror (ret));

  yubikey_client_done (&c);

  printf ("strerror(0): %s\n", yubikey_client_strerror (0));
  printf ("strerror(BAD_OTP): %s\n",
	  yubikey_client_strerror (YUBIKEY_CLIENT_BAD_OTP));

  printf ("\nAll tests successful\n");

  return 0;
}
