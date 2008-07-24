/* libykclient.h --- Definitions and prototypes for Yubico client library.
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

#ifndef YUBIKEY_CLIENT_H
# define YUBIKEY_CLIENT_H

# include <stdint.h>
# include <string.h>

typedef enum {
  /* Official yubikey client API errors. */
  YUBIKEY_CLIENT_OK = 0,
  YUBIKEY_CLIENT_BAD_OTP,
  YUBIKEY_CLIENT_REPLAYED_OTP,
  YUBIKEY_CLIENT_BAD_SIGNATURE,
  YUBIKEY_CLIENT_MISSING_PARAMETER,
  YUBIKEY_CLIENT_NO_SUCH_CLIENT,
  YUBIKEY_CLIENT_OPERATION_NOT_ALLOWED,
  YUBIKEY_CLIENT_BACKEND_ERROR,
  /* Other implementation specific errors. */
  YUBIKEY_CLIENT_OUT_OF_MEMORY = 100,
  YUBIKEY_CLIENT_PARSE_ERROR
} yubikey_client_rc;

typedef struct yubikey_client_st *yubikey_client_t;

yubikey_client_t yubikey_client_init (void);
void yubikey_client_done (yubikey_client_t *client);

void
yubikey_client_set_info (yubikey_client_t client,
			 unsigned int client_id,
			 size_t keylen,
			 const char *key);

const char *yubikey_client_strerror (int ret);

int yubikey_client_request (yubikey_client_t client, const char *yubikey);

/* One call interface. */
int
yubikey_client_simple_request (const char *yubikey,
			       unsigned int client_id,
			       size_t keylen,
			       const char *key);

#endif
