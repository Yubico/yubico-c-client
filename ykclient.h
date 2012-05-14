/* ykclient.h --- Prototypes for Yubikey OTP validation client library.
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

#ifndef YKCLIENT_H
#define YKCLIENT_H

#include <stdint.h>
#include <string.h>

# ifdef __cplusplus
extern "C"
{
# endif

typedef enum
{
  /* Official yubikey client API errors. */
  YKCLIENT_OK = 0,
  YKCLIENT_BAD_OTP,
  YKCLIENT_REPLAYED_OTP,
  YKCLIENT_BAD_SIGNATURE,
  YKCLIENT_MISSING_PARAMETER,
  YKCLIENT_NO_SUCH_CLIENT,
  YKCLIENT_OPERATION_NOT_ALLOWED,
  YKCLIENT_BACKEND_ERROR,
  YKCLIENT_NOT_ENOUGH_ANSWERS,
  YKCLIENT_REPLAYED_REQUEST,
  /* Other implementation specific errors. */
  YKCLIENT_OUT_OF_MEMORY = 100,
  YKCLIENT_PARSE_ERROR,
  YKCLIENT_FORMAT_ERROR,
  YKCLIENT_CURL_INIT_ERROR,
  YKCLIENT_HMAC_ERROR,
  YKCLIENT_HEX_DECODE_ERROR,
  YKCLIENT_BAD_SERVER_SIGNATURE,
  YKCLIENT_NOT_IMPLEMENTED,
  YKCLIENT_CURL_PERFORM_ERROR,
  YKCLIENT_BAD_INPUT
} ykclient_rc;

typedef struct ykclient_st ykclient_t;

extern int ykclient_init (ykclient_t ** ykc);

extern void ykclient_done (ykclient_t ** ykc);

/* If value is 0 the authenticity of the signature returned by the
   server in response to the request won't be verified. */
extern void ykclient_set_verify_signature (ykclient_t * ykc, int value);

extern const char *ykclient_strerror (int ret);

extern void ykclient_set_client (ykclient_t * ykc,
				 unsigned int client_id,
				 size_t keylen, const char *key);

extern int ykclient_set_client_hex (ykclient_t * ykc,
				    unsigned int client_id, const char *key);

extern int ykclient_set_client_b64 (ykclient_t * ykc,
				    unsigned int client_id, const char *key);

extern void ykclient_set_url_template (ykclient_t * ykc,
				       const char *url_template);

extern int ykclient_set_url_templates (ykclient_t * ykc,
				       size_t num_templates, const char **url_templates);

/* By default the signature returned by the server is verified (modify
   this choice by calling ykclient_set_verify_signature()). */
extern void ykclient_set_ca_path (ykclient_t * ykc, const char *ca_path);

/*
 * Set the nonce. A default nonce is generated in ykclient_init(), but
 * if you either want to specify your own nonce, or want to remove the
 * nonce (needed to send signed requests to v1 validation servers),
 * you must call this function. Set nonce to NULL to disable it.
 */
extern void ykclient_set_nonce (ykclient_t * ykc, char *nonce);

extern int ykclient_request (ykclient_t * ykc, const char *yubikey_otp);

extern const char *ykclient_get_last_url (ykclient_t * ykc);

/* One call interface for validation protocol 1.x, with default URL. */
extern int ykclient_verify_otp (const char *yubikey_otp,
				unsigned int client_id, const char *hexkey);

/* One call interface for validation protocol 2.0 and/or non-default URL. */
extern int ykclient_verify_otp_v2 (ykclient_t * ykc_in,
				   const char *yubikey_otp,
				   unsigned int client_id,
				   const char *hexkey,
				   size_t urlcount,
				   const char **urls, const char *api_key);

# ifdef __cplusplus
}
# endif

#endif
