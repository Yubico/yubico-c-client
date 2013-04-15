/* ykclient_errors.h --- Error codes used by ykclient.
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

#ifndef YKCLIENT_ERRORS_H
#define YKCLIENT_ERRORS_H

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
  YKCLIENT_BASE64_DECODE_ERROR,
  YKCLIENT_BAD_SERVER_SIGNATURE,
  YKCLIENT_NOT_IMPLEMENTED,
  YKCLIENT_CURL_PERFORM_ERROR,
  YKCLIENT_BAD_INPUT,
  YKCLIENT_HANDLE_NOT_REINIT
} ykclient_rc;

#endif
