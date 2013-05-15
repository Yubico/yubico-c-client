/* ykclient_server_response.h --- Server response parsing and validation.
 *
 * Written by Sebastien Martini <seb@dbzteam.org>.
 * Copyright (c) 2011-2013 Yubico AB
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

#ifndef YKCLIENT_SERVER_RESPONSE_H
#define YKCLIENT_SERVER_RESPONSE_H

#include <ykclient_errors.h>

/* Example:
     key:   status
     value: OK
*/
typedef struct ykclient_parameter_st
{
  char *key;
  char *value;
} ykclient_parameter_t;

typedef struct ykclient_parameters_st
{
  ykclient_parameter_t *parameter;
  struct ykclient_parameters_st *next;
} ykclient_parameters_t;

typedef struct ykclient_server_response_st
{
  ykclient_parameter_t *signature;
  ykclient_parameters_t *parameters;
} ykclient_server_response_t;


/* Returns NULL if it fails. */
extern ykclient_server_response_t *ykclient_server_response_init (void);

/* Frees allocated data structures. */
extern void ykclient_server_response_free (ykclient_server_response_t
					   * response);

/* Parses server's response and builds a list of parameters and isolates
   the corresponding signature parameter. Returns 0 if it succeeds. */
extern ykclient_rc
ykclient_server_response_parse (char *response,
				ykclient_server_response_t * serv_response);

/* Iterates the parameters buils a HMAC-SHA1 and checks it matches the
   signature returned by the server. This function returns 0 if the signature
   is valid, 1 otherwise. */
extern int
ykclient_server_response_verify_signature (const ykclient_server_response_t
					   * serv_response,
					   const char *key, int key_length);

/* Returns value associated to key or NULL if unmatched. The caller doesn't
   take ownership of the returned value. */
extern char *ykclient_server_response_get (const ykclient_server_response_t *
					   serv_response, const char *key);

#endif /* YKCLIENT_SERVER_RESPONSE_H */
