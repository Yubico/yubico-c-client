/* ykclient_server_response.c --- Server response parsing and validation.
 *
 * Written by Sebastien Martini <seb@dbzteam.org>.
 * Copyright (c) 2011-2012 Yubico AB
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

#include "ykclient_server_response.h"

#include "ykclient.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rfc4634/sha.h"
#include "b64/cdecode.h"


/* Parameters' manipulation functions */

static void
parameter_free (ykclient_parameter_t * param)
{
  if (param == NULL)
    return;

  if (param->key)
    free (param->key);
  if (param->value)
    free (param->value);

  free (param);
}

/* Inserts elem in front of params. */
static void
list_parameter_insert_front (ykclient_parameters_t ** params,
			     ykclient_parameter_t * elem)
{
  if (params == NULL || elem == NULL)
    return;

  ykclient_parameters_t *new_node = malloc (sizeof (ykclient_parameters_t));
  if (new_node == NULL)
    return;
  memset (new_node, 0, (sizeof (ykclient_parameters_t)));

  new_node->parameter = elem;
  new_node->next = NULL;

  if (*params == NULL)
    {
      *params = new_node;
      return;
    }

  new_node->next = *params;
  *params = new_node;
}

/* Keys comparison function. It compares two keys, and returns 1 if
   the first precedes the second. */
static int
alphanum_less_than (const ykclient_parameter_t * rhs,
		    const ykclient_parameter_t * lhs)
{
  if (rhs == NULL || lhs == NULL)
    return -1;

  if (strcmp (rhs->key, lhs->key) < 0)
    return 1;
  return 0;
}

/* Inserts elem into params. The position where elem must inserted is
   determined by cmp_func. cmp_func must be a strict weak ordering binary
   predicate. */
static void
list_parameter_insert_ord (ykclient_parameters_t ** params,
			   ykclient_parameter_t * elem,
			   int (*cmp_func) (const ykclient_parameter_t * rhs,
					    const ykclient_parameter_t * lhs))
{
  if (elem == NULL)
    return;

  ykclient_parameters_t *iter = *params;
  ykclient_parameters_t *prev = NULL;

  for (; iter != NULL; iter = iter->next)
    {
      const int result = cmp_func (elem, iter->parameter);
      if (result == -1)
	return;			/* error */
      if (result == 1)
	break;
      prev = iter;
    }

  list_parameter_insert_front (&iter, elem);
  if (prev != NULL)
    prev->next = iter;
  else
    *params = iter;
}

static void
list_parameter_free (ykclient_parameters_t * params)
{
  ykclient_parameters_t *iter = params;
  while (iter != NULL)
    {
      parameter_free (iter->parameter);
      ykclient_parameters_t *current = iter;
      iter = iter->next;
      free (current);
    }
}


/* Server's response functions */

ykclient_server_response_t *
ykclient_server_response_init (void)
{
  ykclient_server_response_t *serv_response =
    malloc (sizeof (ykclient_server_response_t));
  if (serv_response == NULL)
    return NULL;
  memset (serv_response, 0, (sizeof (ykclient_server_response_t)));
  serv_response->signature = NULL;
  serv_response->parameters = NULL;
  return serv_response;
}

void
ykclient_server_response_free (ykclient_server_response_t * response)
{
  if (response == NULL)
    return;
  list_parameter_free (response->parameters);
  parameter_free (response->signature);
  free (response);
}


/* Server's response parsing functions */

/* Returns 1 if c is a whitespace or a line break character, 0 otherwise. */
static int
is_ws_or_lb (char c)
{
  switch (c)
    {
      /* Line breaks */
    case '\n':
    case '\r':
      /* Spaces */
    case ' ':
    case '\t':
      return 1;
    default:
      return 0;
    }
  return 0;
}

/* Trims leading whitespaces and line breaks. */
static void
trim_ws_and_lb (char **s)
{
  if (s == NULL || *s == NULL)
    return;

  char *pos = *s;
  while (*pos != '\0' && is_ws_or_lb (*pos))
    ++pos;
  *s = pos;
}

/* Parses and builds the next parameter param from s, moves response's pointer
   to the immediate right character. Returns 0 if it succeeds. */
static ykclient_rc
parse_next_parameter (char **s, ykclient_parameter_t * param)
{
  if (s == NULL || *s == NULL || param == NULL)
    return YKCLIENT_PARSE_ERROR;
  char *pos = *s;
  int index = 0;

  /* key parsing */
  while (*(pos + index) != '\0' && *(pos + index) != '=')
    ++index;
  if (*(pos + index) == '\0')
    return YKCLIENT_PARSE_ERROR;

  param->key = malloc (index + 1);
  if (param->key == NULL)
    {
      return YKCLIENT_OUT_OF_MEMORY;
    }
  strncpy (param->key, pos, index);
  param->key[index] = '\0';

  /* value parsing */
  pos += index + 1;
  index = 0;
  while (*(pos + index) != '\0' && !is_ws_or_lb (*(pos + index)))
    ++index;
  if (*(pos + index) == '\0')
    {
      parameter_free (param);
      return YKCLIENT_PARSE_ERROR;
    }

  param->value = malloc (index + 1);
  if (param->value == NULL)
    {
      parameter_free (param);
      return YKCLIENT_OUT_OF_MEMORY;
    }
  strncpy (param->value, pos, index);
  param->value[index] = '\0';

  pos += index;
  *s = pos;
  return 0;
}

ykclient_rc
ykclient_server_response_parse (char *response,
				ykclient_server_response_t * serv_response)
{
  if (response == NULL || serv_response == NULL)
    return YKCLIENT_PARSE_ERROR;

  trim_ws_and_lb (&response);
  while (*response != '\0')
    {
      ykclient_parameter_t *param = malloc (sizeof (ykclient_parameter_t));
      if (param == NULL)
	return YKCLIENT_OUT_OF_MEMORY;
      memset (param, 0, (sizeof (ykclient_parameter_t)));
      int ret = parse_next_parameter (&response, param);
      if (ret)
	return ret;

      if (!strcmp (param->key, "h"))
	serv_response->signature = param;
      else
	/* Parameters are alphanumerically ordered. */
	list_parameter_insert_ord (&serv_response->parameters, param,
				   alphanum_less_than);
      trim_ws_and_lb (&response);
    }

  /* We expect at least one parameter along its mandatory signature. */
  if (serv_response->signature == NULL)
    return YKCLIENT_BAD_SERVER_SIGNATURE;
  if (serv_response->parameters == NULL)
    return YKCLIENT_PARSE_ERROR;
  return 0;
}

int
ykclient_server_response_verify_signature (const ykclient_server_response_t *
					   serv_response, const char *key,
					   int key_length)
{
  if (serv_response == NULL || key == NULL || key_length < 0)
    return 1;

  HMACContext ctx;
  if (hmacReset (&ctx, SHA1, (const unsigned char *) key, key_length))
    return 1;

  /* Iterate over parameters and feed the hmac. */
  ykclient_parameters_t *iter = serv_response->parameters;
  for (; iter != NULL; iter = iter->next)
    {
      if (hmacInput (&ctx, (unsigned char *) iter->parameter->key,
		     strlen (iter->parameter->key)))
	return 1;
      if (hmacInput (&ctx, (const unsigned char *) "=", 1))
	return 1;
      if (hmacInput (&ctx, (unsigned char *) iter->parameter->value,
		     strlen (iter->parameter->value)))
	return 1;
      if (iter->next != NULL
	  && hmacInput (&ctx, (const unsigned char *) "&", 1))
	return 1;
    }

  uint8_t digest[SHA1HashSize + 1];
  if (hmacResult (&ctx, digest))
    return 1;

  if (serv_response->signature == NULL ||
      serv_response->signature->value == NULL)
    return 1;

  char server_digest[SHA1HashSize + 1];
  base64_decodestate b64;
  base64_init_decodestate (&b64);
  if (base64_decode_block (serv_response->signature->value,
			   strlen (serv_response->signature->value),
			   server_digest, &b64) != SHA1HashSize)
    return 1;

  if (memcmp (server_digest, digest, SHA1HashSize) != 0)
    return 1;
  return 0;
}

char *
ykclient_server_response_get (const ykclient_server_response_t *
			      serv_response, const char *key)
{
  if (serv_response == NULL || key == NULL)
    return NULL;

  ykclient_parameters_t *iter = serv_response->parameters;
  for (; iter != NULL; iter = iter->next)
    if (!strcmp (iter->parameter->key, key))
      return iter->parameter->value;
  return NULL;
}
