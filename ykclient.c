/* ykclient.c --- Implementation of Yubikey OTP validation client library.
 *
 * Written by Simon Josefsson <simon@josefsson.org>.
 * Copyright (c) 2006, 2007, 2008, 2009, 2011 Yubico AB
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

#include "ykclient_server_response.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

#include <curl/curl.h>

#include "rfc4634/sha.h"
#include "b64/cencode.h"
#include "b64/cdecode.h"

#define NONCE_LEN 32

struct ykclient_st
{
  CURL *curl;
  const char *ca_path;
  const char *url_template;
  char *url;
  unsigned int client_id;
  size_t keylen;
  const char *key;
  char *key_buf;
  char *nonce;
  char *curl_chunk;
  size_t curl_chunk_size;
  int verify_signature;
};

int
ykclient_init (ykclient_t **ykc)
{
  ykclient_t *p;

  p = malloc (sizeof (*p));

  if (!p)
    return YKCLIENT_OUT_OF_MEMORY;

  p->curl = curl_easy_init ();
  if (!p->curl)
    {
      free (p);
      return YKCLIENT_CURL_INIT_ERROR;
    }

  p->ca_path = NULL;
  p->url_template = NULL;
  p->url = NULL;

  p->curl_chunk = NULL;
  p->curl_chunk_size = 0;

  p->key = NULL;
  p->keylen = 0;
  p->key_buf = NULL;

  /* Generate a random 'nonce' value */
  {
    int i = 0;
    struct timeval tv;

    p->nonce = malloc (NONCE_LEN + 1);
    if (!p->nonce)
      return YKCLIENT_OUT_OF_MEMORY;\

    gettimeofday(&tv, 0);
    srandom (tv.tv_sec * tv.tv_usec);

    for (i = 0; i < NONCE_LEN; ++i)
      {
        p->nonce[i] = (random () % 26) + 'a';
      }

    p->nonce[NONCE_LEN] = 0;
  }

  /* Verification of server signature can only be done if there is
   * an API key provided
   */
  p->verify_signature = 0;

  *ykc = p;

  return YKCLIENT_OK;
}

void
ykclient_done (ykclient_t **ykc)
{
  if (ykc && *ykc)
    {
      curl_easy_cleanup ((*ykc)->curl);
      free ((*ykc)->nonce);
      free ((*ykc)->url);
      free ((*ykc)->curl_chunk);
      free ((*ykc)->key_buf);
      free (*ykc);
    }
  if (ykc)
    *ykc = NULL;
}

void
ykclient_set_verify_signature (ykclient_t *ykc,
                               int value)
{
  if (ykc == NULL)
    return;
  ykc->verify_signature = value;
}

void
ykclient_set_client (ykclient_t *ykc,
		     unsigned int client_id,
		     size_t keylen,
		     const char *key)
{
  ykc->client_id = client_id;
  ykc->keylen = keylen;
  ykc->key = key;
}

int
ykclient_set_client_hex (ykclient_t *ykc,
			 unsigned int client_id,
			 const char *key)
{
  size_t i;
  size_t key_len;
  size_t bin_len;

  ykc->client_id = client_id;

  if (key == NULL)
    return YKCLIENT_OK;

  key_len = strlen (key);

  if (key_len % 2 != 0)
    return YKCLIENT_HEX_DECODE_ERROR;

  bin_len = key_len / 2;

  free (ykc->key_buf);
  ykc->key_buf = malloc (bin_len);
  if (!ykc->key_buf)
    return YKCLIENT_OUT_OF_MEMORY;

  for (i = 0; i < bin_len; i++)
    {
      int tmp;

      if (sscanf (&key[2*i], "%02x", &tmp) != 1)
	{
	  free (ykc->key_buf);
	  ykc->key_buf = NULL;
	  return YKCLIENT_HEX_DECODE_ERROR;
	}

      ykc->key_buf[i] = tmp;
    }

  ykc->keylen = bin_len;
  ykc->key = ykc->key_buf;

  return YKCLIENT_OK;
}

int
ykclient_set_client_b64 (ykclient_t *ykc,
			 unsigned int client_id,
			 const char *key)
{
  size_t key_len;
  base64_decodestate b64;

  ykc->client_id = client_id;

  if (key == NULL)
    return YKCLIENT_OK;

  key_len = strlen (key);

  free (ykc->key_buf);
  ykc->key_buf = malloc (key_len + 1);
  if (!ykc->key_buf)
    return YKCLIENT_OUT_OF_MEMORY;

  base64_init_decodestate(&b64);
  ykc->keylen = base64_decode_block(key, key_len, ykc->key_buf, &b64);
  ykc->key = ykc->key_buf;

  return YKCLIENT_OK;
}

void
ykclient_set_ca_path (ykclient_t *ykc,
			   const char *ca_path)
{
  ykc->ca_path = ca_path;
}

void
ykclient_set_url_template (ykclient_t *ykc,
			   const char *url_template)
{
  ykc->url_template = url_template;
}

/*
 * Simple API to validate an OTP (hexkey) using the YubiCloud validation
 * service.
 */
int
ykclient_verify_otp (const char *yubikey_otp,
		     unsigned int client_id,
		     const char *hexkey)
{
  return ykclient_verify_otp_v2 (NULL,
				 yubikey_otp,
				 client_id,
				 hexkey,
				 0,
				 NULL,
				 NULL);
}

/*
 * Extended API to validate an OTP (hexkey) using either the YubiCloud
 * validation service, or any other validation service.
 *
 * Special CURL settings can be achieved by passing a non-null ykc_in.
 */
int
ykclient_verify_otp_v2 (ykclient_t *ykc_in,
			const char *yubikey_otp,
			unsigned int client_id,
			const char *hexkey,
			size_t urlcount,
			const char **urls,
			const char *api_key)
{
  ykclient_t *ykc;
  int ret;

  /* We currently only support 0 (for default YubiCloud URL) or 1 URL argument,
   * but this function is prepared to support all of Validation protocol 2.0,
   * which supports multiple parallell querys to multiple validation URLs.
   */
  if (urlcount > 1)
    return YKCLIENT_NOT_IMPLEMENTED;

  if (ykc_in == NULL)
    {
      ret = ykclient_init (&ykc);
      if (ret != YKCLIENT_OK)
	return ret;
    }
  else
    {
      ykc = ykc_in;
    }

  ykclient_set_client_hex (ykc, client_id, hexkey);

  if (urlcount == 1)
    ykclient_set_url_template (ykc, urls[0]);

  if (api_key)
    {
      ykclient_set_verify_signature (ykc, 1);
      ykclient_set_client_b64 (ykc, client_id, api_key);
    }

  ret = ykclient_request (ykc, yubikey_otp);

  if (ykc_in == NULL)
    ykclient_done (&ykc);

  return ret;
}

const char *
ykclient_strerror (int ret)
{
  const char *p;

  switch (ret)
    {
    case YKCLIENT_OK:
      p = "Success";
      break;

    case YKCLIENT_CURL_PERFORM_ERROR:
      p = "Error performing curl";
      break;

    case YKCLIENT_BAD_OTP:
      p = "Yubikey OTP was bad (BAD_OTP)";
      break;

    case YKCLIENT_REPLAYED_OTP:
      p = "Yubikey OTP was replayed (REPLAYED_OTP)";
      break;

    case YKCLIENT_REPLAYED_REQUEST:
      p = "Yubikey request was replayed (REPLAYED_REQUEST)";
      break;

    case YKCLIENT_BAD_SIGNATURE:
      p = "Request signature was invalid (BAD_SIGNATURE)";
      break;

    case YKCLIENT_BAD_SERVER_SIGNATURE:
      p = "Server response signature was invalid (BAD_SERVER_SIGNATURE)";
      break;

    case YKCLIENT_MISSING_PARAMETER:
      p = "Request was missing a parameter (MISSING_PARAMETER)";
      break;

    case YKCLIENT_NO_SUCH_CLIENT:
      p = "Client identity does not exist (NO_SUCH_CLIENT)";
      break;

    case YKCLIENT_OPERATION_NOT_ALLOWED:
      p = "Authorization denied (OPERATION_NOT_ALLOWED)";
      break;

    case YKCLIENT_BACKEND_ERROR:
      p = "Internal server error (BACKEND_ERROR)";
      break;

    case YKCLIENT_NOT_ENOUGH_ANSWERS:
      p = "Too few validation servers available (NOT_ENOUGH_ANSWERS)";
      break;

    case YKCLIENT_OUT_OF_MEMORY:
      p = "Out of memory";
      break;

    case YKCLIENT_PARSE_ERROR:
      p = "Could not parse server response";
      break;

    case YKCLIENT_FORMAT_ERROR:
      p = "Internal printf format error";
      break;

    case YKCLIENT_CURL_INIT_ERROR:
      p = "Error initializing curl";
      break;

    case YKCLIENT_HMAC_ERROR:
      p = "HMAC signature validation/generation error";
      break;

    case YKCLIENT_HEX_DECODE_ERROR:
      p = "Error decoding hex string";
      break;

    case YKCLIENT_NOT_IMPLEMENTED:
      p = "Not implemented";
      break;

    default:
      p = "Unknown error";
      break;
    }

  return p;
}

const char *
ykclient_get_last_url (ykclient_t *ykc)
{
  return ykc->url;
}

static size_t
curl_callback (void *ptr, size_t size, size_t nmemb, void *data)
{
  ykclient_t *ykc = (ykclient_t*) data;
  size_t realsize = size * nmemb;
  char *p;

  if (ykc->curl_chunk)
    p = realloc (ykc->curl_chunk, ykc->curl_chunk_size + realsize + 1);
  else
    p = malloc (ykc->curl_chunk_size + realsize + 1);

  if (!p)
    return -1;

  ykc->curl_chunk = p;

  memcpy(&(ykc->curl_chunk[ykc->curl_chunk_size]), ptr, realsize);
  ykc->curl_chunk_size += realsize;
  ykc->curl_chunk[ykc->curl_chunk_size] = 0;

  return realsize;
}

int
ykclient_request (ykclient_t *ykc,
		  const char *yubikey)
{
  const char *url_template = ykc->url_template;
  char *user_agent = NULL;
  char *status;
  int out;

  if (!url_template)
    url_template = "http://api.yubico.com/wsapi/verify?id=%d&otp=%s";

  free (ykc->curl_chunk);
  ykc->curl_chunk_size = 0;
  ykc->curl_chunk = NULL;

  {
    size_t len = strlen (url_template) + strlen (yubikey) + 20;
    size_t wrote;

    free (ykc->url);
    ykc->url = malloc (len);
    if (!ykc->url)
      return YKCLIENT_OUT_OF_MEMORY;
    wrote = snprintf (ykc->url, len, url_template,
		      ykc->client_id, yubikey);
    if (wrote < 0 || wrote > len)
      return YKCLIENT_FORMAT_ERROR;
  }

  if (ykc->nonce)
    {
      /* Create new URL with nonce in it. */
      char *url, *otp_offset;
      size_t len;
      int wrote;

#define ADD_NONCE "&nonce="
      len = strlen (ykc->url) + strlen (ADD_NONCE) + strlen (ykc->nonce) + 1;
      url = malloc (len);
      if (!url)
	return YKCLIENT_OUT_OF_MEMORY;

      /* Find the &otp= in ykc->url and insert ?nonce= before otp. Must get
       *  sorted headers since we calculate HMAC on the result.
       *
       * XXX this will break if the validation protocol gets a parameter that
       * sorts in between "nonce" and "otp", because the headers we sign won't
       * be alphabetically sorted if we insert the nonce between "nz" and "otp".
       * Also, we assume that everyone will have at least one parameter ("id=")
       * before "otp" so there is no need to search for "?otp=".
       */
      otp_offset = strstr (ykc->url, "&otp=");
      if (otp_offset == NULL)
	otp_offset = ykc->url + len;  // point at \0 at end of url in case there is no otp

      /* break up ykc->url where we want to insert nonce */
      *otp_offset = 0;

      wrote = snprintf (url, len, "%s" ADD_NONCE "%s&%s", ykc->url, ykc->nonce, otp_offset + 1);
      if (wrote + 1 != len)
	return YKCLIENT_FORMAT_ERROR;

      free (ykc->url);
      ykc->url = url;
    }

  if (ykc->key && ykc->keylen)
    {
      uint8_t digest[USHAMaxHashSize];
      char b64dig[3*4*SHA1HashSize+1];
      base64_encodestate b64;
      char *text;
      int res, res2;

      /* Find parameters to sign. */
      text = strchr (ykc->url, '?');
      if (!text)
	return YKCLIENT_PARSE_ERROR;
      text++;

      /* HMAC data. */
      res = hmac (SHA1, (unsigned char*) text, strlen (text),
		  (unsigned char*) ykc->key, ykc->keylen, digest);
      if (res != shaSuccess)
	return YKCLIENT_HMAC_ERROR;

      /* Base64 signature. */
      base64_init_encodestate(&b64);
      res = base64_encode_block((char*)digest, SHA1HashSize, b64dig, &b64);
      res2 = base64_encode_blockend(&b64dig[res], &b64);
      b64dig[res+res2-1] = '\0';

      /* Escape + into %2B. */
      {
	char *p;

	while ((p = strchr (b64dig, '+')))
	  {
	    memmove (p+3, p+1, strlen (p));
	    memcpy (p, "%2B", 3);
	  }
      }

      /* Create new URL with signature ( h= ) appended to it . */
      {
	char *url;
	size_t len;
	int wrote;

#define ADD_HASH "&h="
	len = strlen (ykc->url) + strlen (ADD_HASH) + strlen (b64dig) + 1;
	url = malloc (len);
	if (!url)
	  return YKCLIENT_OUT_OF_MEMORY;

	wrote = snprintf (url, len, "%s" ADD_HASH "%s", ykc->url, b64dig);
	if (wrote + 1 != len)
	  return YKCLIENT_FORMAT_ERROR;
	free (ykc->url);
	ykc->url = url;
      }
    }

  if(ykc->ca_path)
    {
      curl_easy_setopt (ykc->curl, CURLOPT_CAPATH, ykc->ca_path);
    }

  curl_easy_setopt (ykc->curl, CURLOPT_URL, ykc->url);
  curl_easy_setopt (ykc->curl, CURLOPT_WRITEFUNCTION, curl_callback);
  curl_easy_setopt (ykc->curl, CURLOPT_WRITEDATA, (void *) ykc);

  {
    size_t len = strlen (PACKAGE) + 1 + strlen (PACKAGE_VERSION) + 1;
    user_agent = malloc (len);
    if (!user_agent)
      return YKCLIENT_OUT_OF_MEMORY;
    if (snprintf (user_agent, len, "%s/%s", PACKAGE, PACKAGE_VERSION) > 0)
      curl_easy_setopt(ykc->curl, CURLOPT_USERAGENT, user_agent);
  }

  CURLcode curl_ret = curl_easy_perform (ykc->curl);

  if (curl_ret != CURLE_OK)
    {
      out = YKCLIENT_CURL_PERFORM_ERROR;
      goto done;
    }

  if (ykc->curl_chunk_size == 0 || ykc->curl_chunk == NULL)
    {
      out = YKCLIENT_PARSE_ERROR;
      goto done;
    }

  ykclient_server_response_t *serv_response = ykclient_server_response_init();
  if (serv_response == NULL)
    {
      out = YKCLIENT_PARSE_ERROR;
      goto done;
    }

  int parse_ret = ykclient_server_response_parse(ykc->curl_chunk,
                                                 serv_response);
  if (parse_ret)
    {
      out = parse_ret;
      goto done;
    }

  if (ykc->verify_signature != 0 &&
      ykclient_server_response_verify_signature(serv_response,
                                                ykc->key, ykc->keylen))
    {
      out = YKCLIENT_BAD_SERVER_SIGNATURE;
      goto done;
    }

  /* Verify that the nonce we put in our request is echoed in the response.
   *
   * This is to protect us from a man in the middle sending us a previously
   * seen genuine response again (such as an status=OK response even though
   * the real server will respond status=REPLAYED_OTP in a few milliseconds.
   */
  if (ykc->nonce)
    {
      char *server_nonce = ykclient_server_response_get(serv_response, "nonce");
      if(server_nonce == NULL || strcmp(ykc->nonce, server_nonce))
	{
	  out = YKCLIENT_HMAC_ERROR;
	  goto done;
	}
    }

  /* Verify that the OTP we put in our request is echoed in the response.
   *
   * Same reason as ykc->nonce above.
   */
    {
      char *server_otp = ykclient_server_response_get(serv_response, "otp");
      if(server_otp == NULL || strcmp(yubikey, server_otp))
	{
	  out = YKCLIENT_HMAC_ERROR;
	  goto done;
	}
    }

  status = ykclient_server_response_get(serv_response, "status");
  if (!status)
    {
      out = YKCLIENT_PARSE_ERROR;
      goto done;
    }

  if (strcmp (status, "OK") == 0)
    {
      out = YKCLIENT_OK;
      goto done;
    }
  else if (strcmp (status, "BAD_OTP") == 0)
    {
      out = YKCLIENT_BAD_OTP;
      goto done;
    }
  else if (strcmp (status, "REPLAYED_OTP") == 0)
    {
      out = YKCLIENT_REPLAYED_OTP;
      goto done;
    }
  else if (strcmp (status, "REPLAYED_REQUEST") == 0)
    {
      out = YKCLIENT_REPLAYED_REQUEST;
      goto done;
    }
  else if (strcmp (status, "BAD_SIGNATURE") == 0)
    {
      out = YKCLIENT_BAD_SIGNATURE;
      goto done;
    }
  else if (strcmp (status, "MISSING_PARAMETER") == 0)
    {
      out = YKCLIENT_MISSING_PARAMETER;
      goto done;
    }
  else if (strcmp (status, "NO_SUCH_CLIENT") == 0)
    {
      out = YKCLIENT_NO_SUCH_CLIENT;
      goto done;
    }
  else if (strcmp (status, "OPERATION_NOT_ALLOWED") == 0)
    {
      out = YKCLIENT_OPERATION_NOT_ALLOWED;
      goto done;
    }
  else if (strcmp (status, "BACKEND_ERROR") == 0)
    {
      out = YKCLIENT_BACKEND_ERROR;
      goto done;
    }
  else if (strcmp (status, "NOT_ENOUGH_ANSWERS") == 0)
    {
      out = YKCLIENT_NOT_ENOUGH_ANSWERS;
      goto done;
    }

  out = YKCLIENT_PARSE_ERROR;

 done:
  if (user_agent)
    free (user_agent);

  if (serv_response)
    ykclient_server_response_free(serv_response);

  return out;
}
