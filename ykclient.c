/* ykclient.c --- Implementation of Yubikey OTP validation client library.
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
#define MAX_TEMPLATES 255

struct ykclient_st
{
  CURLM *curl;
  const char *ca_path;
  size_t num_templates;
  const char **url_templates;
  char last_url[256];
  unsigned int client_id;
  size_t keylen;
  const char *key;
  char *key_buf;
  char *nonce;
  char nonce_supplied;
  int verify_signature;
};

struct curl_data
{
  char *curl_chunk;
  size_t curl_chunk_size;
};

const char *default_url_templates[] = {
  "http://api.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
  "http://api2.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
  "http://api3.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
  "http://api4.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
  "http://api5.yubico.com/wsapi/2.0/verify?id=%d&otp=%s",
};

const size_t default_num_templates = 5;

int
ykclient_init (ykclient_t ** ykc)
{
  ykclient_t *p;

  p = malloc (sizeof (*p));

  if (!p)
    return YKCLIENT_OUT_OF_MEMORY;

  memset(p, 0, (sizeof (*p)));

  p->curl = curl_multi_init ();
  if (!p->curl)
    {
      free (p);
      return YKCLIENT_CURL_INIT_ERROR;
    }

  p->ca_path = NULL;
  p->num_templates = 0;
  p->url_templates = NULL;

  p->key = NULL;
  p->keylen = 0;
  p->key_buf = NULL;

  memset(p->last_url, 0, sizeof(p->last_url));

  p->nonce = NULL;
  p->nonce_supplied = 0;

  /* Verification of server signature can only be done if there is
   * an API key provided
   */
  p->verify_signature = 0;

  *ykc = p;

  return YKCLIENT_OK;
}

void
ykclient_done (ykclient_t ** ykc)
{
  if (ykc && *ykc)
    {
      curl_multi_cleanup ((*ykc)->curl);
      free ((*ykc)->key_buf);
      free ((*ykc)->url_templates);
      free (*ykc);
    }
  if (ykc) {
    *ykc = NULL;
  }
}

void
ykclient_set_verify_signature (ykclient_t * ykc, int value)
{
  if (ykc == NULL)
    return;
  ykc->verify_signature = value;
}

void
ykclient_set_client (ykclient_t * ykc,
		     unsigned int client_id, size_t keylen, const char *key)
{
  ykc->client_id = client_id;
  ykc->keylen = keylen;
  ykc->key = key;
}

int
ykclient_set_client_hex (ykclient_t * ykc,
			 unsigned int client_id, const char *key)
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

      if (sscanf (&key[2 * i], "%02x", &tmp) != 1)
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
ykclient_set_client_b64 (ykclient_t * ykc,
			 unsigned int client_id, const char *key)
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

  base64_init_decodestate (&b64);
  ykc->keylen = base64_decode_block (key, key_len, ykc->key_buf, &b64);
  ykc->key = ykc->key_buf;
  /* Now that we have a key the sensible default is to verify signatures */
  ykc->verify_signature = 1;

  return YKCLIENT_OK;
}

void
ykclient_set_ca_path (ykclient_t * ykc, const char *ca_path)
{
  ykc->ca_path = ca_path;
}

void
ykclient_set_url_template (ykclient_t * ykc, const char *url_template)
{
  ykclient_set_url_templates (ykc, 1, (const char **) &url_template);
}

int
ykclient_set_url_templates (ykclient_t * ykc, size_t num_templates,
			    const char **url_templates)
{
  int i;
  if(num_templates > MAX_TEMPLATES)
    return YKCLIENT_BAD_INPUT;
  free(ykc->url_templates);
  ykc->url_templates = malloc(sizeof(char*) * num_templates);
  if(!ykc->url_templates)
    return YKCLIENT_OUT_OF_MEMORY;
  ykc->num_templates = num_templates;
  for(i = 0; i < num_templates; i++) {
    ykc->url_templates[i] = url_templates[i];
  }
  return YKCLIENT_OK;
}

/*
 * Set the nonce. A default nonce is generated in ykclient_init(), but
 * if you either want to specify your own nonce, or want to remove the
 * nonce (needed to send signed requests to v1 validation servers),
 * you must call this function. Set nonce to NULL to disable it.
 */
void
ykclient_set_nonce (ykclient_t * ykc, char *nonce)
{
  ykc->nonce_supplied = 1;
  ykc->nonce = nonce;
}

/*
 * Simple API to validate an OTP (hexkey) using the YubiCloud validation
 * service.
 */
int
ykclient_verify_otp (const char *yubikey_otp,
		     unsigned int client_id, const char *hexkey)
{
  return ykclient_verify_otp_v2 (NULL,
				 yubikey_otp,
				 client_id, hexkey, 0, NULL, NULL);
}

/*
 * Extended API to validate an OTP (hexkey) using either the YubiCloud
 * validation service, or any other validation service.
 *
 * Special CURL settings can be achieved by passing a non-null ykc_in.
 */
int
ykclient_verify_otp_v2 (ykclient_t * ykc_in,
			const char *yubikey_otp,
			unsigned int client_id,
			const char *hexkey,
			size_t urlcount,
			const char **urls, const char *api_key)
{
  ykclient_t *ykc;
  int ret;

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

  if (urlcount != 0 && *urls != 0)
    {
      ykclient_set_url_templates(ykc, urlcount, urls);
    }

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
ykclient_get_last_url (ykclient_t * ykc)
{
  return ykc->last_url;
}

static size_t
curl_callback (void *ptr, size_t size, size_t nmemb, void *data)
{
  struct curl_data *curl_data = (struct curl_data*) data;
  size_t realsize = size * nmemb;
  char *p;

  if (curl_data->curl_chunk)
    p = realloc (curl_data->curl_chunk, curl_data->curl_chunk_size + realsize + 1);
  else
    p = malloc (curl_data->curl_chunk_size + realsize + 1);

  if (!p)
    return -1;

  curl_data->curl_chunk = p;

  memcpy (&(curl_data->curl_chunk[curl_data->curl_chunk_size]), ptr, realsize);
  curl_data->curl_chunk_size += realsize;
  curl_data->curl_chunk[curl_data->curl_chunk_size] = 0;

  return realsize;
}

int
ykclient_request (ykclient_t * ykc, const char *yubikey)
{
  const char **url_templates = ykc->url_templates;
  size_t num_templates = ykc->num_templates;
  char *user_agent = NULL;
  char *status;
  int out;
  char **urls;
  char *signature = NULL;
  int still_running;
  CURL **curls_list;
  char *encoded_otp;
  char *nonce;

  if (!url_templates || *url_templates == 0) {
    url_templates = default_url_templates;
    num_templates = default_num_templates;
  }

  urls = malloc(sizeof(char*) * num_templates);
  if(!urls)
    return YKCLIENT_OUT_OF_MEMORY;

  curls_list = malloc(sizeof(CURL*) * num_templates);
  if (!curls_list)
    return YKCLIENT_OUT_OF_MEMORY;

  memset(ykc->last_url, 0, sizeof(ykc->last_url));

  {
    size_t len = strlen (PACKAGE) + 1 + strlen (PACKAGE_VERSION) + 1;
    user_agent = malloc (len);
    if (!user_agent)
      return YKCLIENT_OUT_OF_MEMORY;
    snprintf (user_agent, len, "%s/%s", PACKAGE, PACKAGE_VERSION);
  }

  /* URL-encode the OTP */
  encoded_otp = curl_easy_escape(ykc->curl, yubikey, 0);

  if(ykc->nonce_supplied)
  {
    nonce = ykc->nonce;
  }
  else
  {
    nonce = malloc (NONCE_LEN + 1);
    if(!nonce)
      return YKCLIENT_OUT_OF_MEMORY;

    /* Generate a random 'nonce' value */
    int i = 0;
    struct timeval tv;

    gettimeofday (&tv, 0);
    srandom (tv.tv_sec * tv.tv_usec);

    for (i = 0; i < NONCE_LEN; ++i)
    {
      nonce[i] = (random () % 26) + 'a';
    }

    nonce[NONCE_LEN] = 0;
  }

  int i = 0;
  for(; i < num_templates; i++)
  {
    char *url = NULL;
    {
      size_t len = strlen (url_templates[i]) + strlen (encoded_otp) + 20;
      size_t wrote;

      url = malloc(len);
      if (!url)
	return YKCLIENT_OUT_OF_MEMORY;
      wrote = snprintf (url, len, url_templates[i], ykc->client_id, encoded_otp);
      if (wrote < 0 || wrote > len)
	return YKCLIENT_FORMAT_ERROR;
    }

    if (nonce)
    {
      /* Create new URL with nonce in it. */
      char *nonce_url, *otp_offset;
      size_t len;
      int wrote;

#define ADD_NONCE "&nonce="
      len = strlen (url) + strlen (ADD_NONCE) + strlen (nonce) + 1;
      nonce_url = malloc (len + 4); /* avoid valgrind complaint */
      if (!nonce_url)
	return YKCLIENT_OUT_OF_MEMORY;

      /* Find the &otp= in url and insert ?nonce= before otp. Must get
       *  sorted headers since we calculate HMAC on the result.
       *
       * XXX this will break if the validation protocol gets a parameter that
       * sorts in between "nonce" and "otp", because the headers we sign won't
       * be alphabetically sorted if we insert the nonce between "nz" and "otp".
       * Also, we assume that everyone will have at least one parameter ("id=")
       * before "otp" so there is no need to search for "?otp=".
       */
      otp_offset = strstr (url, "&otp=");
      if (otp_offset == NULL)
	/* point at \0 at end of url in case there is no otp */
	otp_offset = url + len;

      /* break up ykc->url where we want to insert nonce */
      *otp_offset = 0;

      wrote =
	snprintf (nonce_url, len, "%s" ADD_NONCE "%s&%s", url, nonce,
	    otp_offset + 1);
      if (wrote + 1 != len)
	return YKCLIENT_FORMAT_ERROR;

      free (url);
      url = nonce_url;
    }

    if (ykc->key && ykc->keylen)
    {
      if (!signature)
      {
	char b64dig[3 * 4 * SHA1HashSize + 1];
	uint8_t digest[USHAMaxHashSize];
	base64_encodestate b64;
	char *text;
	int res, res2;

	/* Find parameters to sign. */
	text = strchr (url, '?');
	if (!text)
	  return YKCLIENT_PARSE_ERROR;
	text++;

	/* HMAC data. */
	res = hmac (SHA1, (unsigned char *) text, strlen (text),
	    (unsigned char *) ykc->key, ykc->keylen, digest);
	if (res != shaSuccess)
	  return YKCLIENT_HMAC_ERROR;

	/* Base64 signature. */
	base64_init_encodestate (&b64);
	res = base64_encode_block ((char *) digest, SHA1HashSize, b64dig, &b64);
	res2 = base64_encode_blockend (&b64dig[res], &b64);
	b64dig[res + res2 - 1] = '\0';

	signature = curl_easy_escape(ykc->curl, b64dig, 0);
      }

      /* Create new URL with signature ( h= ) appended to it . */
      {
	char *sign_url;
	size_t len;
	int wrote;


#define ADD_HASH "&h="
	len = strlen (url) + strlen (ADD_HASH) + strlen (signature) + 1;
	sign_url = malloc (len);
	if (!sign_url)
	  return YKCLIENT_OUT_OF_MEMORY;

	wrote = snprintf (sign_url, len, "%s" ADD_HASH "%s", url, signature);
	if (wrote + 1 != len)
	  return YKCLIENT_FORMAT_ERROR;
	free (url);
	url = sign_url;
      }
    }

    {
      CURL *curl_easy = curl_easy_init();
      struct curl_data *data = malloc(sizeof(struct curl_data));
      if (!data) {
	return YKCLIENT_OUT_OF_MEMORY;
      }
      data->curl_chunk = NULL;
      data->curl_chunk_size = 0;
      if (ykc->ca_path)
      {
	curl_easy_setopt (curl_easy, CURLOPT_CAPATH, ykc->ca_path);
      }
      curl_easy_setopt (curl_easy, CURLOPT_URL, url);
      curl_easy_setopt (curl_easy, CURLOPT_WRITEFUNCTION, curl_callback);
      curl_easy_setopt (curl_easy, CURLOPT_WRITEDATA, (void *) data);
      curl_easy_setopt (curl_easy, CURLOPT_PRIVATE, (void *) data);
      if(user_agent)
      {
	curl_easy_setopt (curl_easy, CURLOPT_USERAGENT, user_agent);
      }
      curl_multi_add_handle(ykc->curl, curl_easy);
      curls_list[i] = curl_easy;
      urls[i] = url;
    }
  }

  still_running = num_templates;
  while(still_running) {
    CURLcode curl_ret = curl_multi_perform (ykc->curl, &still_running);
    struct timeval timeout;

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;

    long curl_timeo = -1;

    if (curl_ret != CURLE_OK)
      {
	fprintf(stderr, "Error with curl: %s\n", curl_multi_strerror(curl_ret));
	out = YKCLIENT_CURL_PERFORM_ERROR;
	still_running = 0;
	break;
      }

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    timeout.tv_sec = 0;
    timeout.tv_usec = 250000;

    curl_multi_timeout(ykc->curl, &curl_timeo);
    if(curl_timeo >= 0) {
      timeout.tv_sec = curl_timeo / 1000;
      if(timeout.tv_sec > 1) {
	timeout.tv_sec = 0;
	timeout.tv_usec = 250000;
      }
      else
	timeout.tv_usec = (curl_timeo % 1000) * 1000;
    }

    curl_multi_fdset(ykc->curl, &fdread, &fdwrite, &fdexcep, &maxfd);

    select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

    {
      int msgs_left = 1;
      while(msgs_left) {
	CURLMsg *msg = curl_multi_info_read(ykc->curl, &msgs_left);
	if(msg && msg->msg == CURLMSG_DONE) {
	  CURL *curl_easy = msg->easy_handle;
	  struct curl_data *data;
	  char *url_used;
	  int parse_ret;

	  ykclient_server_response_t *serv_response = NULL;
	  curl_easy_getinfo(curl_easy, CURLINFO_PRIVATE, (char **) &data);

	  if (data == 0 || data->curl_chunk_size == 0 || data->curl_chunk == NULL)
	  {
	    out = YKCLIENT_PARSE_ERROR;
	    goto done;
	  }

	  curl_easy_getinfo(curl_easy, CURLINFO_EFFECTIVE_URL, &url_used);
	  strncpy(ykc->last_url, url_used, 200);

	  serv_response = ykclient_server_response_init ();
	  if (serv_response == NULL)
	  {
	    out = YKCLIENT_PARSE_ERROR;
	    goto done;
	  }
	  parse_ret = ykclient_server_response_parse (data->curl_chunk,
	      serv_response);
	  if (parse_ret)
	  {
	    out = parse_ret;
	    goto done;
	  }

	  if (ykc->verify_signature != 0 &&
	      ykclient_server_response_verify_signature (serv_response,
		ykc->key, ykc->keylen))
	  {
	    out = YKCLIENT_BAD_SERVER_SIGNATURE;
	    goto done;
	  }

	  status = ykclient_server_response_get (serv_response, "status");
	  if (!status)
	  {
	    out = YKCLIENT_PARSE_ERROR;
	    goto done;
	  }

	  if (strcmp (status, "OK") == 0)
	  {
	    char *server_otp;

	    /* Verify that the OTP and nonce we put in our request is echoed in the response.
	     *
	     * This is to protect us from a man in the middle sending us a previously
	     * seen genuine response again (such as an status=OK response even though
	     * the real server will respond status=REPLAYED_OTP in a few milliseconds.
	     */
	    if (ykc->nonce)
	    {
	      char *server_nonce =
		ykclient_server_response_get (serv_response, "nonce");
	      if (server_nonce == NULL || strcmp (nonce, server_nonce))
	      {
		out = YKCLIENT_HMAC_ERROR;
		goto done;
	      }
	    }

	    server_otp = ykclient_server_response_get (serv_response, "otp");
	    if (server_otp == NULL || strcmp (yubikey, server_otp))
	    {
	      out = YKCLIENT_HMAC_ERROR;
	      goto done;
	    }

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
	  if (serv_response)
	    ykclient_server_response_free (serv_response);
	  /* if we got a valid response, get out of the loops */
	  if (out != YKCLIENT_PARSE_ERROR && out != YKCLIENT_REPLAYED_REQUEST)
	  {
	    still_running = 0;
	    msgs_left = 0;
	  }
	}
      }
    }
  }

  for(i = 0; i < num_templates; i++)
  {
    CURL *curl = curls_list[i];
    CURLMcode code = curl_multi_remove_handle(ykc->curl, curl);

    struct curl_data *data;
    curl_easy_getinfo(curl, CURLINFO_PRIVATE, (char **) &data);
    free(data->curl_chunk);
    free(data);

    curl_easy_cleanup(curl);

    free(urls[i]);
  }

  /* if we allocated the nonce ourselves, free it */
  if(!ykc->nonce_supplied)
    free(nonce);

  curl_free(encoded_otp);
  curl_free(signature);
  free (curls_list);
  free(urls);
  free (user_agent);

  return out;
}
