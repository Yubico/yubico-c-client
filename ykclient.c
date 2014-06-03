/* ykclient.c --- Implementation of Yubikey OTP validation client library.
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

#include "ykclient_server_response.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

#include <curl/curl.h>

#include "sha.h"
#include "cencode.h"
#include "cdecode.h"

#define NONCE_LEN 32
#define MAX_TEMPLATES 255

#define ADD_NONCE "&nonce="
#define ADD_OTP "&otp="
#define ADD_ID "?id="

#define TEMPLATE_FORMAT_OLD 1
#define TEMPLATE_FORMAT_NEW 2

struct ykclient_st
{
  const char *ca_path;
  const char *ca_info;
  size_t num_templates;
  char **url_templates;
  int template_format;
  char last_url[256];
  unsigned int client_id;
  size_t keylen;
  const char *key;
  char *key_buf;
  char *nonce;
  char nonce_supplied;
  int verify_signature;
  const char *user_agent;
};

struct curl_data
{
  char *curl_chunk;
  size_t curl_chunk_size;
};

struct ykclient_handle_st
{
  CURL **easy;
  CURLM *multi;
  size_t num_easy;
  struct curl_data *data;
  char **url_exp;
};

const char *default_url_templates[] = {
  "http://api.yubico.com/wsapi/2.0/verify",
  "http://api2.yubico.com/wsapi/2.0/verify",
  "http://api3.yubico.com/wsapi/2.0/verify",
  "http://api4.yubico.com/wsapi/2.0/verify",
  "http://api5.yubico.com/wsapi/2.0/verify",
};

/** Initialise the global context for the library
 *
 * This function is not thread safe.  It must be invoked successfully
 * before using any other function.
 *
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
ykclient_rc
ykclient_global_init (void)
{

  if (curl_global_init (CURL_GLOBAL_ALL) != 0)
    return YKCLIENT_CURL_INIT_ERROR;
  return YKCLIENT_OK;
}

/** Deinitialise the global context for the library
 *
 * This function is not thread safe.  After this function has been
 * called, no other library functions may be used reliably.
 *
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
void
ykclient_global_done (void)
{
  curl_global_cleanup ();
}

/** Initialise a new configuration structure
 *
 * Additional options can be set with ykclient_set_* functions
 * after memory for the configuration has been allocated with
 * this function.
 *
 * @param ykc Where to write a pointer to the new configuration.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
ykclient_rc
ykclient_init (ykclient_t ** ykc)
{
  ykclient_t *p;

  p = malloc (sizeof (*p));

  if (!p)
    {
      return YKCLIENT_OUT_OF_MEMORY;
    }

  memset (p, 0, (sizeof (*p)));

  p->ca_path = NULL;
  p->ca_info = NULL;

  p->key = NULL;
  p->keylen = 0;
  p->key_buf = NULL;

  memset (p->last_url, 0, sizeof (p->last_url));

  p->nonce = NULL;
  p->nonce_supplied = 0;

  /* 
   * Verification of server signature can only be done if there is
   * an API key provided 
   */
  p->verify_signature = 0;

  *ykc = p;

  /*
   * Set the User-Agent string that will be used by the CURL
   * handles.
   */
  p->user_agent = PACKAGE "/" PACKAGE_VERSION;

  /*
   * Set the default URLs (these can be overridden later)
   */
  ykclient_set_url_bases (p,
			  sizeof (default_url_templates) /
			  sizeof (char *), default_url_templates);

  return YKCLIENT_OK;
}

/** Frees a configuration structure allocated by ykclient_init
 *
 * Any handles created with ykclient_handle_init must be freed
 * separately with ykclient_handle_done.
 *
 * @param ykc configuration to free.
 */
void
ykclient_done (ykclient_t ** ykc)
{
  if (ykc && *ykc)
    {
      if ((*ykc)->url_templates)
	{
	  size_t i;
	  for (i = 0; i < (*ykc)->num_templates; i++)
	    {
	      free ((*ykc)->url_templates[i]);
	    }
	  free ((*ykc)->url_templates);
	}

      free ((*ykc)->key_buf);
      free (*ykc);
    }

  if (ykc)
    {
      *ykc = NULL;
    }
}

/** Callback for processing CURL data received from the validation server
 *
 */
static size_t
curl_callback (void *ptr, size_t size, size_t nmemb, void *data)
{
  struct curl_data *curl_data = (struct curl_data *) data;
  size_t realsize = size * nmemb;
  char *p;

  if (curl_data->curl_chunk)
    {
      p = realloc (curl_data->curl_chunk,
		   curl_data->curl_chunk_size + realsize + 1);
    }
  else
    {
      p = malloc (curl_data->curl_chunk_size + realsize + 1);
    }

  if (!p)
    {
      return 0;
    }

  curl_data->curl_chunk = p;

  memcpy (&(curl_data->curl_chunk[curl_data->curl_chunk_size]), ptr,
	  realsize);
  curl_data->curl_chunk_size += realsize;
  curl_data->curl_chunk[curl_data->curl_chunk_size] = 0;

  return realsize;
}

/** Create a new handle
 *
 * These handles contain curl easy and multi handles required to
 * process a request.
 *
 * This must be called after configuring template URLs, and handles
 * MUST NOT be reused if new template URLs have been set.
 *
 * If new template URLs have been set all handles must be destroyed
 * with ykclient_handle_close and recreated with this function.
 *
 * Handles must be cleaned with ykclient_handle_cleanup between 
 * requests, and closed with ykclient_handle_close when they are no
 * longer needed.
 *
 * @param ykc Yubikey client configuration.
 * @param[out] ykh where to write pointer to new handle.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
ykclient_rc
ykclient_handle_init (ykclient_t * ykc, ykclient_handle_t ** ykh)
{
  ykclient_handle_t *p;

  *ykh = NULL;

  p = malloc (sizeof (*p));
  if (!p)
    {
      return YKCLIENT_OUT_OF_MEMORY;
    }
  memset (p, 0, (sizeof (*p)));

  p->multi = curl_multi_init ();
  if (!p->multi)
    {
      free (p);
      return YKCLIENT_CURL_INIT_ERROR;
    }

  p->easy = malloc (sizeof (CURL *) * ykc->num_templates);
  for (p->num_easy = 0; p->num_easy < ykc->num_templates; p->num_easy++)
    {
      CURL *easy;
      struct curl_data *data;

      data = malloc (sizeof (*data));
      if (!data)
	{
	  ykclient_handle_done (&p);
	  return YKCLIENT_OUT_OF_MEMORY;
	}
      data->curl_chunk = NULL;
      data->curl_chunk_size = 0;

      easy = curl_easy_init ();
      if (!easy)
	{
	  free (data);
	  ykclient_handle_done (&p);
	  return YKCLIENT_CURL_INIT_ERROR;
	}

      if (ykc->ca_path)
	{
	  curl_easy_setopt (easy, CURLOPT_CAPATH, ykc->ca_path);
	}

      if (ykc->ca_info)
	{
	  curl_easy_setopt (easy, CURLOPT_CAINFO, ykc->ca_info);
	}

      curl_easy_setopt (easy, CURLOPT_WRITEDATA, (void *) data);
      curl_easy_setopt (easy, CURLOPT_PRIVATE, (void *) data);
      curl_easy_setopt (easy, CURLOPT_WRITEFUNCTION, curl_callback);
      curl_easy_setopt (easy, CURLOPT_USERAGENT, ykc->user_agent);

      curl_multi_add_handle (p->multi, easy);
      p->easy[p->num_easy] = easy;
    }

  /* Take this opportunity to allocate the array for expanded URLs */
  p->url_exp = malloc (sizeof (char *) * p->num_easy);
  if (!p->url_exp)
    {
      ykclient_handle_done (&p);
      return YKCLIENT_OUT_OF_MEMORY;
    }
  memset (p->url_exp, 0, (sizeof (char *) * p->num_easy));

  *ykh = p;

  return YKCLIENT_OK;
}

/** Cleanup memory allocated for requests
 *
 * Cleans up any memory allocated and held by the handle for a
 * request. Must be called after each request.
 *
 * @param ykh to close.
 */
void
ykclient_handle_cleanup (ykclient_handle_t * ykh)
{
  size_t i;
  struct curl_data *data;
  int requests = 0;

  /*
   *  Curl will not allow a connection to be re-used unless the 
   *  request finished, call curl_multi_perform one last time
   *  to give libcurl an opportunity to mark the request as 
   *  complete.
   *
   *  If the delay between yk_request_send and 
   *  ykclient_handle_cleanup is sufficient to allow the request
   *  to complete, the connection can be re-used, else it will 
   *  be re-established on next yk_request_send.
   */
  (void) curl_multi_perform (ykh->multi, &requests);

  for (i = 0; i < ykh->num_easy; i++)
    {
      free (ykh->url_exp[i]);
      ykh->url_exp[i] = NULL;

      curl_easy_getinfo (ykh->easy[i], CURLINFO_PRIVATE, (char **) &data);
      free (data->curl_chunk);
      data->curl_chunk = NULL;
      data->curl_chunk_size = 0;

      curl_multi_remove_handle (ykh->multi, ykh->easy[i]);
      curl_multi_add_handle (ykh->multi, ykh->easy[i]);
    }
}

/** Close a handle freeing memory and destroying connections
 *
 * Frees any memory allocated for the handle, and calls various CURL
 * functions to destroy all curl easy and multi handles created for
 * this handle.
 *
 * @param ykh to close.
 */
void
ykclient_handle_done (ykclient_handle_t ** ykh)
{
  struct curl_data *data;
  size_t i;

  if (ykh && *ykh)
    {
      ykclient_handle_cleanup (*ykh);

      for (i = 0; i < (*ykh)->num_easy; i++)
	{
	  curl_easy_getinfo ((*ykh)->easy[i], CURLINFO_PRIVATE,
			     (char **) &data);
	  free (data);

	  curl_multi_remove_handle ((*ykh)->multi, (*ykh)->easy[i]);
	  curl_easy_cleanup ((*ykh)->easy[i]);
	}

      if ((*ykh)->multi)
	{
	  curl_multi_cleanup ((*ykh)->multi);
	}

      free ((*ykh)->url_exp);
      free ((*ykh)->easy);
      free (*ykh);
    }

  if (ykh)
    {
      *ykh = NULL;
    }
}

void
ykclient_set_verify_signature (ykclient_t * ykc, int value)
{
  if (ykc == NULL)
    {
      return;
    }

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

ykclient_rc
ykclient_set_client_hex (ykclient_t * ykc,
			 unsigned int client_id, const char *key)
{
  size_t i;
  size_t key_len;
  size_t bin_len;

  ykc->client_id = client_id;

  if (key == NULL)
    {
      return YKCLIENT_OK;
    }

  key_len = strlen (key);

  if (key_len % 2 != 0)
    {
      return YKCLIENT_HEX_DECODE_ERROR;
    }

  bin_len = key_len / 2;

  free (ykc->key_buf);

  ykc->key_buf = malloc (bin_len);
  if (!ykc->key_buf)
    {
      return YKCLIENT_OUT_OF_MEMORY;
    }

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

ykclient_rc
ykclient_set_client_b64 (ykclient_t * ykc,
			 unsigned int client_id, const char *key)
{
  size_t key_len;
  ssize_t dec_len;

  base64_decodestate b64;

  ykc->client_id = client_id;

  if (key == NULL)
    {
      return YKCLIENT_OK;
    }

  key_len = strlen (key);

  free (ykc->key_buf);

  ykc->key_buf = malloc (key_len + 1);
  if (!ykc->key_buf)
    {
      return YKCLIENT_OUT_OF_MEMORY;
    }

  base64_init_decodestate (&b64);
  dec_len = (ssize_t) base64_decode_block (key, key_len, ykc->key_buf, &b64);
  if (dec_len < 0)
    {
      return YKCLIENT_BASE64_DECODE_ERROR;
    }
  ykc->keylen = (size_t) dec_len;
  ykc->key = ykc->key_buf;

  /* Now that we have a key the sensible default is to verify signatures */
  ykc->verify_signature = 1;

  return YKCLIENT_OK;
}

/** Set the CA path 
 *
 * Must be called before creating handles.
 */
void
ykclient_set_ca_path (ykclient_t * ykc, const char *ca_path)
{
  ykc->ca_path = ca_path;
}

/** Set the CA info, needed for linking with GnuTLS
 *
 * Must be called before creating handles.
 */
void
ykclient_set_ca_info (ykclient_t * ykc, const char *ca_info)
{
  ykc->ca_info = ca_info;
}

/** Set a single URL template
 *
 * @param ykc Yubikey client configuration.
 * @param url_template to set.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
ykclient_rc
ykclient_set_url_template (ykclient_t * ykc, const char *url_template)
{
  return ykclient_set_url_templates (ykc, 1, (const char **) &url_template);
}

/** Set the URLs of the YK validation servers
 *
 * The URL strings will be copied to the new buffers, so the 
 * caller may free the original URL strings if they are no 
 * longer needed.
 *
 * @note This function MUST be called before calling ykclient_handle_init
 *
 * @param ykc Yubikey client configuration.
 * @param num_templates Number of template URLs passed in url_templates.
 * @param url_templates Array of template URL strings.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
ykclient_rc
ykclient_set_url_templates (ykclient_t * ykc, size_t num_templates,
			    const char **url_templates)
{
  ykclient_rc ret =
    ykclient_set_url_bases (ykc, num_templates, url_templates);
  if (ret == YKCLIENT_OK)
    {
      ykc->template_format = TEMPLATE_FORMAT_OLD;
    }
  return ret;
}

ykclient_rc
ykclient_set_url_bases (ykclient_t * ykc, size_t num_templates,
			const char **url_templates)
{
  size_t i;
  if (num_templates > MAX_TEMPLATES)
    {
      return YKCLIENT_BAD_INPUT;
    }

  /* Clean out any previously allocated templates */
  if (ykc->url_templates)
    {
      for (i = 0; i < ykc->num_templates; i++)
	{
	  free (ykc->url_templates[i]);
	}
      free (ykc->url_templates);
    }

  /* Reallocate the template array */
  ykc->url_templates = malloc (sizeof (char *) * num_templates);
  if (!ykc->url_templates)
    {
      return YKCLIENT_OUT_OF_MEMORY;
    }
  memset (ykc->url_templates, 0, (sizeof (char *) * num_templates));

  for (ykc->num_templates = 0; ykc->num_templates < num_templates;
       ykc->num_templates++)
    {
      ykc->url_templates[ykc->num_templates] =
	strdup (url_templates[ykc->num_templates]);

      if (!ykc->url_templates[ykc->num_templates])
	{
	  return YKCLIENT_OUT_OF_MEMORY;
	}
    }

  ykc->template_format = TEMPLATE_FORMAT_NEW;
  return YKCLIENT_OK;
}

/*
 * Set the nonce. A default nonce is generated in ykclient_init (), but
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

/** Convert a ykclient_rc value to a string
 *
 * Returns a more verbose error message relating to the ykclient_rc
 * value passed as ret.
 *
 * @param ret the error code to convert.
 * @return verbose error string.
 */
const char *
ykclient_strerror (ykclient_rc ret)
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

    case YKCLIENT_BASE64_DECODE_ERROR:
      p = "Error decoding base64 string";
      break;

    case YKCLIENT_NOT_IMPLEMENTED:
      p = "Not implemented";
      break;

    case YKCLIENT_HANDLE_NOT_REINIT:
      p = "Request template URLs modified without reinitialising handles";
      break;

    case YKCLIENT_BAD_INPUT:
      p = "Passed invalid or incorrect number of parameters";
      break;

    default:
      p = "Unknown error";
    }

  return p;
}

/** Generates or duplicates an existing nonce value
 *
 * If a nonce value was set with ykclient_set_nonce, it will be duplicated 
 * and a pointer to the memory returned in nonce.
 *
 * If a nonce value has not been set a new buffer will be allocated and a 
 * random string of NONCE_LEN will be written to it.
 *
 * Memory pointed to by nonce must be freed by the called when it is no 
 * longer requiest.
 * 
 * @param ykc Yubikey client configuration.
 * @param[out] nonce where to write the pointer to the nonce value.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
static ykclient_rc
ykclient_generate_nonce (ykclient_t * ykc, char **nonce)
{
  *nonce = NULL;

  /* 
   * If we were supplied with a static value just strdup,
   * makes memory management easier.
   */
  if (ykc->nonce_supplied)
    {
      if (ykc->nonce)
	{
	  *nonce = strdup (ykc->nonce);
	  if (*nonce == NULL)
	    return YKCLIENT_OUT_OF_MEMORY;
	}
    }
  /*
   * Generate a random 'nonce' value
   */
  else
    {
      struct timeval tv;
      size_t i;
      char *p;

      p = malloc (NONCE_LEN + 1);
      if (!p)
	{
	  return YKCLIENT_OUT_OF_MEMORY;
	}

      gettimeofday (&tv, 0);
      srandom (tv.tv_sec * tv.tv_usec);

      for (i = 0; i < NONCE_LEN; ++i)
	{
	  p[i] = (random () % 26) + 'a';
	}

      p[NONCE_LEN] = 0;

      *nonce = p;
    }

  return YKCLIENT_OK;
}

static ykclient_rc
ykclient_expand_new_url (const char *template,
			 const char *encoded_otp, const char *nonce,
			 int client_id, char **url_exp)
{
  size_t len =
    strlen (template) + strlen (encoded_otp) + strlen (ADD_OTP) +
    strlen (ADD_ID) + 1;
  len += snprintf (NULL, 0, "%d", client_id);

  if (nonce)
    {
      len += strlen (nonce) + strlen (ADD_NONCE);
    }

  *url_exp = malloc (len);
  if (!*url_exp)
    {
      return YKCLIENT_OUT_OF_MEMORY;
    }

  if (nonce)
    {
      snprintf (*url_exp, len, "%s" ADD_ID "%d" ADD_NONCE "%s" ADD_OTP "%s",
		template, client_id, nonce, encoded_otp);
    }
  else
    {
      snprintf (*url_exp, len, "%s" ADD_ID "%d" ADD_OTP "%s", template,
		client_id, encoded_otp);
    }
  return YKCLIENT_OK;
}

static ykclient_rc
ykclient_expand_old_url (const char *template,
			 const char *encoded_otp, const char *nonce,
			 int client_id, char **url_exp)
{
  {
    size_t len;
    ssize_t wrote;

    len = strlen (template) + strlen (encoded_otp) + 20;
    *url_exp = malloc (len);
    if (!*url_exp)
      {
	return YKCLIENT_OUT_OF_MEMORY;
      }

    wrote = snprintf (*url_exp, len, template, client_id, encoded_otp);
    if (wrote < 0 || (size_t) wrote > len)
      {
	return YKCLIENT_FORMAT_ERROR;
      }
  }

  if (nonce)
    {
      /* Create new URL with nonce in it. */
      char *nonce_url, *otp_offset;
      size_t len;
      ssize_t wrote;

      len = strlen (*url_exp) + strlen (ADD_NONCE) + strlen (nonce) + 1;
      nonce_url = malloc (len + 4);	/* avoid valgrind complaint */
      if (!nonce_url)
	{
	  return YKCLIENT_OUT_OF_MEMORY;
	}

      /* Find the &otp= in url and insert ?nonce= before otp. Must get
       *  sorted headers since we calculate HMAC on the result.
       *
       * XXX this will break if the validation protocol gets a parameter that
       * sorts in between "nonce" and "otp", because the headers we sign won't
       * be alphabetically sorted if we insert the nonce between "nz" and "otp".
       * Also, we assume that everyone will have at least one parameter ("id=")
       * before "otp" so there is no need to search for "?otp=".
       */
      otp_offset = strstr (*url_exp, ADD_OTP);
      if (otp_offset == NULL)
	{
	  /* point at \0 at end of url in case there is no otp */
	  otp_offset = *url_exp + len;
	}

      /* break up ykc->url where we want to insert nonce */
      *otp_offset = 0;

      wrote = snprintf (nonce_url, len, "%s" ADD_NONCE "%s&%s", *url_exp,
			nonce, otp_offset + 1);
      if (wrote < 0 || (size_t) wrote + 1 != len)
	{
	  free (nonce_url);
	  return YKCLIENT_FORMAT_ERROR;
	}

      free (*url_exp);
      *url_exp = nonce_url;
    }
  return YKCLIENT_OK;
}

/** Expand URL templates specified with set_url_templates
 *
 * Expands placeholderss or inserts additional parameters for nonce,
 * OTP, and signing values into duplicates of URL templates.
 *
 * The memory allocated for these duplicates must be freed 
 * by calling either ykclient_handle_done or ykclient_handle_cleanup
 * after they are no longer needed.
 * 
 * @param ykc Yubikey client configuration.
 * @param ykh Yubikey client handle.
 * @param yubikey OTP string passed to the client.
 * @param nonce Random value included in the request and validated in the response.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
static ykclient_rc
ykclient_expand_urls (ykclient_t * ykc, ykclient_handle_t * ykh,
		      const char *yubikey, const char *nonce)
{
  ykclient_rc out = YKCLIENT_OK;

  size_t i, j;

  char *signature = NULL;
  char *encoded_otp = NULL;

  /* The handle must have the same number of easy handles as we have templates */
  if (ykc->num_templates != ykh->num_easy)
    {
      return YKCLIENT_HANDLE_NOT_REINIT;
    }

  /* URL-encode the OTP */
  encoded_otp = curl_easy_escape (ykh->multi, yubikey, 0);

  for (i = 0; i < ykc->num_templates; i++)
    {
      ykclient_rc ret;
      if (ykc->template_format == TEMPLATE_FORMAT_OLD)
	{
	  ret = ykclient_expand_old_url (ykc->url_templates[i],
					 encoded_otp, nonce, ykc->client_id,
					 &ykh->url_exp[i]);
	}
      else
	{
	  ret = ykclient_expand_new_url (ykc->url_templates[i],
					 encoded_otp, nonce, ykc->client_id,
					 &ykh->url_exp[i]);
	}
      if (ret != YKCLIENT_OK)
	{
	  out = ret;
	  goto finish;
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
	      text = strchr (ykh->url_exp[i], '?');
	      if (!text)
		{
		  out = YKCLIENT_PARSE_ERROR;
		  goto finish;
		}
	      text++;

	      /* HMAC data. */
	      res = hmac (SHA1, (unsigned char *) text, strlen (text),
			  (const unsigned char *) ykc->key, ykc->keylen,
			  digest);
	      if (res != shaSuccess)
		{
		  out = YKCLIENT_HMAC_ERROR;
		  goto finish;
		}

	      /* Base64 signature. */
	      base64_init_encodestate (&b64);
	      res =
		base64_encode_block ((char *) digest, SHA1HashSize, b64dig,
				     &b64);
	      res2 = base64_encode_blockend (&b64dig[res], &b64);
	      b64dig[res + res2 - 1] = '\0';

	      signature = curl_easy_escape (ykh->multi, b64dig, 0);
	    }

	  /* Create new URL with signature ( h= ) appended to it . */
	  {
	    char *sign_url;
	    size_t len;
	    ssize_t wrote;

#define ADD_HASH "&h="
	    len =
	      strlen (ykh->url_exp[i]) + strlen (ADD_HASH) +
	      strlen (signature) + 1;
	    sign_url = malloc (len);
	    if (!sign_url)
	      {
		free (sign_url);

		out = YKCLIENT_OUT_OF_MEMORY;
		goto finish;
	      }

	    wrote =
	      snprintf (sign_url, len, "%s" ADD_HASH "%s", ykh->url_exp[i],
			signature);
	    if (wrote < 0 || (size_t) wrote + 1 != len)
	      {
		free (sign_url);

		out = YKCLIENT_FORMAT_ERROR;
		goto finish;
	      }

	    free (ykh->url_exp[i]);
	    ykh->url_exp[i] = sign_url;
	  }
	}

      curl_easy_setopt (ykh->easy[i], CURLOPT_URL, ykh->url_exp[i]);
    }

finish:

  if (encoded_otp)
    {
      curl_free (encoded_otp);
    }

  if (signature)
    {
      curl_free (signature);
    }

  /* On error free any URLs we previously built */
  if (out != YKCLIENT_OK)
    {
      for (j = 0; j < i; j++)
	{
	  free (ykh->url_exp[j]);
	  ykh->url_exp[j] = NULL;
	}
    }

  return out;
}

/** Convert the response from the validation server into a ykclient_rc
 *
 * @param status message from the validation server.
 * @return one of the YKCLIENT_* values.
 */
static ykclient_rc
ykclient_parse_srv_error (const char *status)
{
  if (strcmp (status, "OK") == 0)
    {
      return YKCLIENT_OK;
    }
  else if (strcmp (status, "BAD_OTP") == 0)
    {
      return YKCLIENT_BAD_OTP;
    }
  else if (strcmp (status, "REPLAYED_OTP") == 0)
    {
      return YKCLIENT_REPLAYED_OTP;
    }
  else if (strcmp (status, "REPLAYED_REQUEST") == 0)
    {
      return YKCLIENT_REPLAYED_REQUEST;
    }
  else if (strcmp (status, "BAD_SIGNATURE") == 0)
    {
      return YKCLIENT_BAD_SIGNATURE;
    }
  else if (strcmp (status, "MISSING_PARAMETER") == 0)
    {
      return YKCLIENT_MISSING_PARAMETER;
    }
  else if (strcmp (status, "NO_SUCH_CLIENT") == 0)
    {
      return YKCLIENT_NO_SUCH_CLIENT;
    }
  else if (strcmp (status, "OPERATION_NOT_ALLOWED") == 0)
    {
      return YKCLIENT_OPERATION_NOT_ALLOWED;
    }
  else if (strcmp (status, "BACKEND_ERROR") == 0)
    {
      return YKCLIENT_BACKEND_ERROR;
    }
  else if (strcmp (status, "NOT_ENOUGH_ANSWERS") == 0)
    {
      return YKCLIENT_NOT_ENOUGH_ANSWERS;
    }

  return YKCLIENT_PARSE_ERROR;
}

/** Send requests to one or more validation servers and processes the response
 *
 * @param ykc Yubikey client configuration.
 * @param ykh Yubikey client handle.
 * @param yubikey OTP string passed to the client.
 * @param nonce Random value included in the request and validated in the response.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
static ykclient_rc
ykclient_request_send (ykclient_t * ykc, ykclient_handle_t * ykh,
		       const char *yubikey, char *nonce)
{
  ykclient_rc out = YKCLIENT_OK;
  int requests;
  ykclient_server_response_t *srv_response = NULL;

  if (!ykc->num_templates)
    {
      return YKCLIENT_MISSING_PARAMETER;
    }

  /* The handle must have the same number of easy handles as we have templates */
  if (ykc->num_templates != ykh->num_easy)
    {
      return YKCLIENT_HANDLE_NOT_REINIT;
    }

  memset (ykc->last_url, 0, sizeof (ykc->last_url));

  /* Perform the request */
  do
    {
      int msgs = 1;
      CURLMcode curl_ret = curl_multi_perform (ykh->multi, &requests);
      struct timeval timeout;

      fd_set fdread;
      fd_set fdwrite;
      fd_set fdexcep;
      int maxfd = -1;

      long curl_timeo = -1;

      /* curl before 7.20.0 can return CURLM_CALL_MULTI_PERFORM, continue so we
       * call curl_multi_perform again. */
      if (curl_ret == CURLM_CALL_MULTI_PERFORM)
	{
	  continue;
	}

      if (curl_ret != CURLM_OK)
	{
	  fprintf (stderr, "Error with curl: %s\n",
		   curl_multi_strerror (curl_ret));
	  out = YKCLIENT_CURL_PERFORM_ERROR;
	  goto finish;
	}

      FD_ZERO (&fdread);
      FD_ZERO (&fdwrite);
      FD_ZERO (&fdexcep);

      memset (&timeout, 0, sizeof (timeout));

      timeout.tv_sec = 0;
      timeout.tv_usec = 250000;

      curl_multi_timeout (ykh->multi, &curl_timeo);
      if (curl_timeo >= 0)
	{
	  timeout.tv_sec = curl_timeo / 1000;
	  if (timeout.tv_sec > 1)
	    {
	      timeout.tv_sec = 0;
	      timeout.tv_usec = 250000;
	    }
	  else
	    {
	      timeout.tv_usec = (curl_timeo % 1000) * 1000;
	    }
	}

      curl_multi_fdset (ykh->multi, &fdread, &fdwrite, &fdexcep, &maxfd);
      select (maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

      while (msgs)
	{
	  CURL *curl_easy;
	  struct curl_data *data;
	  char *url_used;
	  char *status;
	  CURLMsg *msg;

	  msg = curl_multi_info_read (ykh->multi, &msgs);
	  if (!msg || msg->msg != CURLMSG_DONE)
	    {
	      continue;
	    }

	  /* if we get anything other than CURLE_OK we throw away this result */
	  if (msg->data.result != CURLE_OK)
	    {
	      out = YKCLIENT_CURL_PERFORM_ERROR;
	      continue;
	    }

	  curl_easy = msg->easy_handle;

	  curl_easy_getinfo (curl_easy, CURLINFO_PRIVATE, (char **) &data);

	  if (data == 0 || data->curl_chunk_size == 0 ||
	      data->curl_chunk == NULL)
	    {
	      out = YKCLIENT_PARSE_ERROR;
	      goto finish;
	    }

	  curl_easy_getinfo (curl_easy, CURLINFO_EFFECTIVE_URL, &url_used);
	  strncpy (ykc->last_url, url_used, sizeof (ykc->last_url));

	  srv_response = ykclient_server_response_init ();
	  if (srv_response == NULL)
	    {
	      out = YKCLIENT_PARSE_ERROR;
	      goto finish;
	    }

	  out = ykclient_server_response_parse (data->curl_chunk,
						srv_response);
	  if (out != YKCLIENT_OK)
	    {
	      goto finish;
	    }

	  if (ykc->verify_signature != 0 &&
	      ykclient_server_response_verify_signature (srv_response,
							 ykc->key,
							 ykc->keylen))
	    {
	      out = YKCLIENT_BAD_SERVER_SIGNATURE;
	      goto finish;
	    }

	  status = ykclient_server_response_get (srv_response, "status");
	  if (!status)
	    {
	      out = YKCLIENT_PARSE_ERROR;
	      goto finish;
	    }

	  out = ykclient_parse_srv_error (status);
	  if (out == YKCLIENT_OK)
	    {
	      char *server_otp;

	      /* Verify that the OTP and nonce we put in our request is echoed 
	       * in the response.
	       *
	       * This is to protect us from a man in the middle sending us a 
	       * previously seen genuine response again (such as an status=OK 
	       * response even though the real server will respond 
	       * status=REPLAYED_OTP in a few milliseconds.
	       */
	      if (nonce)
		{
		  char *server_nonce =
		    ykclient_server_response_get (srv_response,
						  "nonce");
		  if (server_nonce == NULL || strcmp (nonce, server_nonce))
		    {
		      out = YKCLIENT_HMAC_ERROR;
		      goto finish;
		    }
		}

	      server_otp = ykclient_server_response_get (srv_response, "otp");
	      if (server_otp == NULL || strcmp (yubikey, server_otp))
		{
		  out = YKCLIENT_HMAC_ERROR;
		}

	      goto finish;
	    }
	  else if ((out != YKCLIENT_PARSE_ERROR) &&
		   (out != YKCLIENT_REPLAYED_REQUEST))
	    {
	      goto finish;
	    }

	  ykclient_server_response_free (srv_response);
	  srv_response = NULL;
	}
    }
  while (requests);
finish:
  if (srv_response)
    {
      ykclient_server_response_free (srv_response);
    }

  return out;
}

/** Returns the actual URL the request was sent to
 *
 * @param ykc Yubikey client configuration.
 * @return the last URL a request was send to.
 */
const char *
ykclient_get_last_url (ykclient_t * ykc)
{
  return ykc->last_url;
}

/** Generates and send requests to one or more validation servers
 *
 * Sends a request to each of the servers specified by set_url_templates and
 * validates the response.
 *
 * @param ykc Yubikey client configuration.
 * @param yubikey OTP string passed to the client.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
ykclient_rc
ykclient_request_process (ykclient_t * ykc, ykclient_handle_t * ykh,
			  const char *yubikey)
{
  ykclient_rc out;
  char *nonce = NULL;

  /* Generate nonce value */
  out = ykclient_generate_nonce (ykc, &nonce);
  if (out != YKCLIENT_OK)
    {
      goto finish;
    }

  /* Build request/template specific URLs */
  out = ykclient_expand_urls (ykc, ykh, yubikey, nonce);
  if (out != YKCLIENT_OK)
    {
      goto finish;
    }

  /* Send the request to the validation server */
  out = ykclient_request_send (ykc, ykh, yubikey, nonce);

finish:
  free (nonce);

  return out;
}

/** Generates and send requests to one or more validation servers
 *
 * Constructs a throwaway Curl handle, and sends a request to each of the
 * servers specified by set_url_templates.
 *
 * @note ykclient_request_process should be used for repeat requests as it
 * @note supports connection caching.
 *
 * @param ykc Yubikey client configuration.
 * @param yubikey OTP string passed to the client.
 * @return one of the YKCLIENT_* values or YKCLIENT_OK on success.
 */
ykclient_rc
ykclient_request (ykclient_t * ykc, const char *yubikey)
{
  ykclient_rc out;

  ykclient_handle_t *ykh;

  /* Initialise a throw away handle */
  out = ykclient_handle_init (ykc, &ykh);
  if (out != YKCLIENT_OK)
    {
      return out;
    }

  out = ykclient_request_process (ykc, ykh, yubikey);

  ykclient_handle_done (&ykh);

  return out;
}

/** Extended API to validate an OTP (hexkey) 
 * 
 * Will default to YubiCloud validation service, but may be used
 * with any service, if non-NULL ykc_in pointer is passed, and 
 * ykclient_set_url_templates is used to configure template URLs.
 *
 */
ykclient_rc
ykclient_verify_otp_v2 (ykclient_t * ykc_in,
			const char *yubikey_otp,
			unsigned int client_id,
			const char *hexkey,
			size_t urlcount,
			const char **urls, const char *api_key)
{
  ykclient_rc out;
  ykclient_t *ykc;


  if (ykc_in == NULL)
    {
      out = ykclient_init (&ykc);
      if (out != YKCLIENT_OK)
	{
	  return out;
	}
    }
  else
    {
      ykc = ykc_in;
    }

  ykclient_set_client_hex (ykc, client_id, hexkey);

  if (urlcount != 0 && *urls != 0)
    {
      if (strstr (urls[0], ADD_OTP "%s"))
	{
	  ykclient_set_url_templates (ykc, urlcount, urls);
	}
      else
	{
	  ykclient_set_url_bases (ykc, urlcount, urls);
	}
    }

  if (api_key)
    {
      ykclient_set_verify_signature (ykc, 1);
      ykclient_set_client_b64 (ykc, client_id, api_key);
    }

  out = ykclient_request (ykc, yubikey_otp);

  if (ykc_in == NULL)
    {
      ykclient_done (&ykc);
    }

  return out;
}

/** Simple API to validate an OTP (hexkey) using YubiCloud
 */
ykclient_rc
ykclient_verify_otp (const char *yubikey_otp,
		     unsigned int client_id, const char *hexkey)
{
  return ykclient_verify_otp_v2 (NULL,
				 yubikey_otp,
				 client_id, hexkey, 0, NULL, NULL);
}
