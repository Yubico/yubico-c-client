/* tool.c --- Command line interface to libykclient.
 *
 * Copyright (c) 2006-2013 Yubico AB
 * Copyright (c) 2012 Secure Mission Solutions
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

const char *usage =
  "Usage: ykclient [OPTION]... CLIENTID YUBIKEYOTP\n"
  "Validate the YUBIKEYOTP one-time-password against the YubiCloud\n"
  "using CLIENTID as the client identifier.\n"
  "\n"
  "Mandatory arguments to long options are mandatory for short options too.\n"
  "    --help         Display this help screen\n"
  "    --version      Display version information\n"
  "\n"
  "    --debug        Print debugging information\n"
  "    --url URL      Validation service URL, for example,\n"
  "                   \"http://api.yubico.com/wsapi/verify?id=%d&otp=%s\"\n"
  "    --ca CADIR     Path to directory containing Certificate Authoritity,\n"
  "                   e.g., \"/usr/local/etc/CERTS\"\n"
  "    --apikey Key   API key for HMAC validation of request/response\n"
  "\n"
  "Exit status is 0 on success, 1 if there is a hard failure, 2 if the\n"
  "OTP was replayed, 3 for other soft OTP-related failures.\n"
  "\n" "Report bugs at <https://github.com/Yubico/yubico-c-client>.\n";

static struct option long_options[] = {
  {"url", 1, 0, 'u'},
  {"ca", 1, 0, 'c'},
  {"apikey", 1, 0, 'a'},
  {"debug", 0, 0, 'd'},
  {"help", 0, 0, 'h'},
  {"version", 0, 0, 'V'},
  {0, 0, 0, 0}
};

/* Parse command line parameters. */
static void
parse_args (int argc, char *argv[],
	    unsigned int *client_id, char **token, char **url, char **ca,
	    char **api_key, int *debug)
{
  while (1)
    {
      int option_index = 0;

      int c = getopt_long (argc, argv, "",
			   long_options, &option_index);
      if (c == -1)
	break;

      switch (c)
	{
	case 'a':
	  if (strlen (optarg) < 16)
	    {
	      fprintf (stderr,
		       "error: API key must be at least 16 characters");
	      exit (EXIT_FAILURE);
	    }
	  *api_key = optarg;
	  break;

	case 'd':
	  *debug = 1;
	  break;

	case 'u':
	  if (strncmp ("http://", optarg, 7) != 0
	      && strncmp ("https://", optarg, 8) != 0)
	    {
	      fprintf (stderr, "error: validation url must be http or https");
	      exit (EXIT_FAILURE);
	    }
	  *url = optarg;
	  break;

	case 'c':
	  if (strlen (optarg) < 1)
	    {
	      fprintf (stderr,
		       "error: must give a valid directory containing CAs");
	      exit (EXIT_FAILURE);
	    }
	  *ca = optarg;
	  break;

	case 'h':
	  printf ("%s", usage);
	  exit (EXIT_SUCCESS);
	  break;

	case 'V':
	  printf ("%s\n", VERSION);
	  exit (EXIT_SUCCESS);
	  break;
	}
    }

  if (argc - optind != 2)
    {
      printf ("%s", usage);
      exit (EXIT_SUCCESS);
    }

  /* Now get mandatory numeric client_id */
  *client_id = strtoul (argv[optind++], NULL, 10);

  if (*client_id <= 0)
    {
      fprintf (stderr, "error: client identity must be a non-zero integer.");
      exit (EXIT_FAILURE);
    }

  /* Likewise mandatory OTP token */
  *token = argv[optind++];
  if (strlen (*token) < 32)
    {
      fprintf (stderr,
	       "error: modhex encoded token must be at least 32 characters");
      exit (EXIT_FAILURE);
    }
}

int
main (int argc, char *argv[])
{
  unsigned int client_id;
  char *token, *url = NULL, *ca = NULL, *api_key = NULL;
  int debug = 0;
  ykclient_rc ret;
  ykclient_t *ykc = NULL;

  parse_args (argc, argv, &client_id, &token, &url, &ca, &api_key, &debug);

  if (ca)
    {
      ret = ykclient_init (&ykc);
      if (ret != YKCLIENT_OK)
	return EXIT_FAILURE;

      ykclient_set_ca_path (ykc, ca);
    }

  if (debug)
    {
      fprintf (stderr, "Input:\n");
      if (url)
	fprintf (stderr, "  validation URL: %s\n", url);
      if (ca)
	fprintf (stderr, "  CA Path: %s\n", ca);
      fprintf (stderr, "  client id: %d\n", client_id);
      fprintf (stderr, "  token: %s\n", token);
      if (api_key != NULL)
	fprintf (stderr, "  api key: %s\n", api_key);
    }

  ret = ykclient_verify_otp_v2 (ykc, token, client_id, NULL, 1,
				(const char **) &url, api_key);

  if (debug)
    printf ("Verification output (%d): %s\n", ret, ykclient_strerror (ret));

  if (ret == YKCLIENT_REPLAYED_OTP)
    return 2;
  else if (ret != YKCLIENT_OK)
    return 3;

  return EXIT_SUCCESS;
}
