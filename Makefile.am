# Written by Simon Josefsson <simon@josefsson.org>.
# Copyright (c) 2008-2013 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials provided
#      with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

SUBDIRS = . tests

AM_CPPFLAGS = @LIBCURL_CPPFLAGS@
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = $(WARN_CFLAGS)

# The library.

lib_LTLIBRARIES = libykclient.la
include_HEADERS = ykclient_server_response.h ykclient.h \
	ykclient_errors.h ykclient_version.h

libykclient_la_SOURCES = ykclient_server_response.h \
			 ykclient_server_response.c
libykclient_la_SOURCES += ykclient.h ykclient_errors.h	\
			  ykclient_version.h
libykclient_la_SOURCES += ykclient.c ykclient_version.c
libykclient_la_SOURCES += rfc4634/sha.h rfc4634/sha-private.h		\
			rfc4634/hmac.c rfc4634/sha1.c rfc4634/usha.c	\
			rfc4634/sha224-256.c rfc4634/sha384-512.c
libykclient_la_SOURCES += b64/cencode.h b64/cencode.c b64/cdecode.h	\
			b64/cdecode.c
libykclient_la_LIBADD = @LIBCURL@
libykclient_la_LDFLAGS = -no-undefined \
	-export-symbols-regex '^ykclient_.*' \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

# The command line tools.

bin_PROGRAMS = ykclient

ykclient_SOURCES = tool.c
ykclient_LDADD = ./libykclient.la

# Man page

dist_man_MANS = ykclient.1
MAINTAINERCLEANFILES = $(dist_man_MANS)

ykclient.1: $(builddir)/ykclient $(srcdir)/tool.c $(srcdir)/configure.ac
	$(HELP2MAN) \
		--output=$@ $(builddir)/ykclient$(EXEEXT) \
		--name="YubiCloud One-Time-Password Validation Client" \
		--no-info

# Release

EXTRA_DIST = simple.mk

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

PROJECT = yubico-c-client

release:
	@if test -z "$(USER)" || test -z "$(KEYID)"; then \
		echo "Try this instead:"; \
		echo "  make release USER=[GOOGLEUSERNAME] KEYID=[PGPKEYID]"; \
		echo "For example:"; \
		echo "  make release USER=simon@yubico.com KEYID=2117364A"; \
		echo "  make release USER=fredrikyubico@gmail.com KEYID=4EAA4232"; \
		exit 1; \
	fi
	@head -3 $(srcdir)/NEWS | grep -q "Version $(VERSION) .released `date -I`" || \
		(echo 'error: Update date/version in $(srcdir)/NEWS.'; exit 1)
# check that non-autoconf build system works
	cd $(srcdir) &&	make -f simple.mk check clean
	rm -f $(srcdir)/ChangeLog
	make ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID)! -m $(VERSION) $(PACKAGE)-$(VERSION)
	cd $(srcdir) && git push --tags
	mkdir -p ../releases/$(PACKAGE)/ && \
		cp -v $(PACKAGE)-$(VERSION).tar.gz* ../releases/$(PACKAGE)/
	googlecode_upload.py -s "OpenPGP signature for $(PACKAGE) $(VERSION)." \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION).tar.gz.sig
	googlecode_upload.py -s "$(PACKAGE) $(VERSION)" \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION).tar.gz
