# Written by Simon Josefsson <simon@josefsson.org>.
# Copyright (c) 2008, 2009 Yubico AB
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

AM_CPPFLAGS = @LIBCURL_CPPFLAGS@
ACLOCAL_AMFLAGS = -I m4

# The library.

lib_LTLIBRARIES = libykclient.la
include_HEADERS = ykclient_server_response.h ykclient.h

libykclient_la_SOURCES = ykclient_server_response.h ykclient_server_response.c	\
			ykclient.h ykclient.c
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

# Self tests.

AM_LDFLAGS = -no-install
LDADD = libykclient.la

check_PROGRAMS = selftest
TESTS = $(check_PROGRAMS)

# Release

# Dist docs from wiki.
EXTRA_DIST = doc/ReadMe.asciidoc

EXTRA_DIST += simple.mk

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

PROJECT = yubico-c-client
USER ?= simon75j
KEYID ?= B9156397

check-doc-dist:
	cd $(srcdir) && git submodule update
	cd $(srcdir)/doc && git pull
	perl -pe "s,^EXTRA_DIST = .*,EXTRA_DIST = `cd $(srcdir) && ls doc/*.asciidoc | grep -v Todo.ascii | xargs echo`," \
		< $(srcdir)/Makefile.am > check-doc-dist.tmp
	diff -ur $(srcdir)/Makefile.am check-doc-dist.tmp || \
		(rm -f check-doc-dist.tmp; echo 'error: please update $(srcdir)/Makefile.am to include all docs'; exit 1)
	rm -f check-doc-dist.tmp
	diff -ur $(srcdir)/README $(srcdir)/doc/ReadMe.asciidoc || \
		(echo 'error: README and doc/ReadMe.asciidoc does not match!'; exit 1)

release:
	rm -f ChangeLog
	make check-doc-dist ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID)! -m $(VERSION) v$(VERSION)
	cd $(srcdir) && git push --tags
	mkdir -p ../releases/$(PACKAGE)/ && \
		cp -v $(PACKAGE)-$(VERSION).tar.gz* ../releases/$(PACKAGE)/
	googlecode_upload.py -s "OpenPGP signature for $(PACKAGE) $(VERSION)." \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION).tar.gz.sig
	googlecode_upload.py -s "$(PACKAGE) $(VERSION)" \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION).tar.gz
