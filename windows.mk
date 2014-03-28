# Copyright (C) 2014 Yubico AB
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

PACKAGE=ykclient
CURL_VERSION=7.36.0

all: usage 32bit 64bit

.PHONY: usage
usage:
	@if test -z "$(VERSION)" || test -z "$(PGPKEYID)"; then \
		echo "Try this instead:"; \
		echo "  make PGPKEYID=[PGPKEYID] VERSION=[VERSION]"; \
		echo "For example:"; \
		echo "  make PGPKEYID=2117364A VERSION=1.6.0"; \
		exit 1; \
	fi

doit:
	rm -rf tmp$(ARCH) && mkdir tmp$(ARCH) && cd tmp$(ARCH) && \
	mkdir -p root/licenses && \
	cp ../curl-$(CURL_VERSION).tar.gz . || \
	wget "http://curl.haxx.se/download/curl-$(CURL_VERSION).tar.gz" && \
	tar xfa curl-$(CURL_VERSION).tar.gz && \
	cd curl-$(CURL_VERSION) && \
	lt_cv_deplibs_check_method=pass_all ./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp$(ARCH)/root && \
	make install $(CHECK) && \
	cp COPYING $(PWD)/tmp$(ARCH)/root/licenses/curl.txt && \
	cd .. && \
	rm -rf root/share/ && \
	rm root/bin/curl* && \
	cp ../$(PACKAGE)-$(VERSION).tar.gz . && \
	tar xfa $(PACKAGE)-$(VERSION).tar.gz && \
	cd $(PACKAGE)-$(VERSION)/ && \
	LDFLAGS="-lws2_32" lt_cv_deplibs_check_method=pass_all PKG_CONFIG_PATH=$(PWD)/tmp$(ARCH)/root/lib/pkgconfig ./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp$(ARCH)/root && \
	make install $(CHECK) && \
	cp COPYING $(PWD)/tmp$(ARCH)/root/licenses/$(PACKAGE).txt && \
	cd ../root && \
	rm -f ../../$(PACKAGE)-$(VERSION)-win$(ARCH).zip && \
	zip -r ../../$(PACKAGE)-$(VERSION)-win$(ARCH).zip *

32bit:
	$(MAKE) -f windows.mk doit ARCH=32 HOST=i686-w64-mingw32 CHECK=check

64bit:
	$(MAKE) -f windows.mk doit ARCH=64 HOST=x86_64-w64-mingw32 CHECK=check

upload:
	@if test ! -d "$(YUBICO_GITHUB_REPO)"; then \
		echo "yubico.github.com repo not found!"; \
		echo "Make sure that YUBICO_GITHUB_REPO is set"; \
		exit 1; \
	fi
	gpg --detach-sign --default-key $(PGPKEYID) \
		$(PACKAGE)-$(VERSION)-win$(BITS).zip
	gpg --verify $(PACKAGE)-$(VERSION)-win$(BITS).zip.sig
	$(YUBICO_GITHUB_REPO)/publish $(PACKAGE) $(VERSION) $(PACKAGE)-$(VERSION)-win${BITS}.zip*

upload-32bit:
	$(MAKE) -f windows.mk upload BITS=32

upload-64bit:
	$(MAKE) -f windows.mk upload BITS=64
