NAME     = connectfolder
VERSION  = 2.0.0
PREFIX  ?= /usr
DESTDIR ?=
PYTHON  ?= python3

DATADIR  = $(PREFIX)/share/$(NAME)
LIBEXEC  = $(PREFIX)/libexec/$(NAME)
DEMO_ROOT = $(HOME)/.cache/connectfolder-demo-root

SOURCES  = connectfolder_core.py connectfolder_gui.py connectfolder-helper \
           Makefile connectfolder.spec README.md \
           data/connectfolder data/io.github.lazermin.ConnectFolder.desktop \
           data/io.github.lazermin.connectfolder.policy \
           tests/test_core.py tests/demo_seed.py

.PHONY: all install uninstall test demo demo-reset dist rpm clean

all:
	@echo "Цели: install, uninstall, test, demo, demo-reset, dist, rpm"

install:
	install -Dm644 connectfolder_core.py $(DESTDIR)$(DATADIR)/connectfolder_core.py
	install -Dm644 connectfolder_gui.py  $(DESTDIR)$(DATADIR)/connectfolder_gui.py
	install -Dm755 connectfolder-helper  $(DESTDIR)$(LIBEXEC)/connectfolder-helper
	install -Dm755 data/connectfolder    $(DESTDIR)$(PREFIX)/bin/connectfolder
	install -Dm644 data/io.github.lazermin.ConnectFolder.desktop \
	    $(DESTDIR)$(PREFIX)/share/applications/io.github.lazermin.ConnectFolder.desktop
	install -Dm644 data/io.github.lazermin.connectfolder.policy \
	    $(DESTDIR)$(PREFIX)/share/polkit-1/actions/io.github.lazermin.connectfolder.policy

uninstall:
	rm -rf $(DESTDIR)$(DATADIR) $(DESTDIR)$(LIBEXEC)
	rm -f $(DESTDIR)$(PREFIX)/bin/connectfolder \
	      $(DESTDIR)$(PREFIX)/share/applications/io.github.lazermin.ConnectFolder.desktop \
	      $(DESTDIR)$(PREFIX)/share/polkit-1/actions/io.github.lazermin.connectfolder.policy

test:
	$(PYTHON) tests/test_core.py -v

demo-reset:
	$(PYTHON) tests/demo_seed.py $(DEMO_ROOT)

demo:
	@test -d $(DEMO_ROOT) || $(PYTHON) tests/demo_seed.py $(DEMO_ROOT)
	CONNECTFOLDER_DEMO=1 $(PYTHON) connectfolder_gui.py

dist:
	rm -rf $(NAME)-$(VERSION)
	mkdir -p $(NAME)-$(VERSION)
	tar cf - $(SOURCES) | tar xf - -C $(NAME)-$(VERSION)
	tar czf $(NAME)-$(VERSION).tar.gz $(NAME)-$(VERSION)
	rm -rf $(NAME)-$(VERSION)

rpm: dist
	mkdir -p $(HOME)/rpmbuild/SOURCES
	cp $(NAME)-$(VERSION).tar.gz $(HOME)/rpmbuild/SOURCES/
	rpmbuild -ba connectfolder.spec

clean:
	rm -rf $(NAME)-$(VERSION) $(NAME)-$(VERSION).tar.gz __pycache__ tests/__pycache__
