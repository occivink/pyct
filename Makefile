debug ?= yes
static ?= no

sources := $(sort $(wildcard *.cpp))
objects := $(addprefix ., $(sources:.cpp=$(suffix).o))
deps := $(addprefix ., $(sources:.cpp=$(suffix).d))

PREFIX ?= /usr/local
DESTDIR ?= # root dir

bindir := $(DESTDIR)$(PREFIX)/bin

CXXFLAGS += -pedantic -std=c++14 -g -Wall -Wextra

all : pyct

pyct : $(objects)
	$(CXX) $(LDFLAGS) $(CXXFLAGS) $(objects) $(LIBS) -o $@

-include $(deps)

.%$(suffix).o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MD -MP -MF $(addprefix ., $(<:.cpp=$(suffix).d)) -c -o $@ $<

clean:
	rm -f .*.o .*.d

distclean: clean
	rm -f pyct pyct$(suffix)

installdirs:
	install -d $(bindir) \
		$(sharedir)/rc/base \
		$(sharedir)/rc/core \
		$(sharedir)/rc/extra \
		$(sharedir)/colors \
		$(docdir)/manpages \
		$(mandir)

install: pyct man doc installdirs
	install -m 0755 pyct $(bindir)

.PHONY: check TAGS clean distclean installdirs install install-strip uninstall
.PHONY: tags test man doc pyct
