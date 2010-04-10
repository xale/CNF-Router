CC=gcc
LDFLAGS=-lpthread
CFLAGS=-std=gnu99 -pedantic -Wall -Wextra -O
SOURCES=
DEPENDS=$(SOURCES:.c=.d)

EXECUTABLES=

.PHONY:all
all: $(DEPENDS) $(EXECUTABLES) stub_sr

.SECONDEXPANSION:
$(EXECUTABLES): $$($$@_OBJECTS)
	$(CC) $(LDFLAGS) $(CFLAGS) $^ -o $@

-include $(DEPENDS)

.PHONY:debug
debug: CFLAGS+=-g -O0
debug: all

.PHONY:stub_sr
stub_sr:
	cd stub_sr; $(MAKE) $(MFLAGS)

.PHONY:profile
profile: CFLAGS+=-pg -g -fprofile-arcs -ftest-coverage
profile: all

.PHONY:clean
clean:
	$(RM) *.o *.d *.out *.gcov *.gcda *.gcno $(EXECUTABLES)

%.d: %.c
	$(SHELL) -ec "$(CC) -M $< | sed 's/^$*.o/& $@/g' > $@"
