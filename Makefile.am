
if HAVE_APPLE
# MacOS uses Homebrew to install needed packages but they aren't linked for
# the jansson test in configure. Ignore the failed test & link them now,
# different path for different CPU arch.

if ARCH_ARM64
  EXTRA_INCLUDES = -I/opt/homebrew/include
  EXTRA_LIBS     = -L/opt/homebrew/lib
else
  EXTRA_INCLUDES = -I/usr/local/include
  EXTRA_LIBS     = -L/usr/local/lib
endif

else

if WANT_JANSSON
# Can't find jansson libraries, compile the included source code.
  EXTRA_INCLUDES = -I$(top_srcdir)/compat/jansson
  EXTRA_LIBS     = -L$(top_srcdir)/compat/jansson
else
  EXTRA_INCLUDES =
  EXTRA_LIBS     =
endif

endif

EXTRA_DIST = example-cfg.json nomacro.pl

SUBDIRS = compat

ALL_INCLUDES = @PTHREAD_FLAGS@ -fno-strict-aliasing $(EXTRA_INCLUDES) -I.

bin_PROGRAMS = soj

dist_man_MANS = soj.1

soj_SOURCES = \
  dummy.cpp \
  soj.c \
  soj_work.c \
  soj_protocol.c \
  soj_queue.c \
  soj_stratum_transport.c \
  soj_stratum_methods.c \
  util.c \
  soj_cpu.c \
  algo-gate-api.c\
  simd-utils/simd-constants.c \
  algo/civiclight/civiclight.c \
  algo/civiclight/civiclight_stats.c \
  algo/civiclight/yespower/yespower-opt.c \
  algo/civiclight/yespower/yespower-avx512.c \
  algo/civiclight/yespower/yespower_sha256.c \
  algo/sha/sha1.c \
  algo/sha/sha1-hash.c \
  algo/sha/sha256-hash.c \
  algo/sha/sph_sha2.c \
  algo/sha/sha256d.c

if HAVE_WINDOWS
   soj_SOURCES += compat/winansi.c
endif

if USE_ASM
   disable_flags =
else
   disable_flags = -DNOASM
endif

soj_LDFLAGS = @LDFLAGS@
soj_LDADD	= $(EXTRA_LIBS) @LIBCURL@ -lcurl -lz -ljansson @PTHREAD_LIBS@ @WS2_LIBS@ -lgmp -lssl -lcrypto
soj_CPPFLAGS = @LIBCURL_CPPFLAGS@ $(ALL_INCLUDES)
soj_CFLAGS = -Wno-pointer-sign -Wno-pointer-to-int-cast $(disable_flags)

if ARCH_ARM64
   soj_CFLAGS += -flax-vector-conversions
endif

if HAVE_WINDOWS

# use to profile an object
# gprof_cflags = -pg -g3
# soj_LDFLAGS += -pg
# soj_CFLAGS += -fno-inline-functions -static

# copy/paste from generated Makefile
common_ccflags = $(DEFS) $(ALL_INCLUDES) $(soj_CPPFLAGS) $(CPPFLAGS) $(soj_CFLAGS) $(CFLAGS)

endif
