CC = $(CROSS)$(TARGET)gcc-9
STRIP = $(CROSS)$(TARGET)strip
BUILD_ID = $(shell date +%F_%R)
VERSION="v1.1"
GIT_VER = $(shell git describe --tags --dirty --always 2>/dev/null)
CFLAGS = -Wall -Wno-unused-result -Wshadow  -Wno-strict-aliasing -O2 -D_GNU_SOURCE -DBUILD_ID=\"$(BUILD_ID)\"
ifneq "$(GIT_VER)" ""
CFLAGS += -DGIT_VER=\"$(GIT_VER)\"
else
CFLAGS += -DGIT_VER=\"$(VERSION)\"
endif

RM = /bin/rm -f
Q = @

LIBS = -lpthread -lm -lrt ../lock/libRockey4Smart.a 

FUNCS_DIR = libfuncs
FUNCS_LIB = $(FUNCS_DIR)/libfuncs.a

TSFUNCS_DIR = libtsfuncs
TSFUNCS_LIB = $(TSFUNCS_DIR)/libtsfuncs.a

tomts_OBJS =  $(FUNCS_LIB) $(TSFUNCS_LIB) \
	iniparser.o inidict.o pidref.o data.o config.o \
	sleep.o network.o \
	input.o \
	output_psi.o output_mix.o output_write.o \
	web_pages.o web_server.o \
	tomts.o

PROGS = tomts
CLEAN_OBJS = $(PROGS) $(tomts_OBJS) *~

all: $(PROGS)
	cp -f $(PROGS) ../../bin/tomts

$(FUNCS_LIB):
	$(Q)echo "  MAKE	$(FUNCS_LIB)"
	$(Q)$(MAKE) -s -C $(FUNCS_DIR)

$(TSFUNCS_LIB):
	$(Q)echo "  MAKE	$(TSFUNCS_LIB)"
	$(Q)$(MAKE) -s -C $(TSFUNCS_DIR)

tomts: $(tomts_OBJS)
	$(Q)echo "  LINK	tomts"
	$(Q)$(CC) $(CFLAGS) $(tomts_OBJS) $(LIBS) -o tomts

%.o: %.c data.h
	$(Q)echo "  CC	tomts		$<"
	$(Q)$(CC) $(CFLAGS)  -c $<

strip:
	$(Q)echo "  STRIP	$(PROGS)"
	$(Q)$(STRIP) $(PROGS)

clean:
	$(Q)echo "  RM	$(CLEAN_OBJS)"
	$(Q)$(RM) $(CLEAN_OBJS)

distclean: clean
	$(Q)$(MAKE) -s -C $(TSFUNCS_DIR) clean
	$(Q)$(MAKE) -s -C $(FUNCS_DIR) clean
