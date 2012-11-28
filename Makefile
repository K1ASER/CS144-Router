#------------------------------------------------------------------------------
# File: Makefile
# 
# Note: This Makefile requires GNU make.
# 
# (c) 2001,2000 Stanford University
#
#------------------------------------------------------------------------------

SILENCE = @

all : sr

CC = gcc

OSTYPE = $(shell uname)

ifeq ($(OSTYPE),CYGWIN_NT-5.1)
ARCH = -D_CYGWIN_
endif

ifeq ($(OSTYPE),Linux)
ARCH = -D_LINUX_
SOCK = -lnsl -lresolv
endif

ifeq ($(OSTYPE),SunOS)
ARCH =  -D_SOLARIS_
SOCK = -lnsl -lsocket -lresolv
endif

ifeq ($(OSTYPE),Darwin)
ARCH = -D_DARWIN_
SOCK = -lresolv
endif

CFLAGS = -g -Wall -ansi -D_DEBUG_ -D_GNU_SOURCE $(ARCH)

LIBS= $(SOCK) -lm -lpthread
PFLAGS= -follow-child-processes=yes -cache-dir=/tmp/${USER} 
PURIFY= purify ${PFLAGS}

# Paths that make will use to try and find header files
INCLUDE_DIRS = .

# Add any source files you've added here
SRCS = sr_router.c sr_main.c sr_if.c sr_rt.c sr_vns_comm.c sr_utils.c sr_dumper.c \
	sr_arpcache.c sha1.c

# Directory for object and dependancy files (executables will be built in the 
# same folder as the client source)
OBJS_DIR = bin

# Helper Functions
get_src_from_dir = $(wildcard $1/*.cpp) $(wildcard $1/*.c)
get_dirs_from_dirspec = $(wildcard $1)
get_src_from_dir_list = $(foreach dir, $1, $(call get_src_from_dir,$(dir)))
__src_to = $(subst .c,$1, $(subst .cpp,$1,$2))
src_to = $(addprefix $(OBJS_DIR)/,$(call __src_to,$1,$2))
src_to_o = $(call src_to,.o,$1)
src_to_d = $(call src_to,.d,$1)
debug_print_list = $(foreach word,$1,echo " $(word)";) echo;

OBJS = $(call src_to_o,$(SRCS))
INCLUDES_DIRS_EXPANDED = $(call get_dirs_from_dirspec, $(INCLUDE_DIRS))
INCLUDES += $(foreach dir, $(INCLUDES_DIRS_EXPANDED), -I$(dir))
DEP = $(call src_to_d, $(SRCS))

STUFF_TO_CLEAN = sr $(OBJS) $(DEP)

$(OBJS_DIR)/%.o: %.cpp
	@echo Compiling $(notdir $<)
	$(SILENCE)mkdir -p $(dir $@)
	$(SILENCE)$(COMPILE.cpp) $(INCLUDES) -MMD -MP $(OUTPUT_OPTION) $<

# Not that we should have any C sources, just covering my bases.
$(OBJS_DIR)/%.o: %.c
	@echo Compiling $(notdir $<)
	$(SILENCE)mkdir -p $(dir $@)
	$(SILENCE)$(COMPILE.c) -c $(INCLUDES) -MMD -MP $(OUTPUT_OPTION) $<

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEP)
endif	

sr : $(OBJS)
	@echo Linking $(notdir $@)
	$(SILENCE)$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS) 

sr.purify : $(OBJS)
	$(PURIFY) $(CC) $(CFLAGS) -o sr.purify $(OBJS) $(LIBS)

tests:
	$(SILENCE)make -f TestSpecificCode/build/TestingMakefile.mk gcov

.PHONY : clean clean-deps dist    

clean:
	@echo Cleaning Project
	$(SILENCE)$(RM) $(STUFF_TO_CLEAN)
	$(SILENCE)$(RM) -r $(OBJS_DIR)
	$(SILENCE)$(RM) *.tar tags
#	$(SILENCE)make -f TestSpecificCode/build/TestingMakefile.mk clean

dist-clean: clean
	rm -f .*.swp sr_stub.tar.gz

dist: dist-clean 
	(cd ..; tar -X stub/exclude -cvf sr_stub.tar stub/; gzip sr_stub.tar); \
    mv ../sr_stub.tar.gz .

tags:
	ctags *.c
	
submit:
	@tar -czf router-submit.tar.gz $(SRCS) *.h README Makefile

debug:
	@echo
	@echo "Target Source files:"
	@$(call debug_print_list,$(SRCS))
	@echo "Target Object files:"
	@$(call debug_print_list,$(OBJS))
	@echo Stuff to clean:
	@$(call debug_print_list,$(STUFF_TO_CLEAN))
	@echo Includes:
	@$(call debug_print_list,$(INCLUDES))

