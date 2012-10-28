SILENCE = @

# CppUTest Inputs
CPPUTEST_HOME = TestSpecificCode/CppUTest
CPP_PLATFORM = Gcc
#CPPUTEST_EXE_FLAGS += -v
CPPUTEST_USE_EXTENSIONS = Y
CPPUTEST_USE_MEM_LEAK_DETECTION = Y
CPPUTEST_USE_GCOV = Y
CPPFLAGS += -I$(CPPUTEST_HOME)/include 
CPPUTEST_OBJS_DIR = bin/objs
CPPUTEST_LIB_DIR = bin/lib

TESTING_DIR = TestSpecificCode

# CppUTest Outputs
COMPONENT_NAME = Router
TARGET_LIB = lib/lib$(COMPONENT_NAME).a
TEST_TARGET = $(COMPONENT_NAME)_tests

SRC_DIRS = 

SRC_FILES = sr_router.c sr_arpcache.c sr_utils.c sr_if.c

TEST_SRC_DIRS = $(TESTING_DIR)/tests

TEST_SRC =

MOCKS_SRC_DIRS = $(TESTING_DIR)/mocks

MOCKS_SRC = 

INCLUDE_DIRS = . \
	$(CPPUTEST_HOME)/include

CPPUTEST_CFLAGS += -g -Wall -ansi -D_DEBUG_ -D_GNU_SOURCE -D_LINUX_ -std=c99
CPPUTEST_CXXFLAGS += -std=c++0x
CPPUTEST_WARNINGFLAGS = -Wall -Wextra -Wshadow

LD_LIBRARIES = -L $(CPPUTEST_HOME)/lib -l CppUTest -l CppUTestExt -lm -lpthread -lnsl -lresolv
#LDFLAGS += $(CPPUTEST_HOME)/lib/libCppUTest.a -lstdc++

include $(CPPUTEST_HOME)/build/MakefileWorker.mk 
