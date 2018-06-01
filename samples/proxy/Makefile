# Disable all implicit Makefile rules
MAKEFLAGS += --no-builtin-rules
.SUFFIXES: ;

################################################################

# target name
EXEC = proxy

# compilers
CXX = c++
CUCXX = /usr/local/cuda-8.0/bin/nvcc

# linker
LD = c++

# Seastar path
#SEASTAR = /home/net/jjwang/gpunfv/seastar

# CUDA path
CUDA = /usr/local/cuda-8.0


###############################################################
LIBEVENT_INC_DIR=/home/net/gpunfv/libevent
# check CXX version
# e.g., 4.9.3 -> 40903
CXXVERSION = $(shell $(CXX) -dumpversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$$/&00/')
CXXVERSION_4_8_OR_HIGHER = $(shell expr $(CXXVERSION) \>= 40800)
ifeq "$(CXXVERSION_4_8_OR_HIGHER)" "0"
  $(error g++ 4.8 or higher is required)
endif


# CUDA inc path
CUDA_INC_DIR = $(CUDA)/samples/common/inc $(CUDA)/include

# dependency directory
DEPDIR = .deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$(@:.o=.d)
CUDEPFLAGS = -MT $@ -Xcompiler -MMD,-MP,-MF$(DEPDIR)/$(@:.o=.d)
$(shell mkdir -p $(DEPDIR) > /dev/null)

#########################################################################################

# Seastar flags
#SEASTAR_CFLAGS = $(shell pkg-config --cflags $(SEASTAR)/build/release/seastar.pc)
#SEASTAR_LDFLAGS = $(shell pkg-config --libs $(SEASTAR)/build/release/seastar.pc)

# CUDA flags	    
CUDA_CFLAGS = $(addprefix -I  ,$(CUDA_INC_DIR)) 
CUDA_LDFLAGS = -L$(CUDA)/lib64

# c++ flags
CXXFLAGS = -std=gnu++11 -g3 -ggdb3 -Ofast -march=native \
	    $(addprefix -isystem ,$(CUDA_INC_DIR) $(LIBEVENT_INC_DIR)) 

# link flags
LDFLAGS = $(CUDA_LDFLAGS)

#LIBS += -lcudart -lrte_mempool -lrte_mempool_ring -lrte_mempool_stack -lrte_eal
LIBS += -lcudart  -Wl,--whole-archive -Wl,--no-whole-archive -lpthread -ldl -levent -levent_openssl -lssl -lcrypto
#LIBS += -lcudart -lpthread  \
 -Wl,--whole-archive -lrte_pmd_i40e \
 -lrte_hash -lrte_kvargs -lrte_mbuf -lrte_ethdev -lrte_eal -lrte_mempool -lrte_mempool_ring -lrte_ring \
 -lrte_cmdline -lrte_cfgfile -Wl,--no-whole-archive -ldl 

# C++ sources and headers  
CC_SRCS = $(wildcard *.cc )        
CC_HEADERS =  $(wildcard *.hh)

# CUDA sources and headers
CUDA_SRCS = $(wildcard *.cu)
CUDA_HEADERS = $(wildcard *.cuh)

# all sources and objects
SRCS = $(CC_SRCS) $(CUDA_SRCS)
OBJS = $(addsuffix .o, $(basename $(SRCS)))
HEADERS = $(CC_HEADERS) $(CUDA_HEADERS)

# This build wrapper takes 4 parameters:
# $(1): build type (CXX, LD, ...)
# $(2): Make target
# $(3): Make prerequisites
# $(4): command
VERBOSE ?= 1

define BUILD
$(2): $(3)
	$$(eval _TYPE = $$(strip $(1)))
	$$(eval _CMD = $$(strip $(4)))
	@if [ $$(VERBOSE) -eq 0 ]; then \
		printf "%-11s %s\n" "[$$(_TYPE)]" "$$@"; \
	else \
		printf "%-11s %s\n" "[$$(_TYPE)]" "$$(_CMD)"; \
	fi
	@if ! $$(_CMD); then \
		echo "Error: \033[0;31m$$@"; \
		echo "\033[0;33m$$(_CMD)\033[0m"; \
		false; \
	fi
endef

#################################################################################
#							target rules
#################################################################################

.PHONY: all build clean

all: build 

build: $(EXEC)

$(EXEC): $(OBJS)

clean:
	rm -rf $(OBJS) $(EXEC) .deps

# .cc -> .o
$(eval $(call BUILD, \
	CXX, \
	%.o, \
	%.cc $(CC_HEADERS) $(DEPDIR)/$$@.d, \
	$$(CXX) -o $$@ -c $$< $$(CXXFLAGS) $$(DEPFLAGS)))
	
# .cu -> .o
$(eval $(call BUILD, \
	NVCC, \
	%.o, \
	%.cu $(CUDA_HEADERS) $(DEPDIR)/$$@.d, \
	$$(CUCXX) -o $$@ -c $$< $$(CUDA_CFLAGS) $$(CUDEPFLAGS)))
	
# Link
$(eval $(call BUILD, \
	LD, \
	$$(EXEC), \
	$$(OBJS), \
	$$(LD) -o $$@ $$^ $$(LDFLAGS) $$(LIBS)))
	

%.d: ;

.PRECIOUS: %.d 

# include rules in .d files
-include $(patsubst %,$(DEPDIR)/%.d,$(basename $(CC_SRCS)))
