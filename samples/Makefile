# Disable all implicit Makefile rules
MAKEFLAGS += --no-builtin-rules
.SUFFIXES: ;

CXX =c++
CUCXX =/usr/local/cuda-8.0/bin/nvcc


VERBOSE ?= 1

DEPDIR ?= .deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(DEPDIR)/$(@:.o=.d)
CUDEPFLAGS = -MT $@ -Xcompiler -MMD,-MP,-MF$(DEPDIR)/$(@:.o=.d)
$(shell mkdir -p $(DEPDIR) >/dev/null)
$(shell mkdir -p $(DEPDIR)/samples > /dev/null)


# e.g., 4.9.3 -> 40903
CXXVERSION := $(shell g++ -dumpversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$$/&00/')

CXXVERSION_4_8_OR_HIGHER := $(shell expr $(CXXVERSION) \>= 40800)
ifeq "$(CXXVERSION_4_8_OR_HIGHER)" "0"
  $(error g++ 4.8 or higher is required)
endif

RTE_SDK ?= $(abspath /home/net/gpunfv/seastar/dpdk)
RTE_TARGET ?= $(shell uname -m)-native-linuxapp-gcc
DPDK_LIB ?= dpdk
SEASTAR=/home/net/gpunfv/seastar

ifneq ($(wildcard $(RTE_SDK)/$(RTE_TARGET)/*),)
    DPDK_INC_DIR = $(RTE_SDK)/$(RTE_TARGET)/include
    DPDK_LIB_DIR = $(RTE_SDK)/$(RTE_TARGET)/lib
else ifneq ($(wildcard $(RTE_SDK)/build/*),)
    # if the user didn't do "make install" for DPDK
    DPDK_INC_DIR = $(RTE_SDK)/build/include
    DPDK_LIB_DIR = $(RTE_SDK)/build/lib
else
    ifeq ($(words $(MAKECMDGOALS)),1)
        ifneq ($(MAKECMDGOALS),clean)
            $(error DPDK is not available. \
                    Make sure $(abspath $(RTE_SDK)) is available and built)
        endif
    endif
endif
SEASTAR_FLAGS:=$(shell pkg-config --cflags --libs $(SEASTAR)/build/release/seastar.pc)

CUDA_INC_DIR= /usr/local/cuda-8.0/samples/common/inc /usr/local/cuda-8.0/include


CXXFLAGS += -std=gnu++11 -g3 -ggdb3 -Ofast -march=native \
	    -isystem $(DPDK_INC_DIR) -isystem /usr/local/cuda-8.0/samples/common/inc -isystem /usr/local/cuda-8.0/include $(SEASTAR_FLAGS)
	    
CUDAFLAGS += -I/usr/local/cuda-8.0/samples/common/inc -gencode arch=compute_60,code=sm_60 -gencode arch=compute_60,code=compute_60 -rdc=true -I/usr/local/cuda-8.0/include -I$(DPDK_INC_DIR)

CUDA_LINK_FLAGS += -dlink -I/usr/local/cuda-8.0/samples/common/inc -gencode arch=compute_60,code=sm_60 -gencode arch=compute_60,code=compute_60  -I/usr/local/cuda-8.0/include -I$(DPDK_INC_DIR)
LDFLAGS += $(SEASTAR_FLAGS) -L/usr/local/cuda-8.0/lib64

LIBS +=-lcudart -lcudadevrt -lcublas_device

ALL_SRCS = $(wildcard ./*.cc ) 
                      
HEADERS =  $(wildcard ./*.h )

CU_HEADERS =  $(wildcard ./*.cuh )

CU_SRCS = $(wildcard ./*.cu)


SRCS =  $(ALL_SRCS)
OBJS = $(SRCS:.cc=.o)
CU_OBJS = $(CU_SRCS:.cu=.o)
CU_LINK_OBJS = $(CU_OBJS:.o =.l)

# The following variables are defined for sample examples.

#SAMPLES_SRCS = $(wildcard samples/*.cc)
#SAMPLES_SRCS += $(wildcard samples/*/*.cc)
#SAMPLES_OBJS = $(SAMPLES_SRCS:.cc=.o)

PLAYGROUND_EXEC = playground
PLAYGROUND_OBJS = playground.o $(CU_OBJS) $(CU_LINK_OBJS)

L2_FORWARD_EXEC = l2_forward
L2_FORWARD_OBJS = l2_forward.o $(CU_OBJS) $(CU_LINK_OBJS)


.PHONY: all clean tests protobuf

all: $(CU_OBJS) $(CU_LINK_OBJS) $(OBJS) $(PLAYGROUND_EXEC) $(L2_FORWARD_EXEC)

clean:
	rm -rf $(EXEC) .deps/*.d .deps/*/*.d *_test */*_test *_bench */*_bench \
		*.a *.pb.* *.o */*.o *.l */*.l *.gcda *.gcno */*.gcda */*.gcno \
		coverage.info coverage_html */*.pb.cc */*.pb.h

# This build wrapper takes 4 parameters:
# $(1): build type (CXX, LD, ...)
# $(2): Make target
# $(3): Make prerequisites
# $(4): command
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

$(eval $(call BUILD, \
	CUDACXX, \
	%.o, \
	%.cu $(CU_HEADERS) $(DEPDIR)/$$@.d, \
	$$(CUCXX) -o $$@ -c $$< $$(CUDAFLAGS) $$(CUDEPFLAGS)))
	
	
$(eval $(call BUILD, \
	CUDACXX, \
	%.l, \
	%.o $(CU_HEADERS) $(DEPDIR)/$$@.d, \
	$$(CUCXX) -o $$ $$< $$(CUDA_LINK_FLAGS) $$(CUDEPFLAGS)))
	


$(eval $(call BUILD, \
	CXX, \
	%.o, \
	%.cc $(PROTO_HEADERS) $(DEPDIR)/$$@.d, \
	$$(CXX) -o $$@ -c $$< $$(CXXFLAGS) $$(DEPFLAGS)))
	

CORE_OBJS = $(OBJS)

$(eval $(call BUILD, \
	AR, \
	bess.a, \
	$(CORE_OBJS), \
	$$(AR) rcs $$@ $$^))

# The rule for linking samples are added below here.
	
$(eval $(call BUILD, \
	LD, \
	$$(PLAYGROUND_EXEC), \
	$$(PLAYGROUND_OBJS), \
	$$(CXX) -o $$@ $$^ $$(LDFLAGS) $$(LIBS)))

$(eval $(call BUILD, \
	LD, \
	$$(L2_FORWARD_EXEC), \
	$$(L2_FORWARD_OBJS), \
	$$(CXX) -o $$@ $$^ $$(LDFLAGS) $$(LIBS)))


%.d: ;

.PRECIOUS: %.d $(PROTO_HEADERS)

-include $(patsubst %,$(DEPDIR)/%.d,$(basename $(ALL_SRCS)))
