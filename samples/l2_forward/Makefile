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

RTE_SDK ?= $(abspath /home/net/gpunfv/dpdk)
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


CUDA_INC_DIR= /usr/local/cuda-8.0/samples/common/inc /usr/local/cuda-8.0/include


CXXFLAGS += -std=gnu++11 -g3 -ggdb3 -Ofast -march=native \
	    -isystem $(DPDK_INC_DIR) -isystem /usr/local/cuda-8.0/samples/common/inc -isystem /usr/local/cuda-8.0/include -fopenmp

	    
CUDAFLAGS += -I/usr/local/cuda-8.0/samples/common/inc -gencode arch=compute_60,code=sm_60 -gencode arch=compute_60,code=compute_60 -rdc=true -I/usr/local/cuda-8.0/include -I$(DPDK_INC_DIR)

CUDA_LINK_FLAGS += -dlink -I/usr/local/cuda-8.0/samples/common/inc -gencode arch=compute_60,code=sm_60 -gencode arch=compute_60,code=compute_60  -I/usr/local/cuda-8.0/include -I$(DPDK_INC_DIR)
LDFLAGS += -L/usr/local/cuda-8.0/lib64 -L$(DPDK_LIB_DIR) -fopenmp

LIBS += -lcudart -lcudadevrt -lcublas_device -Wl,--no-whole-archive -std=gnu++1y -g -Wall -Werror -Wno-error=deprecated-declarations -fvisibility=hidden -pthread -I/home/net/gpunfv/seastar -U_FORTIFY_SOURCE -DHAVE_DPDK -I/home/net/gpunfv/seastar/build/dpdk/include -march=native  -Wno-error=literal-suffix -Wno-literal-suffix -Wno-invalid-offsetof -Wno-overloaded-virtual -Wno-maybe-uninitialized -Wl,--no-as-needed -laio -lboost_program_options -lboost_system -lboost_filesystem -lstdc++ -lm -lboost_thread -lcryptopp -lrt -lgnutls -lgnutlsxx -llz4 -lprotobuf -ldl -lgcc_s -lunwind -Wl,--whole-archive -lrte_pmd_vmxnet3_uio -lrte_pmd_i40e -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring -lrte_pmd_bnxt -lrte_pmd_cxgbe -lrte_pmd_ena -lrte_pmd_enic -lrte_pmd_fm10k -lrte_pmd_nfp -lrte_pmd_qede -lrte_pmd_sfc_efx -lrte_hash -lrte_kvargs -lrte_mbuf -lrte_ethdev -lrte_eal -lrte_mempool -lrte_mempool_ring -lrte_ring -lrte_cmdline -lrte_cfgfile -Wl,--no-whole-archive -lrt -lm -ldl -lhwloc -lnuma -lpciaccess -lxml2 -lz

ALL_SRCS = $(wildcard ./*.cc ) 
                      
HEADERS =  $(wildcard ./*.h ../*.h)

CU_HEADERS =  $(wildcard ./*.cuh ../*.cuh )

CU_SRCS = $(wildcard ./*.cu ../*.cu)


SRCS =  $(ALL_SRCS)
OBJS = $(SRCS:.cc=.o)
CU_OBJS = $(CU_SRCS:.cu=.o)
CU_LINK_OBJS = $(CU_SRCS:.cu=.l)
SAMPLE_OBJS = l2_forward.o

# The following variables are defined for sample examples.

#SAMPLES_SRCS = $(wildcard samples/*.cc)
#SAMPLES_SRCS += $(wildcard samples/*/*.cc)
#SAMPLES_OBJS = $(SAMPLES_SRCS:.cc=.o)


L2_FORWARD_EXEC = l2_forward
L2_FORWARD_OBJS = $(filter-out main.o $(filter-out l2_forward.o,$(SAMPLES_OBJS)),$(OBJS))  $(CU_OBJS) $(CU_LINK_OBJS)


.PHONY: all clean tests protobuf

all: $(CU_OBJS) $(CU_LINK_OBJS) $(OBJS) $(L2_FORWARD_EXEC)

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
	$$(CUCXX) -o $$@ $$< $$(CUDA_LINK_FLAGS) $$(CUDEPFLAGS)))
	


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
	$$(L2_FORWARD_EXEC), \
	$$(L2_FORWARD_OBJS), \
	$$(CXX) -o $$@ $$^ $$(LDFLAGS) $$(LIBS)))


%.d: ;

.PRECIOUS: %.d $(PROTO_HEADERS)

-include $(patsubst %,$(DEPDIR)/%.d,$(basename $(ALL_SRCS)))