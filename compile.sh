nvcc -ccbin g++ -I/usr/local/cuda-8.0/samples/common/inc  -m64    -gencode arch=compute_20,code=sm_20 -gencode arch=compute_30,code=sm_30 -gencode arch=compute_35,code=sm_35 -gencode arch=compute_37,code=sm_37 -gencode arch=compute_50,code=sm_50 -gencode arch=compute_52,code=sm_52 -gencode arch=compute_60,code=sm_60 -gencode arch=compute_60,code=compute_60 -o vectorAdd.o -c vectorAdd.cu


c++ -c playground.cc -I/usr/local/cuda-8.0/samples/common/inc -I/usr/local/cuda-8.0/include `pkg-config --cflags --libs $SEASTAR/build/release/seastar.pc`


nvcc -o playground.out vectorAdd.o playground.o  -Xlinker --whole-archive,-lseastar,--no-whole-archive -std=c++11 -Xcompiler -g,-Wall,-Werror,-Wno-error=deprecated-declarations,-fvisibility=hidden,-pthread -I/home/net/async-nf/seastar -U_FORTIFY_SOURCE -DHAVE_DPDK -I/home/net/async-nf/seastar/build/dpdk/include,-march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2 -Xcompiler -Wno-error=literal-suffix,-Wno-literal-suffix,-Wno-invalid-offsetof -I/home/net/async-nf/seastar/fmt -DBOOST_TEST_DYN_LINK -Xcompiler -Wno-overloaded-virtual,-Wno-maybe-uninitialized -DFMT_HEADER_ONLY -DHAVE_HWLOC -DHAVE_NUMA -DHAVE_LZ4_COMPRESS_DEFAULT -Xlinker --no-as-needed,-laio,-lboost_program_options,-lboost_system,-lboost_filesystem,-lstdc++,-lm,-lboost_thread,-lcryptopp,-lrt,-lgnutls,-lgnutlsxx,-llz4,-lprotobuf,-ldl,-lgcc_s,-lunwind -Xlinker  -lrte_pmd_vmxnet3_uio -lrte_pmd_i40e -lrte_pmd_ixgbe -lrte_pmd_e1000 -lrte_pmd_ring -lrte_pmd_bnxt -lrte_pmd_cxgbe -lrte_pmd_ena -lrte_pmd_enic -lrte_pmd_fm10k -lrte_pmd_nfp -lrte_pmd_qede -lrte_pmd_sfc_efx -lrte_hash -lrte_kvargs -lrte_mbuf -lrte_ethdev -lrte_eal -lrte_mempool -lrte_mempool_ring -lrte_ring -lrte_cmdline -lrte_cfgfile -lrt -lm -ldl -lhwloc -lnuma -lpciaccess -lxml2 -lz -lcares-seastar -L ~/async-nf/seastar/build/release -L ~/async-nf/seastar/dpdk/x86_64-native-linuxapp-gcc/lib
