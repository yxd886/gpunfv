nvcc -ccbin g++ -I/usr/local/cuda-8.0/samples/common/inc  -m64    -gencode arch=compute_20,code=sm_20 -gencode arch=compute_30,code=sm_30 -gencode arch=compute_35,code=sm_35 -gencode arch=compute_37,code=sm_37 -gencode arch=compute_50,code=sm_50 -gencode arch=compute_52,code=sm_52 -gencode arch=compute_60,code=sm_60 -gencode arch=compute_60,code=compute_60 -o vectorAdd.o -c vectorAdd.cu


c++ -c playground.cc -I/usr/local/cuda-8.0/samples/common/inc -I/usr/local/cuda-8.0/include `pkg-config --cflags --libs $SEASTAR/build/release/seastar.pc`

c++ -o playground.out vectorAdd.o playground.o `pkg-config --cflags --libs $SEASTAR/build/release/seastar.pc` -L/usr/local/cuda-8.0/lib64 -lcudart
