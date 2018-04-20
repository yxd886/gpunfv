#ifndef VECTOR_HH
#define VECTOR_HH

#include <type_traits>

#include "cuda_common.hh"

template<typename T>
__DEVICE__ typename remove_reference<T>::type&& move(T&& t) {
	return static_cast<typename remove_reference<T>::type&&>(t);
}

template<typename T>
class Vector {
	static constexpr uint32_t MIN_SIZE = 50;
	T *data;
	uint32_t max_size;
	uint32_t current_size;

	__DEVICE__ void double_size() {
		assert(max_size < (1 << 31));

		uint32_t new_size = max_size << 1;
		T *new_data = new T[new_size];

		assert(new_data);

		// move objects to new memory
		for(int i = 0; i < current_size; i++) {
			new_data[i] = move(data[i]);
		}

		// free old memory
		delete data;

		// set new data and max_size
		data = new_data;
		max_size = new_size;
	}

	__DEVICE__ void half_size() {
		assert(max_size >= MIN_SIZE);

		uint32_t new_size = max_size >> 1;
		T *new_data = new T[new_size];

		assert(new_data);
		assert(current_size <= new_size);

		// move objects to new memory
		for(int i = 0; i < current_size; i++) {
			new_data[i] = move(data[i]);
		}

		// free old memory
		delete data;

		// set new data and max_size
		data = new_data;
		max_size = new_size;
	}

public:
	__DEVICE__ Vector() : max_size(MIN_SIZE), current_size(0) {
		data = new T[max_size];
		assert(data);
	}

	__DEVICE__ Vector(const Vector& v) = delete;
	__DEVICE__ Vector(Vector&& v) = delete;

	__DEVICE__ ~Vector() {
		if(data) delete data;
	}

	__DEVICE__ void push_back(const T& t) {
		if(current_size == max_size) 
			double_size();

		data[current_size] = t;
		current_size++;
	}

	__DEVICE__ void push_back(T&& t) {
		if(current_size == max_size) 
			double_size();

		data[current_size] = move(t);
		current_size++;
	}

	__DEVICE__ void pop_back() {
		assert(current_size > 0);
		current_size--;

		if(max_size > MIN_SIZE && current_size < (max_size >> 2))
			half_size();
	}

	__DEVICE__ inline T& operator[](uint32_t idx) {
		assert(idx < current_size);
		return data[idx];
	}

	__DEVICE__ inline uint32_t size() {
		return current_size;
	}
}

#endif // VECTOR_HH