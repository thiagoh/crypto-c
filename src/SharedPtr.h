/*
 * Crypto.h
 *
 *  Created on: Jul 29, 2015
 *      Author: Thiago Andrade
 */

#ifndef SRC_SHARED_PTR_H_
#define SRC_SHARED_PTR_H_

template<typename T>
class SharedPtr {
public:
	SharedPtr(T* ptr) : _ptr(ptr), _c(0) {
		_c = new Counter(0);
		_c->addRef();
	}
	SharedPtr(const SharedPtr<T>& rhs) :
			_ptr(rhs._ptr), _c(rhs._c) {
		_addRef(rhs);
	}
	SharedPtr<T>& operator=(const SharedPtr<T>& rhs) {
		if (this == &rhs) {
			return *this;
		}
		_c->releaseRef();
		_addRef(rhs);
		return *this;
	}
	virtual ~SharedPtr() {
		_c->releaseRef();
		if (_c->get() == 0) {
			delete _ptr;
			delete _c;
		}
	}
	T& operator*() {
		return *_ptr;
	}
	T* operator->() {
		return _ptr;
	}
	T* get() {
		return _ptr;
	}
private:

	void _addRef(const SharedPtr<T>& rhs) {
		_ptr = rhs._ptr;
		_c = rhs._c;
		_c->addRef();
	}

	class Counter {
	public:
		Counter(unsigned int c) :
				_refs(c) {
		}
		Counter(const Counter& rhs) :
				_refs(rhs._refs) {
		}
		~Counter() {
		}
		unsigned int get() {
			return _refs;
		}
		void addRef() {
			++_refs;
		}

		void releaseRef() {
			--_refs;
		}

	private:
		unsigned int _refs;
	};
	T* _ptr;
	Counter* _c;
};

#endif /* SRC_SHARED_PTR_H_ */

