#!/bin/bash

if [ ! -f cmocka-1.0.1.tar.xz ]; then
	wget https://cmocka.org/files/1.0/cmocka-1.0.1.tar.xz
	rm -rf cmocka-1.0.1
	tar xf cmocka-1.0.1.tar.xz

	rm -rf cmocka-build || true
	mkdir cmocka-build

	cd cmocka-build
	cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug -DUNIT_TESTING=ON ../cmocka-1.0.1
    make
    sudo make install
	cd ..
fi

rm -rf build || true
mkdir build
cd build

cmake -G"Eclipse CDT4 - Unix Makefiles" -D_ECLIPSE_VERSION=4.5 -D CMAKE_BUILD_TYPE=Release ..
#cmake --debug-output .. 

mv .project ..
mv .cproject ..
make -j 4 
ctest --output-on-failure .
