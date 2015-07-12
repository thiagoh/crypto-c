cmake_minimum_required(VERSION 2.8)

file(GLOB SOURCES impl/*.c include/*.h)
include_directories(include)

add_library(crypto_c ${SOURCES})

# add the install targets
install (TARGETS crypto_c DESTINATION bin)
install (DIRECTORY "include" DESTINATION include
		FILES_MATCHING PATTERN "*.h")

find_package(OpenSSL)
include_directories(${OpenSSL_INCLUDE_DIRS})