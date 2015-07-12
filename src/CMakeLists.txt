cmake_minimum_required(VERSION 2.8)

file(GLOB SOURCES impl/*.c include/*.h)
include_directories(include)

add_library(crypto_c ${SOURCES})

find_package(OpenSSL)
include_directories(${OpenSSL_INCLUDE_DIRS})