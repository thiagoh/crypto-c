cmake_minimum_required(VERSION 2.8)

file(GLOB SOURCES impl/*.c include/*.h)
include_directories(include)

add_library(cryptoc ${SOURCES})
generate_export_header(cryptoc)

# add the install targets
install (TARGETS cryptoc EXPORT CryptoCTargets 
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
		RUNTIME DESTINATION bin
		INCLUDES DESTINATION include)
install (DIRECTORY "include" DESTINATION include
		FILES_MATCHING PATTERN "*.h")

find_package(OpenSSL)
include_directories(${OpenSSL_INCLUDE_DIRS})