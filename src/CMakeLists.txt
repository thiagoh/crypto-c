cmake_minimum_required(VERSION 2.8)

include(GenerateExportHeader)

file(GLOB SOURCES *.c *.h)
include_directories(include)

#add_library(cryptoc SHARED ${SOURCES})
add_library(cryptoc STATIC ${SOURCES})
generate_export_header(cryptoc)

# add the install targets
install (TARGETS cryptoc 
		EXPORT CryptoCTargets 
		LIBRARY DESTINATION lib
		ARCHIVE DESTINATION lib
		RUNTIME DESTINATION bin
		INCLUDES DESTINATION include)
		
install (DIRECTORY "${PROJECT_SOURCE_DIR}/src/" DESTINATION include COMPONENT Devel
		FILES_MATCHING PATTERN "*.h")

find_package(OpenSSL)
include_directories(${OpenSSL_INCLUDE_DIRS})






include(CMakePackageConfigHelpers)


# ... for the build tree
set(CONF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}" "${PROJECT_BINARY_DIR}")
configure_file(CryptoCConfig.cmake.in
  "${PROJECT_BINARY_DIR}/CryptoCConfig.cmake" @ONLY)
# ... for the install tree
set(CONF_INCLUDE_DIRS "\${CRYPTOC_CMAKE_DIR}/${REL_INCLUDE_DIR}")
configure_file(CryptoCConfig.cmake.in
  "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CryptoCConfig.cmake" @ONLY)

configure_package_config_file(CryptoCConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/CryptoCConfig.cmake" 
    INSTALL_DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/CryptoCConfigVersion.cmake"
  VERSION ${APPLICATION_VERSION}
  COMPATIBILITY AnyNewerVersion)

set(ConfigPackageLocation lib/cmake/CryptoC)
install(EXPORT CryptoCTargets
  FILE
    CryptoCTargets.cmake
  DESTINATION
    ${ConfigPackageLocation})
    
install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/CryptoCConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/CryptoCConfigVersion.cmake"
  DESTINATION
    ${ConfigPackageLocation}
  COMPONENT
    Devel
)
