cmake_minimum_required(VERSION 2.8)

project(crypto_c)

# Offer the user the choice of overriding the installation directories
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for executables")
set(INSTALL_INCLUDE_DIR include CACHE PATH
  "Installation directory for header files")
if(WIN32 AND NOT CYGWIN)
  set(DEF_INSTALL_CMAKE_DIR CMake)
else()
  set(DEF_INSTALL_CMAKE_DIR lib/CMake/CryptoC)
endif()
set(INSTALL_CMAKE_DIR ${DEF_INSTALL_CMAKE_DIR} CACHE PATH
  "Installation directory for CMake files")
  
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_INCLUDE_CURRENT_DIR_IN_INTERFACE ON)
set(APPLICATION_NAME ${PROJECT_NAME})
set(APPLICATION_VERSION_MAJOR "1")
set(APPLICATION_VERSION_MINOR "0")
set(APPLICATION_VERSION_PATCH "0")
set(APPLICATION_VERSION "${APPLICATION_VERSION_MAJOR}.${APPLICATION_VERSION_MINOR}.${APPLICATION_VERSION_PATCH}")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Wall")

# Make relative paths absolute (needed later on)
foreach(p LIB BIN INCLUDE CMAKE)
  set(var INSTALL_${p}_DIR)
  if(NOT IS_ABSOLUTE "${${var}}")
    set(${var} "${CMAKE_INSTALL_PREFIX}/${${var}}")
  endif()
endforeach()

include(GenerateExportHeader)

add_subdirectory(src)
add_subdirectory(test)

include(CMakePackageConfigHelpers)

# Add all targets to the build-tree export set
export(TARGETS cryptoc FILE "${PROJECT_BINARY_DIR}/CryptoCTargets.cmake")
message("CMake exported to ${PROJECT_BINARY_DIR}/CryptoCTargets.cmake")
 
# Export the package for use from the build-tree
# (this registers the build-tree with a global CMake-registry)
export(PACKAGE cryptoc)

# Create the CryptoCConfig.cmake and CryptoCConfigVersion files
file(RELATIVE_PATH REL_INCLUDE_DIR "${INSTALL_CMAKE_DIR}"
   "${INSTALL_INCLUDE_DIR}")

# ... for the build tree
set(CONF_INCLUDE_DIRS "${PROJECT_SOURCE_DIR}" "${PROJECT_BINARY_DIR}")
configure_file(CryptoCConfig.cmake.in "${PROJECT_BINARY_DIR}/CryptoCConfig.cmake" @ONLY)

# ... for the install tree
set(CONF_INCLUDE_DIRS "\${CRYPTOC_CMAKE_DIR}/${REL_INCLUDE_DIR}")
configure_file(CryptoCConfig.cmake.in "${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CryptoCConfig.cmake" @ONLY)
message("CMake Config exported to ${PROJECT_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CryptoCConfig.cmake")
  
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/cryptoc/CryptoCConfigVersion.cmake"
  VERSION ${APPLICATION_VERSION}
  COMPATIBILITY AnyNewerVersion)
  
message("CMake ConfigVersion exported to ${CMAKE_CURRENT_BINARY_DIR}/cryptoc/CryptoCConfigVersion.cmake")

enable_testing()