#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "log4cplus::log4cplus" for configuration "Release"
set_property(TARGET log4cplus::log4cplus APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(log4cplus::log4cplus PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE "/usr/lib/x86_64-linux-gnu/librt.a;/usr/lib/x86_64-linux-gnu/libnsl.so"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/liblog4cplus.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS log4cplus::log4cplus )
list(APPEND _IMPORT_CHECK_FILES_FOR_log4cplus::log4cplus "${_IMPORT_PREFIX}/lib/liblog4cplus.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
