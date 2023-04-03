

include_directories(${CMAKE_SOURCE_DIR})

list(APPEND _sources main.cpp util.cpp)

add_executable(frontend_libOTe  ${_sources})

target_link_libraries(frontend_libOTe libOTe_Tests tests_cryptoTools libsodium relic_s bitpolymul cryptoTools libOTe)

add_executable(test_s send.cpp)
target_link_libraries(test_s relic_s bitpolymul cryptoTools libOTe)
add_executable(test_r receiver.cpp)
target_link_libraries(test_r relic_s bitpolymul cryptoTools libOTe)