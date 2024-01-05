cmake_minimum_required(VERSION 3.27.5)

project("pcap-file-reader-lib")

set(CMAKE_CXX_STANDARD 23)

# download byte buffer lib dependency
include(FetchContent)
FetchContent_Declare(
  byte_buffer
  GIT_REPOSITORY https://github.com/esirazeev/byte_buffer.git
  GIT_TAG master
)
FetchContent_MakeAvailable(byte_buffer)

file(GLOB_RECURSE LIB_SOURCES "pcap/*.cpp")
add_library(pcap_file_reader SHARED ${LIB_SOURCES})
target_link_libraries(pcap_file_reader byte_buffer)
target_include_directories(pcap_file_reader PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
