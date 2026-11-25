cmake_minimum_required(VERSION 3.16)
project(modgrep VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(modgrep src/main.c)
target_include_directories(modgrep PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(modgrep PRIVATE ${PCAP_LIBRARIES})
target_compile_options(modgrep PRIVATE -Wall -Wextra -Wpedantic)

install(TARGETS modgrep RUNTIME DESTINATION bin)
