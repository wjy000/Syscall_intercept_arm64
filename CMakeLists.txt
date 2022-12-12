cmake_minimum_required(VERSION 3.18.1)
project(Syscall_intercept_arm64)

set(CMAKE_CXX_STANDARD 17)

add_executable(Syscall_intercept_arm64 Syscall_intercept_arm64.cpp Syscall_item_enter_arm64.cpp)
