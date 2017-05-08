cmake_minimum_required(VERSION 3.5)
project(sik)

#set(CMAKE_CXX_COMPILER      "/usr/bin/clang++")
set(CMAKE_CXX_FLAGS         "-Werror -Wall -std=c++14")
set(CMAKE_CXX_STANDARD      14)
set(SOURCE_FILES)

add_executable(client ${SOURCE_FILES} client.cc)
add_executable(server ${SOURCE_FILES} server.cc)