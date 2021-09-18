cmake_minimum_required(VERSION 3.2)

project(common, C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include_directories("${CMAKE_SOURCE_DIR}/include/")

add_library(common STATIC
    utils.c
)