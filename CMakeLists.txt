cmake_minimum_required(VERSION 3.10)

set(HADES_VERSION "0.0.1")
project(Hades, C)

add_subdirectory(source/common)
add_subdirectory(source/gba)
add_subdirectory(source/platform/gui)