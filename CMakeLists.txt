cmake_minimum_required(VERSION 2.7)

enable_testing()
set(CMAKE_BUILD_TYPE Debug)

project(fit_aligner)

set(SRC fit_aligner.c)

add_executable(fit_aligner ${SRC})

target_link_libraries(fit_aligner fdt)
