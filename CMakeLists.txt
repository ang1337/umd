cmake_minimum_required(VERSION 3.5)
project(umd VERSION 1.1)

set (THREADLIB "-lpthread")
set (CXX_17 "-std=c++17")
set (COMP_OPT "-O3")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${THREADLIB} ${CXX_17} ${COMP_OPT}")

add_executable( umd
    ./src/dumper.cpp
    ./src/dumper_main.cpp
)
