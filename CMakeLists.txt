cmake_minimum_required (VERSION 3.0)
project (MiniDbg)

add_compile_options(-std=c++17)

include_directories(ext/libelfin ext/linenoise include)
add_executable(minidbg src/debugger.cpp src/breakpoint.cpp ext/linenoise/linenoise.c)

add_executable(hello examples/hello.cpp)
set_target_properties(hello
                      PROPERTIES COMPILE_FLAGS "-g -O0")

#add_executable(variable examples/variable.cpp)
#set_target_properties(variable
                      #PROPERTIES COMPILE_FLAGS "-gdwarf-2 -O0")

add_executable(more_code examples/more_code.cpp)
set_target_properties(more_code
                      PROPERTIES COMPILE_FLAGS "-gdwarf-2 -O0")


add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
)
target_link_libraries(minidbg
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so)
add_dependencies(minidbg libelfin)
