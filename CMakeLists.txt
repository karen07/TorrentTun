cmake_minimum_required(VERSION 3.13)

project(TorrentTun)

if(CMAKE_BUILD_TYPE MATCHES "Debug_ASan")
    add_compile_options(-Og -g -fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-g -fsanitize=address)
endif()

if(CMAKE_BUILD_TYPE MATCHES "Debug_MSan")
    add_compile_options(-Og -g -fsanitize=memory -fno-omit-frame-pointer)
    add_link_options(-g -fsanitize=memory)
endif()

find_package(OpenSSL REQUIRED)

file(GLOB SRC "src/*.c")
add_executable(${PROJECT_NAME} ${SRC})
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Werror -Wpedantic -std=gnu11)
target_include_directories(${PROJECT_NAME} PRIVATE include)
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)

install(TARGETS ${PROJECT_NAME} DESTINATION /usr/bin)

find_program(CLANGFORMAT clang-format)
if(CLANGFORMAT)
    add_custom_command(TARGET ${PROJECT_NAME} PRE_BUILD
        COMMAND clang-format -i ${CMAKE_CURRENT_SOURCE_DIR}/src/*
    )
endif()

find_package(Git QUIET)
execute_process(
    COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE GIT_RC
)
target_compile_definitions(${PROJECT_NAME} PRIVATE
    GIT_COMMIT_STR="${GIT_COMMIT}"
)
