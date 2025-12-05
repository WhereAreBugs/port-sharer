cmake_minimum_required(VERSION 3.10)

project(port-sharer VERSION 1.0.0 LANGUAGES CXX)

if (POLICY CMP0167)
    # Silence Boost find module removal warning on newer CMake versions.
    cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(TEST_SANITIZER_SUPPORTED OFF)
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    set(TEST_SANITIZER_SUPPORTED ON)
    set(TEST_SANITIZER_FLAGS "-fsanitize=address,undefined" "-fno-omit-frame-pointer")
endif()

find_package(Boost REQUIRED COMPONENTS system thread)

if (FLAG_OPENWRT)
    find_package(uci REQUIRED)
endif ()

set(PORT_SHARER_USE_IO_URING OFF)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_path(LIBURING_INCLUDE_DIR liburing.h)
    find_library(LIBURING_LIBRARY uring)
    if (LIBURING_INCLUDE_DIR AND LIBURING_LIBRARY)
        set(PORT_SHARER_USE_IO_URING ON)
        message(STATUS "liburing found: ${LIBURING_LIBRARY}")
    else ()
        message(STATUS "liburing not found, io_uring path disabled")
    endif ()
endif ()

file(GLOB_RECURSE APP_SOURCES "src/*.cpp")
set(LIB_SOURCES ${APP_SOURCES})
list(REMOVE_ITEM LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")

include_directories(src)

add_library(port-sharer-lib ${LIB_SOURCES})

target_include_directories(port-sharer-lib
        PUBLIC
        ${Boost_INCLUDE_DIRS}
        ${UCI_INCLUDE_DIR}
)

target_link_libraries(port-sharer-lib
        PUBLIC
        Boost::system
        Boost::thread
        ${UCI_LIBRARIES}
)

if (PORT_SHARER_USE_IO_URING)
    target_compile_definitions(port-sharer-lib PUBLIC PORT_SHARER_HAS_IO_URING=1)
    target_include_directories(port-sharer-lib PUBLIC ${LIBURING_INCLUDE_DIR})
    target_link_libraries(port-sharer-lib PUBLIC ${LIBURING_LIBRARY})
endif ()

# Sanitized test-only library to avoid instrumenting production binary.
add_library(port-sharer-test-lib ${LIB_SOURCES})
target_include_directories(port-sharer-test-lib
        PUBLIC
        ${Boost_INCLUDE_DIRS}
        ${UCI_INCLUDE_DIR}
)
target_link_libraries(port-sharer-test-lib
        PUBLIC
        Boost::system
        Boost::thread
        ${UCI_LIBRARIES}
)
if (PORT_SHARER_USE_IO_URING)
    target_compile_definitions(port-sharer-test-lib PUBLIC PORT_SHARER_HAS_IO_URING=1)
    target_include_directories(port-sharer-test-lib PUBLIC ${LIBURING_INCLUDE_DIR})
    target_link_libraries(port-sharer-test-lib PUBLIC ${LIBURING_LIBRARY})
endif ()
if (TEST_SANITIZER_SUPPORTED)
    target_compile_options(port-sharer-test-lib PRIVATE ${TEST_SANITIZER_FLAGS})
    target_link_options(port-sharer-test-lib PRIVATE ${TEST_SANITIZER_FLAGS})
endif()

add_executable(port-sharer src/main.cpp)

target_link_libraries(port-sharer
        PRIVATE
        port-sharer-lib
)


install(TARGETS port-sharer DESTINATION bin)

message(STATUS "Project name: ${PROJECT_NAME}")
message(STATUS "Boost libraries found: ${Boost_LIBRARIES}")
if (FLAG_OPENWRT)
    message(STATUS "UCI library found: ${UCI_LIBRARIES}")
    target_compile_definitions(port-sharer OPENWRT=1)
endif ()

enable_testing()

file(GLOB TEST_SOURCES "tests/test_*.cpp")
foreach(test_src IN LISTS TEST_SOURCES)
    get_filename_component(test_name ${test_src} NAME_WE)
    add_executable(${test_name} ${test_src})
    target_link_libraries(${test_name}
            PRIVATE
            port-sharer-test-lib
    )
    if (TEST_SANITIZER_SUPPORTED)
        target_compile_options(${test_name} PRIVATE ${TEST_SANITIZER_FLAGS})
        target_link_options(${test_name} PRIVATE ${TEST_SANITIZER_FLAGS})
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
