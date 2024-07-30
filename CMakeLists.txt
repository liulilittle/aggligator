CMAKE_MINIMUM_REQUIRED(VERSION 3.0.0) 

# Define the solutions name.
SET(NAME aggligator)
PROJECT(${NAME} C CXX) # CMAKE_CURRENT_SOURCE_DIR

# C/CXX compiler configurations.
SET(CMAKE_C_FLAGS "-fPIC -fvisibility=hidden -Wno-format -Wno-implicit-function-declaration")
SET(CMAKE_CXX_FLAGS "-fPIC -fvisibility=hidden -Wno-format -Wno-inconsistent-missing-override -Wno-pointer-bool-conversion -Wno-unsequenced -Wno-null-dereference -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-undefined-compare -Wno-deprecated-declarations")

# Configure predefined compilation macros.
ADD_DEFINITIONS(-DJEMALLOC)

# ENV.
SET(PLATFORM_DEBUG FALSE)
IF(CMAKE_BUILD_TYPE STREQUAL "Debug" OR BT MATCHES "Debug")
    SET(PLATFORM_DEBUG TRUE)
ENDIF()

SET(PLATFORM_COMPILER_CLANG FALSE)
SET(PLATFORM_SYSTEM_LINUX FALSE)
SET(PLATFORM_SYSTEM_DARWIN FALSE)

IF(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    SET(PLATFORM_COMPILER_CLANG TRUE)
ENDIF()

IF(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME MATCHES "Darwin")
    SET(PLATFORM_SYSTEM_DARWIN TRUE)
ELSE()
    SET(PLATFORM_SYSTEM_LINUX TRUE)
ENDIF()

# C
IF(PLATFORM_DEBUG)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DEBUG -g3")
ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
ENDIF()

# C/CXX
IF(PLATFORM_DEBUG)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_DEBUG -g3")
ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
ENDIF()

# When compiling only linux kernel distributions >= 5.10 and later, 
# You can enable this macro to get the new io_uring asynchronous event driver model support.
# IF(PLATFORM_SYSTEM_LINUX) 
#     ADD_DEFINITIONS(-DBOOST_ASIO_HAS_IO_URING=1)
#     ADD_DEFINITIONS(-DBOOST_ASIO_DISABLE_EPOLL=1)
# ENDIF()

# Check C/CXX compiler supports.
INCLUDE(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++17" COMPILER_SUPPORTS_CXX17)
CHECK_CXX_COMPILER_FLAG("-std=c++1z" COMPILER_SUPPORTS_CXX1Z)

# According to the type of operating system to determine whether you need to check whether the compiler supports C/C++17, 
# On the MACOS system, the following check code is invalid, so directly specify the standard version of C/C++, 
# If an error or compilation does not pass, it means that you need to upgrade the LLVM GCC/CLANG compiler installed on MACOS.
IF(PLATFORM_SYSTEM_DARWIN)
    # The mandatory version is C++17.
    SET(CMAKE_CXX_STANDARD 17)

    ADD_DEFINITIONS(-D_GNU_SOURCE)
    ADD_DEFINITIONS(-DBOOST_STACKTRACE_GNU_SOURCE_NOT_REQUIRED)
ELSE()
    # CXX17
    IF(COMPILER_SUPPORTS_CXX17)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
    ELSEIF(COMPILER_SUPPORTS_CXX1Z)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z")
    ELSE()
        MESSAGE(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++ 17 support. Please use a different C++ compiler.")
    ENDIF()

    # -rdynamic -Wl,-Bstatic -Wl,-Bdynamic -lstdc++ -lpthread -ldl -lz -lrt
    SET(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++ -rdynamic -Wl,-Bstatic") 
ENDIF()

# Set the tripartite library directorys.
SET(THIRD_PARTY_LIBRARY_DIR /root/dev)

# Set the compiled header file search directorys.
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/

    ${THIRD_PARTY_LIBRARY_DIR}/boost
    ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/include
    ${THIRD_PARTY_LIBRARY_DIR}/openssl/include
)

# Set the third library connection directory to searchs.
LINK_DIRECTORIES(
    ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib
    ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/lib
    ${THIRD_PARTY_LIBRARY_DIR}/openssl
)

# List of common cpp source files compilations for aggligator/unix cmake solution projects.
FILE(GLOB_RECURSE SOURCE_FILES 
    ${PROJECT_SOURCE_DIR}/main.cpp 
    ${PROJECT_SOURCE_DIR}/DateTime.cpp 
    ${PROJECT_SOURCE_DIR}/aggligator.cpp 
)

# Add the compiled output binary files.
ADD_EXECUTABLE(${NAME} ${SOURCE_FILES} ${PLATFORM_SOURCE_FILES})

# Set the compilation output files path.
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# Set up library connections to dependent libraries.
IF(PLATFORM_SYSTEM_DARWIN)
    SET(BUILD_SHARED_LIBS ON) # System

    TARGET_LINK_LIBRARIES(${NAME} 
        ${THIRD_PARTY_LIBRARY_DIR}/openssl/libssl.a 
        ${THIRD_PARTY_LIBRARY_DIR}/openssl/libcrypto.a 
        ${THIRD_PARTY_LIBRARY_DIR}/jemalloc/lib/libjemalloc.a

        dl
        pthread

        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_system.a
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_coroutine.a 
        ${THIRD_PARTY_LIBRARY_DIR}/boost/stage/lib/libboost_context.a) 
ELSEIF(PLATFORM_COMPILER_CLANG)
    SET(BUILD_SHARED_LIBS ON)

    TARGET_LINK_LIBRARIES(${NAME}
        libssl.a 
        libcrypto.a 
        libjemalloc.a
        # liburing.a

        atomic
        dl
        pthread

        libboost_system.a
        libboost_coroutine.a 
        libboost_context.a) 
ELSE()
    TARGET_LINK_LIBRARIES(${NAME} 
        libc.a
        libssl.a 
        libcrypto.a 
        libjemalloc.a
        # liburing.a

        atomic
        dl
        pthread

        libboost_system.a
        libboost_coroutine.a 
        libboost_context.a) 
ENDIF()