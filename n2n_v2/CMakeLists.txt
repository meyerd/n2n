project(n2n)
cmake_minimum_required(VERSION 2.6)

# N2n information
set(N2N_VERSION 2.1.0)
set(N2N_OSNAME ${CMAKE_SYSTEM})

# N2n specific params
if(NOT DEFINED N2N_OPTION_AES)
if(NOT WIN32)
set(N2N_OPTION_AES ON)
else(NOT WIN32)
set(N2N_OPTIONS_AES OFF)
endif(NOT WIN32)
endif(NOT DEFINED N2N_OPTION_AES)

add_definitions(-DN2N_VERSION=\"${N2N_VERSION}\" -DN2N_OSNAME=\"${N2N_OSNAME}\")

if(N2N_OPTION_AES)
add_definitions(-DN2N_HAVE_AES)
endif(N2N_OPTION_AES)

# Build information
if(NOT DEFINED BUILD_SHARED_LIBS)
set(BUILD_SHARED_LIBS OFF)
endif(NOT DEFINED BUILD_SHARED_LIBS)

if(NOT DEFINED CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE None)
endif(NOT DEFINED CMAKE_BUILD_TYPE)
#set(CMAKE_BUILD_TYPE Debug)
#set(CMAKE_BUILD_TYPE Release)

#Ultrasparc64 users experiencing SIGBUS should try the following gcc options
#(thanks to Robert Gibbon)
#PLATOPTS_SPARC64=-mcpu=ultrasparc -pipe -fomit-frame-pointer -ffast-math -finline-functions -fweb -frename-registers -mapp-regs

#for macOS, find openssl installed by Homebrew
# cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl ..
if(APPLE)
find_package(openssl REQUIRED)
endif(APPLE)

# None
if(NOT WIN32)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wshadow -Wpointer-arith -Wmissing-declarations -Wnested-externs -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wshadow -Wpointer-arith -Wmissing-declarations -Wnested-externs")
# Debug 
set(CMAKE_C_FLAGS_DEBUG "-g -fsanitize=address")
set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address")
# Release
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
endif(NOT WIN32)

#for macOS, add openssl include dir
if(APPLE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${OPENSSL_INCLUDE_DIR}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${OPENSSL_INCLUDE_DIR}")
endif(APPLE)

## DEBUG FOR CMAKE
#message(${N2N_VERSION})
#message(${N2N_OSNAME})
##message(${CMAKE_BUILD_TYPE})
#message(${N2N_OPTION_AES})
## DEBUG FOR CMAKE

add_library(n2n n2n.c
                n2n_keyfile.c
                wire.c
                minilzo.c
                twofish.c
                transform_null.c
                transform_tf.c
                transform_aes.c
                tuntap_freebsd.c
                tuntap_netbsd.c
                tuntap_linux.c
                tuntap_osx.c
                version.c
            )

if(NOT WIN32)
add_library(scm unix-scm.c)
target_link_libraries(n2n scm)
endif(NOT WIN32)

if(WIN32)
add_subdirectory(win32)
add_library(scm win32/win-scm.c)
target_link_libraries(n2n n2n_win32)
endif(WIN32)

if(N2N_OPTION_AES)
target_link_libraries(n2n crypto)
endif(N2N_OPTION_AES)

# For Solaris (or OpenSolaris?)
#target_link_libraries(n2n socket nsl)

add_executable(edge edge.c)
target_link_libraries(edge n2n)

add_executable(supernode sn.c)
target_link_libraries(supernode n2n)

add_executable(n2n_test n2n_test.c)
target_link_libraries(n2n_test n2n)

add_executable(benchmark benchmark.c)
target_link_libraries(benchmark n2n)

add_executable(benchmark_hashtable benchmark_hashtable.c)
target_link_libraries(benchmark_hashtable n2n)

install(TARGETS edge supernode
        RUNTIME DESTINATION sbin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
       )

# Documentation
if(DEFINED UNIX)
add_dependencies(n2n doc)
file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/doc)
add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/edge.8 > ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/edge.8
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/supernode.1 > ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/supernode.1
                  )

add_custom_command(OUTPUT ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                   COMMAND gzip -c ${PROJECT_SOURCE_DIR}/n2n_v2.7 > ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                   DEPENDS ${PROJECT_SOURCE_DIR}/n2n_v2.7
                  )

add_custom_target(doc DEPENDS ${PROJECT_BINARY_DIR}/doc/edge.8.gz
                              ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                              ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                 )

set_source_files_properties(${PROJECT_BINARY_DIR}/doc/edge.8.gz
                            ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
                            ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
                            PROPERTIES GENERATED 1)

install(FILES ${PROJECT_BINARY_DIR}/doc/edge.8.gz
        DESTINATION /usr/share/man8)
install(FILES ${PROJECT_BINARY_DIR}/doc/supernode.1.gz
        DESTINATION /usr/share/man1)
install(FILES ${PROJECT_BINARY_DIR}/doc/n2n_v2.7.gz
        DESTINATION /usr/share/man7)

install(PROGRAMS ${PROJECT_SOURCE_DIR}/munin/n2n-supernode
        DESTINATION /usr/share/munin/plugins)

endif(DEFINED UNIX)
