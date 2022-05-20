cmake_minimum_required(VERSION 3.8.1)
project(memcache_sniffer)

set(CMAKE_CXX_STANDARD 17)

if(BUILD_STATIC_BINARY)
    message("Building static binary")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    set(BUILD_SHARED_LIBRARIES OFF)
    set(CMAKE_EXE_LINKER_FLAGS "-static -Wl,-gc-sections")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -ffunction-sections -fdata-sections")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -ffunction-sections -fdata-sections")
endif(BUILD_STATIC_BINARY)


add_subdirectory(deps/fmt EXCLUDE_FROM_ALL)

add_executable(memcache_sniffer src/main.cpp
        src/protocols/headers.h
        src/protocols/memcachedl.h
        src/utils/socket.h
        src/utils/pcap.h
        src/exporter.h
        src/forwarder.h
        src/sniffer.h)

target_include_directories(memcache_sniffer PUBLIC
        deps/better-enums/
        deps/clipp/include
        deps/spdlog/include/
        deps/prometheus-cpp/_build/deploy/usr/local/include/
        )

target_link_directories(memcache_sniffer PUBLIC
        deps/prometheus-cpp/_build/deploy/usr/local/lib/
        deps/prometheus-cpp/_build/deploy/usr/local/lib64/
        )

target_link_libraries(memcache_sniffer pthread)
target_link_libraries(memcache_sniffer fmt::fmt-header-only)
target_link_libraries(memcache_sniffer pcap)
target_link_libraries(memcache_sniffer prometheus-cpp-core)
target_link_libraries(memcache_sniffer prometheus-cpp-pull)
target_link_libraries(memcache_sniffer prometheus-cpp-core)
target_link_libraries(memcache_sniffer z)
