cmake_minimum_required(VERSION 4.1)
project(WhipPipe C)

set(CMAKE_C_STANDARD 11)

add_library(whippipe STATIC
    src/loader.c
    src/client.c
    src/util.c
    src/crypto.c
)

target_include_directories(whippipe PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(whippipe PUBLIC ws2_32 bcrypt)
endif()

add_executable(loader_basic              examples/loader_basic.c)
add_executable(client_basic              examples/client_basic.c)
add_executable(loader_async_heartbeat    examples/loader_async_heartbeat.c)
add_executable(client_async_heartbeat    examples/client_async_heartbeat.c)

target_link_libraries(loader_basic             whippipe)
target_link_libraries(client_basic             whippipe)
target_link_libraries(loader_async_heartbeat   whippipe)
target_link_libraries(client_async_heartbeat   whippipe)