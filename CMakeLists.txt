cmake_minimum_required(VERSION 3.0.0)
project(asio_demo VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-std=c++17 ${CMAKE_CXX_FLAGS}")

include(CTest)
enable_testing()

include_directories(/home/fhl/Desktop/boost_1_73_0)
FIND_LIBRARY(BOOST_LIB boost_coroutine boost_context boost_system /home/fhl/Desktop/boost_1_73_0/stage/lib)
FIND_LIBRARY(AIO_LIB rt /usr/lib/x86_64-linux-gnu/)
FIND_LIBRARY(SSL_LIB ssl /usr/lib/x86_64-linux-gnu/)
FIND_LIBRARY(CRYPTO_LIB crypto /usr/lib/x86_64-linux-gnu/)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
link_libraries(${BOOST_LIB} ${AIO_LIB} ${SSL_LIB} ${CRYPTO_LIB})

add_executable(asio_demo main.cpp crypto.cc)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
