# wolfHSM AUTOSAR Adaptive CryptoProvider library

cmake_minimum_required(VERSION 3.13)
project(wolfhsm_ara_crypto CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED WOLFHSM_DIR)
    set(WOLFHSM_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)
endif()
if(NOT DEFINED WOLFSSL_DIR)
    set(WOLFSSL_DIR ${WOLFHSM_DIR}/../wolfssl)
endif()
get_filename_component(WOLFHSM_DIR "${WOLFHSM_DIR}" ABSOLUTE
                       BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
get_filename_component(WOLFSSL_DIR "${WOLFSSL_DIR}" ABSOLUTE
                       BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

set(SRC src/crypto_provider.cpp)

add_library(wolfhsm_ara_crypto ${SRC})

target_include_directories(wolfhsm_ara_crypto PUBLIC
    include
    ${WOLFHSM_DIR}
    ${WOLFSSL_DIR}
)
# Integrators set WOLFHSM_CONFIG_DIR to their own config headers.
if(NOT DEFINED WOLFHSM_CONFIG_DIR)
    set(WOLFHSM_CONFIG_DIR ${CMAKE_CURRENT_LIST_DIR}/../common/config)
endif()
target_include_directories(wolfhsm_ara_crypto PRIVATE
    ${WOLFHSM_CONFIG_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/../common/include
)

target_compile_definitions(wolfhsm_ara_crypto PRIVATE
    WOLFHSM_CFG
    WOLFSSL_USER_SETTINGS
)
target_compile_options(wolfhsm_ara_crypto PRIVATE -Wall -Wextra -Werror)
