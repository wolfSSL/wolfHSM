# Build script for the wolfHSM AUTOSAR Adaptive CryptoProvider library.
# Produces libwolfhsm_ara_crypto.{a,so} that an Adaptive integrator links
# into their CryptoProvider adapter.

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
# Resolve to absolute paths so they don't get reinterpreted against this
# target's source dir. This matters when a relative -DWOLFHSM_DIR is
# passed for a standalone build; when inherited from a parent project the
# values are already absolute and this is a no-op.
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
# Integrators override WOLFHSM_CONFIG_DIR to point at their own
# wolfhsm_cfg.h / user_settings.h. The default points at the shared
# port/autosar config so the library builds out of the box for
# verification.
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

# Integrators link this library into their ara::crypto::cryp::CryptoProvider
# adapter. See docs/integration_adaptive.md for the bridging pattern.
