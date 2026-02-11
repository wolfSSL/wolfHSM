cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0-a4)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico2 CACHE STRING "Board type")

# Handle platform configuration before SDK import
if(BUILD_PICO2_DEMOS)
    if(NOT DEFINED PICO_PLATFORM)
        set(PICO_PLATFORM "rp2350" CACHE STRING "Pico Platform" FORCE)
    elseif(PICO_PLATFORM STREQUAL "RP2350")
        set(PICO_PLATFORM "rp2350" CACHE STRING "Pico Platform" FORCE)
    endif()
endif()

# Include Pico SDK import if PICO_SDK_PATH is defined
if(BUILD_PICO2_DEMOS OR DEFINED PICO_SDK_PATH OR DEFINED ENV{PICO_SDK_PATH})
    include(${CMAKE_CURRENT_SOURCE_DIR}/pico_sdk_import.cmake)
    
    # Force usage of Pico toolchain if we found the SDK and no toolchain was specified
    if(DEFINED PICO_SDK_PATH AND NOT CMAKE_TOOLCHAIN_FILE)
        set(CMAKE_TOOLCHAIN_FILE ${PICO_SDK_PATH}/cmake/preload/toolchains/pico_arm_gcc.cmake)
    endif()
endif()

project(wolfHSM C CXX ASM)

# Initialize Pico SDK immediately after project definition
if(DEFINED PICO_SDK_PATH)
    pico_sdk_init()
endif()

# Configure wolfSSL to use user_settings.h
set(WOLFSSL_USER_SETTINGS ON CACHE BOOL "Use user settings" FORCE)
set(WOLFSSL_INSTALL OFF CACHE BOOL "Disable wolfSSL install" FORCE)

# Disable wolfSSL tests and examples when building for Pico
if(BUILD_PICO2_DEMOS)
    set(WOLFSSL_EXAMPLES OFF CACHE BOOL "Disable wolfSSL examples" FORCE)
    set(WOLFSSL_CRYPT_TESTS OFF CACHE BOOL "Disable wolfSSL crypt tests" FORCE)
    set(WOLFSSL_TEST OFF CACHE BOOL "Disable wolfSSL tests" FORCE)
endif()

# Add wolfSSL subdirectory
add_subdirectory(wolfssl)

# If building for Pico demo, point wolfSSL to the example's user_settings.h
if(BUILD_PICO2_DEMOS)
    target_include_directories(wolfssl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/examples/pico)
    target_compile_definitions(wolfssl PUBLIC WOLFSSL_USER_SETTINGS)
    target_link_libraries(wolfssl PUBLIC pico_stdlib)
endif()

# Create wolfHSM library
file(GLOB WOLFHSM_SOURCES "src/*.c")
add_library(wolfhsm STATIC ${WOLFHSM_SOURCES})

# Include directories for wolfHSM
target_include_directories(wolfhsm PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/wolfhsm
    ${CMAKE_CURRENT_SOURCE_DIR}/wolfssl
)

# Link wolfHSM against wolfSSL
target_link_libraries(wolfhsm PUBLIC wolfssl)

if(BUILD_PICO2_DEMOS)
    target_link_libraries(wolfhsm PUBLIC pico_stdlib)
endif()

# Add examples subdirectory if building for Pico
if(BUILD_PICO2_DEMOS)
    add_subdirectory(examples/pico)
endif()
