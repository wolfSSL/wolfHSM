if (WOLFHSM_DEMO_DUAL)
add_executable(pico2_demo_dual
    pico2_demo_dual.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../port/pico/pico2_transport_shm.c
)

target_link_libraries(pico2_demo_dual
    pico_stdlib
    pico_multicore
    wolfhsm
)

target_compile_definitions(pico2_demo_dual PRIVATE
    WOLFSSL_USER_SETTINGS
    WOLFHSM_CFG_ENABLE_CLIENT
    WOLFHSM_CFG_ENABLE_SERVER
)

target_include_directories(pico2_demo_dual PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wolfhsm
    ${CMAKE_CURRENT_SOURCE_DIR}/../../port/pico
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wolfssl
)

# Enable stdio over USB only
pico_enable_stdio_usb(pico2_demo_dual 1)
pico_enable_stdio_uart(pico2_demo_dual 0)

# Generate UF2 file for Pico
pico_add_extra_outputs(pico2_demo_dual)
endif()

if (WOLFHSM_DEMO_SHA256)
# SHA256 Demo
add_executable(pico2_demo_sha256
    pico2_demo_sha256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../port/pico/pico2_transport_shm.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wolfssl/wolfcrypt/src/port/rpi_pico/pico.c
)

target_link_libraries(pico2_demo_sha256
    pico_stdlib
    pico_multicore
    pico_rand
    wolfhsm
    wolfssl
)

target_compile_definitions(pico2_demo_sha256 PRIVATE
    WOLFSSL_USER_SETTINGS
    WOLFHSM_CFG_ENABLE_CLIENT
    WOLFHSM_CFG_ENABLE_SERVER
)

target_include_directories(pico2_demo_sha256 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wolfhsm
    ${CMAKE_CURRENT_SOURCE_DIR}/../../port/pico
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wolfssl
    ${CMAKE_CURRENT_SOURCE_DIR}/../../wolfssl/wolfssl    
)

# Enable stdio over USB only
pico_enable_stdio_usb(pico2_demo_sha256 1)
pico_enable_stdio_uart(pico2_demo_sha256 0)

# Generate UF2 file for Pico
pico_add_extra_outputs(pico2_demo_sha256)
endif()
