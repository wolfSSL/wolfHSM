add_executable(pico2_demo_dual
    pico2_demo_dual.c
    ../../port/pico/pico2_transport_shm.c
)

target_link_libraries(pico2_demo_dual
    wolfssl
    wolfhsm
    pico_stdlib
    pico_multicore
)

target_compile_definitions(pico2_demo_dual PRIVATE
    WOLFSSL_USER_SETTINGS
    WOLFHSM_CFG_ENABLE_CLIENT
    WOLFHSM_CFG_ENABLE_SERVER
)

target_include_directories(pico2_demo_dual PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/config
    ${CMAKE_SOURCE_DIR}/wolfHSM
    ${CMAKE_SOURCE_DIR}/wolfHSM/wolfhsm
    ${CMAKE_SOURCE_DIR}/wolfHSM/port/pico
)

if (USE_UART)
pico_enable_stdio_usb(pico2_demo_dual 0)
pico_enable_stdio_uart(pico2_demo_dual 1)
else()
pico_enable_stdio_usb(pico2_demo_dual 1)
pico_enable_stdio_uart(pico2_demo_dual 0)
endif()

pico_add_extra_outputs(pico2_demo_dual)
