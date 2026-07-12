add_library(liblicenseclient STATIC
    src/license_client.cpp
)

target_include_directories(liblicenseclient
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(liblicenseclient
    PUBLIC  license_common
)

# CLI executable.
add_executable(license-client src/main.cpp)
target_link_libraries(license-client PRIVATE liblicenseclient)

# Compiler hardening: PIE on non-Windows.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(license-client PRIVATE -pie)
endif()
