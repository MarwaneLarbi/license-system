add_executable(license-server src/main.cpp)
target_link_libraries(license-server PRIVATE license_common)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(license-server PRIVATE -pie)
endif()
