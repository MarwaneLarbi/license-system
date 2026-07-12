add_library(license_common STATIC
    src/crypto.cpp
    src/fingerprint.cpp
    src/tpm_software.cpp
    src/license.cpp
    src/keystore.cpp
    $<$<BOOL:${TSS2_ESYS_FOUND}>:src/tpm_linux.cpp>
    $<$<BOOL:${WIN32}>:src/tpm_windows.cpp>
)

target_include_directories(license_common
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${ARGON2_INCLUDE_DIR}
)

target_link_libraries(license_common
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
    PRIVATE
        ${ARGON2_LIBRARY}
)

if(TSS2_ESYS_FOUND)
    target_include_directories(license_common PRIVATE ${TSS2_ESYS_INCLUDE_DIRS})
    target_link_libraries(license_common PRIVATE
        ${TSS2_ESYS_LIBRARIES}
        ${TSS2_MU_LIBRARIES}
        ${TSS2_SYS_LIBRARIES}
        ${TSS2_TCTILDR_LIBRARIES}
    )
endif()

if(WIN32)
    target_link_libraries(license_common PRIVATE tbs bcrypt)
endif()

target_compile_definitions(license_common PUBLIC
    LICENSE_SYSTEM_VERSION="${PROJECT_VERSION}"
)
