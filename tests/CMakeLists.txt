add_executable(license_tests
    test_crypto.cpp
    test_fingerprint.cpp
    test_license.cpp
)

target_link_libraries(license_tests
    PRIVATE
        license_common
        liblicenseclient
        Catch2::Catch2WithMain
)

catch_discover_tests(license_tests)
