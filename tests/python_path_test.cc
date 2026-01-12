#include <iostream>
#include <string>
#include <cassert>
#include <vector>
#include <err.h>
#include "libpstack/python.h"
#include "libpstack/exception.h"

// Mock Exception for standalone testing if needed, but we are linking against libpstack/procman
// which contains the Exception class.

void test_py_version_from_filename(const std::string& path, int expected_major, int expected_minor, bool should_throw) {
    try {
        auto [major, minor] = pstack::getPythonVersionFromFilename(path);
        if (should_throw) {
            errx(1, "Expected exception for path: %s, but got %d.%d", path.c_str(), major, minor);
        }
        if (major != expected_major || minor != expected_minor) {
            errx(1, "Failed for path: %s. Expected %d.%d, got %d.%d", path.c_str(), expected_major, expected_minor, major, minor);
        }
        std::cout << "PASS: " << path << " -> " << major << "." << minor << std::endl;
    } catch (const std::exception& e) {
        if (!should_throw) {
             errx(1, "Unexpected exception for path: %s: %s", path.c_str(), e.what());
        }
        std::cout << "PASS: " << path << " -> threw exception as expected (" << e.what() << ")" << std::endl;
    }
}

int main() {
    // Standard cases
    test_py_version_from_filename("/usr/lib/libpython3.9.so", 3, 9, false);
    test_py_version_from_filename("/usr/lib/python3.9/config-3.9-x86_64-linux-gnu/libpython3.9.so", 3, 9, false);
    test_py_version_from_filename("libpython2.7.so", 2, 7, false);
    // Complex paths (Bazel-like)
    test_py_version_from_filename("/execroot/_main/bazel-out/k8-opt/bin/Foo/Foo.runfiles/+_repo_rules+RPM/python39/_python3.9_dc/libpython3.9.so.1.0", 3, 9, false);

    // Filename only cases
    test_py_version_from_filename("python3.9", 3, 9, false);
    test_py_version_from_filename("python3.9.so", 3, 9, false);

    // Additional separators (should be handled by standard path logic, but good to check)
    test_py_version_from_filename("/usr//lib//python3.8//libpython3.8.so", 3, 8, false);

    // Edge cases for length and format
    // Too short
    test_py_version_from_filename("/usr/bin/python", 0, 0, true);
    // Too short for X.Y logic
    test_py_version_from_filename("/usr/bin/python3", 0, 0, true);
    // Missing dot/digit at expected pos
    test_py_version_from_filename("libpython39.so", 0, 0, true); 

    // Directory contains "python", filename does not
    test_py_version_from_filename("/opt/python/bin/my_app", 0, 0, true);

    // other invalid names
    test_py_version_from_filename("/usr/lib/libpython.so", 0, 0, true);
    test_py_version_from_filename("not_a_python_lib.so", 0, 0, true);
    // Ends in slash, no filename python
    test_py_version_from_filename("/usr/lib/python3.9/", 0, 0, true);

    return 0;
}
