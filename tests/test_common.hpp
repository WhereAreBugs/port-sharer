#pragma once

#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

struct TestFailure : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

#define EXPECT_TRUE(cond) \
    do { if (!(cond)) throw TestFailure(std::string("EXPECT_TRUE failed: ") + #cond); } while (false)

#define EXPECT_FALSE(cond) EXPECT_TRUE(!(cond))

#define EXPECT_EQ(lhs, rhs) \
    do { \
        auto _lhs = (lhs); \
        auto _rhs = (rhs); \
        if (!(_lhs == _rhs)) { \
            throw TestFailure(std::string("EXPECT_EQ failed: ") + #lhs + " != " + #rhs); \
        } \
    } while (false)

#define EXPECT_NE(lhs, rhs) EXPECT_FALSE((lhs) == (rhs))

struct TestEntry {
    const char* name;
    std::function<void()> fn;
};

inline int run_tests(std::initializer_list<TestEntry> tests) {
    int failed = 0;
    for (const auto& t : tests) {
        try {
            t.fn();
            std::cout << "[PASS] " << t.name << "\n";
        } catch (const std::exception& ex) {
            ++failed;
            std::cerr << "[FAIL] " << t.name << ": " << ex.what() << "\n";
        }
    }
    if (failed) {
        std::cerr << failed << " test(s) failed\n";
        return 1;
    }
    std::cout << "All tests passed\n";
    return 0;
}
