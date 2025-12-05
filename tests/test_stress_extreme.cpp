#include "stress_common.hpp"

using namespace stress_shared;

int main() {
    return run_tests({
        {"stress_extreme", [] { stress_run_extreme(); }},
    });
}
