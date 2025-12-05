#include "stress_common.hpp"

using namespace stress_shared;

int main() {
    return run_tests({
        {"stress_64", [] { stress_run({64, "64"}); }},
        {"stress_64_no_proxy", [] { stress_run({64, "64_no_proxy", ProxyMode::AllOff}); }},
        {"stress_128", [] { stress_run({128, "128"}); }},
        {"stress_256", [] { stress_run({256, "256"}); }},
    });
}
