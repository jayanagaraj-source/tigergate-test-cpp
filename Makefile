# Plain-g++ build so the fixture compiles without CMake/Conan present.
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wno-format-security -Wno-deprecated-declarations -Isrc
LDLIBS   ?= -lssl -lcrypto -lsqlite3
BUILD    := build
BIN      := $(BUILD)/tigergate
LIBSRC   := $(filter-out src/main.cpp,$(wildcard src/*.cpp))
LIBOBJ   := $(patsubst src/%.cpp,$(BUILD)/%.o,$(LIBSRC))

.PHONY: all test run asan scan sbom clean

all: $(BIN)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.cpp src/tigergate.hpp src/secrets.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BIN): $(LIBOBJ) src/main.cpp
	$(CXX) $(CXXFLAGS) src/main.cpp $(LIBOBJ) -o $@ $(LDLIBS)

$(BUILD)/test_app: $(LIBOBJ) tests/test_app.cpp
	$(CXX) $(CXXFLAGS) tests/test_app.cpp $(LIBOBJ) -o $@ $(LDLIBS)

test: $(BUILD)/test_app
	./$(BUILD)/test_app

run: $(BIN)
	./$(BIN) version

# Memory-corruption probes; each is expected to ABORT under ASan.
asan: | $(BUILD)
	$(CXX) $(CXXFLAGS) -g -O0 -fsanitize=address,undefined src/*.cpp -o $(BUILD)/tigergate-asan $(LDLIBS)
	-./$(BUILD)/tigergate-asan copy AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	-./$(BUILD)/tigergate-asan uaf
	-./$(BUILD)/tigergate-asan dfree
	-./$(BUILD)/tigergate-asan header

# Convenience wrapper around whichever scanners are on PATH.
scan:
	@command -v semgrep    >/dev/null && semgrep scan --config auto . || echo "skip: semgrep"
	@command -v trivy      >/dev/null && trivy fs --scanners vuln,secret,misconfig,license . || echo "skip: trivy"
	@command -v gitleaks   >/dev/null && gitleaks detect --no-git -v || echo "skip: gitleaks"
	@command -v checkov    >/dev/null && checkov -d . || echo "skip: checkov"
	@command -v flawfinder >/dev/null && flawfinder src/ || echo "skip: flawfinder"
	@command -v cppcheck   >/dev/null && cppcheck --enable=all --inconclusive src/ || echo "skip: cppcheck"

sbom:
	@command -v syft >/dev/null && syft . -o cyclonedx-json=sbom/bom.cdx.json -o spdx-json=sbom/sbom.spdx.json || echo "skip: syft"

clean:
	rm -rf $(BUILD)
