# pvac-hfhe-toolkit
#
# Build needs the pinned PVAC-HFHE library headers and the challenge serializer.
# Run `./setup.sh` first (clones them into ./vendor), or override the paths:
#
#   make PVAC_INC=/path/to/pvac_hfhe_cpp/include SER_INC=/path/to/hfhe-challenge/source
#
# Requires a CPU with hardware AES (x86_64 -maes, or aarch64 crypto extensions).

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O3 -march=native -maes -pthread
PVAC_INC ?= vendor/pvac_hfhe_cpp/include
SER_INC  ?= vendor/hfhe-challenge/source
INCLUDES  = -I$(PVAC_INC) -I$(SER_INC)

BIN = bin
SRC = src

all: $(BIN)/parse_artifacts $(BIN)/oracle_poc $(BIN)/recover_mnemonic

$(BIN):
	mkdir -p $(BIN)

$(BIN)/%: $(SRC)/%.cpp | $(BIN)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf $(BIN)

.PHONY: all clean
