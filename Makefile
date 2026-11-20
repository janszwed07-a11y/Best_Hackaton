CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -Wshadow
CFLAGS  += $(shell pkg-config --cflags cairo fontconfig)
LDLIBS  += $(shell pkg-config --libs cairo fontconfig) -lm
CFLAGS  += $(SAN)
LDFLAGS += $(SAN)

SRC := $(wildcard src/*.c)
OBJ := $(SRC:src/%.c=build/%.o)
BIN := pcapan

.PHONY: all clean samples test asan

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c src/*.h | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

# Generate the synthetic test captures
samples:
	python3 tools/gen_samples.py samples

# Run the tool on every sample and check it succeeds
test: $(BIN) samples
	@for f in samples/*.pcap; do \
		name=$$(basename $$f .pcap); \
		./$(BIN) -q -o out/$$name $$f || exit 1; \
		echo "ok  $$f -> out/$$name/"; \
	done

# Build with AddressSanitizer + UndefinedBehaviorSanitizer
asan: clean
	$(MAKE) SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"

clean:
	rm -rf build $(BIN) out
