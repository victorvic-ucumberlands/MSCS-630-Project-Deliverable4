# Makefile - build the shell on Linux (g++ >= 7, C++17)
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -g
SRC      := $(wildcard src/*.cpp)
OBJ      := $(SRC:src/%.cpp=build/%.o)

DEMO_BIN := demos/cpuburn demos/memproc demos/counter demos/pc demos/philo demos/mktest

all: myshell $(DEMO_BIN)

myshell: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

build/%.o: src/%.cpp $(wildcard src/*.hpp) | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build:
	mkdir -p build

# CPU-bound helper program used as a scheduler workload in the demos
demos/cpuburn: demos/cpuburn.c
	$(CXX) -std=c++17 -O1 -Wall -o $@ $<

# Deliverable 3 test programs (plain C, they only include src/mkernel.h)
CC       ?= gcc
demos/memproc demos/counter demos/pc demos/philo demos/mktest: demos/%: demos/%.c src/mkernel.h
	$(CC) -std=gnu11 -O2 -Wall -Wextra -o $@ $<

demo: myshell $(DEMO_BIN)
	./demos/run_demos.sh

clean:
	rm -rf build myshell myshell_asan $(DEMO_BIN) evidence

.PHONY: all demo clean

# Extra safety net: build with AddressSanitizer + UBSan (output: myshell_asan)
sanitize:
	$(CXX) -std=c++17 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer src/*.cpp -o myshell_asan

.PHONY: sanitize
