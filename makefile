CXXFLAGS=--std=c++20 -g -Wall -Werror -O3
LDXXFLAGS=-lstdc++fs -lstdc++

ALL_HPP=$(wildcard *.hpp)
ALL_CPP=$(wildcard *.cpp)
ALL=$(ALL_CPP) $(ALL_HPP)

ut: main
	./main unit-tests
benchmark: main
	./main benchmark

main: $(ALL)
	$(CXX) $(CXXFLAGS) -o $@ $(ALL_CPP) $(LDXXFLAGS)

.PHONY: ut
