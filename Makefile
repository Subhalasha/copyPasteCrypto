PROG=cipher

# 
UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
	LFLAGS=-L/usr/local/libsodium/lib
	CFLAGS=-I/usr/local/libsodium/lib
	CXXFLAGS = -g -Wall -std=c++11
	CXX=g++
else
	LFLAGS=-L/usr/local/Cellar/libsodium/1.0.11/lib
	CFLAGS=-I/usr/local/Cellar/libsodium/1.0.11/include
	CXXFLAGS = -g -Wall -std=c++11
	CXX=g++
endif

all: cipher

cipher: main.o cipher.o
	$(CXX) -Wall main.o cipher.o $(LFLAGS) -lsodium -o $(PROG)

test: test.o cipher.o
	$(CXX) -Wall test.o cipher.o $(LFLAGS) -lsodium -o test

test.o: test.cpp cipher.h
	$(CXX) $(CXXFLAGS) test.cpp $(CFLAGS) -c

main.o: main.cpp cipher.h
	$(CXX) $(CXXFLAGS) main.cpp $(CFLAGS) -c

cipher.o: cipher.cpp cipher.h
	$(CXX) $(CXXFLAGS) cipher.cpp $(CFLAGS) -c

.PHONY: clean

clean:
	rm -f *.o $(PROG)

