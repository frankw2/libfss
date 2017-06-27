CC=g++
CFLAGS=-fomit-frame-pointer -maes -std=c++11 -msse4.2 -fno-strict-aliasing -pedantic -Wall -Wextra -Wunreachable-code -Wmissing-declarations -Wunused-function -Wno-overlength-strings -Wno-deprecated-declarations -O3
LDFLAGS= -L/usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu/libcrypto.a -ldl -lssl -lgmpxx -lgmp
SOURCES= fss-client.cpp fss-server.cpp fss-common.cpp fss-test.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=fss-test
LIB=libfss.a

all: $(SOURCES) $(EXECUTABLE) $(LIB)

$(EXECUTABLE): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(LIB): fss-client.o fss-server.o fss-common.o
	ar rcs $@ $^

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@

.PHONY: clean

clean:
	rm -f *.o $(LIB) $(OBJECTS) $(EXECUTABLE)
