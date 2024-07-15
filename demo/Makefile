CXX = g++
CXXFLAGS = -std=c++11 -Wall
LIBS = -lssl -lcrypto  # Link against OpenSSL libraries if using AES

all: main

main: main.o CaesarCipher.o VigenereCipher.o AES.o
    $(CXX) $(CXXFLAGS) -o main main.o CaesarCipher.o VigenereCipher.o AES.o $(LIBS)

main.o: main.cpp CaesarCipher.h VigenereCipher.h AES.h
    $(CXX) $(CXXFLAGS) -c main.cpp

CaesarCipher.o: CaesarCipher.cpp CaesarCipher.h
    $(CXX) $(CXXFLAGS) -c CaesarCipher.cpp

VigenereCipher.o: VigenereCipher.cpp VigenereCipher.h
    $(CXX) $(CXXFLAGS) -c VigenereCipher.cpp

AES.o: AES.cpp AES.h
    $(CXX) $(CXXFLAGS) -c AES.cpp

clean:
    rm -f *.o main
