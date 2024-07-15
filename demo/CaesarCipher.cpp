#include "CaesarCipher.h"

CaesarCipher::CaesarCipher(int key) : key(key) {}

std::string CaesarCipher::encrypt(const std::string& plaintext) {
    std::string ciphertext = plaintext;
    for (char& c : ciphertext) {
        if (isalpha(c)) {
            char offset = isupper(c) ? 'A' : 'a';
            c = (c - offset + key) % 26 + offset;
        }
    }
    return ciphertext;
}

std::string CaesarCipher::decrypt(const std::string& ciphertext) {
    std::string plaintext = ciphertext;
    for (char& c : plaintext) {
        if (isalpha(c)) {
            char offset = isupper(c) ? 'A' : 'a';
            c = (c - offset - key + 26) % 26 + offset;
        }
    }
    return plaintext;
}
