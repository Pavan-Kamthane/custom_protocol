#include "VigenereCipher.h"

VigenereCipher::VigenereCipher(const std::string& key) : key(key) {}

std::string VigenereCipher::encrypt(const std::string& plaintext) {
    std::string ciphertext = plaintext;
    int keyLength = key.size();
    for (size_t i = 0; i < plaintext.size(); ++i) {
        char c = plaintext[i];
        if (isalpha(c)) {
            char offset = isupper(c) ? 'A' : 'a';
            c = (c - offset + (isupper(key[i % keyLength]) ? key[i % keyLength] - 'A' : key[i % keyLength] - 'a')) % 26 + offset;
        }
        ciphertext[i] = c;
    }
    return ciphertext;
}

std::string VigenereCipher::decrypt(const std::string& ciphertext) {
    std::string plaintext = ciphertext;
    int keyLength = key.size();
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        char c = ciphertext[i];
        if (isalpha(c)) {
            char offset = isupper(c) ? 'A' : 'a';
            c = (c - offset - (isupper(key[i % keyLength]) ? key[i % keyLength] - 'A' : key[i % keyLength] - 'a') + 26) % 26 + offset;
        }
        plaintext[i] = c;
    }
    return plaintext;
}
