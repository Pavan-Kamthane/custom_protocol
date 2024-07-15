#ifndef VIGENERE_CIPHER_H
#define VIGENERE_CIPHER_H

#include <string>

class VigenereCipher {
public:
    explicit VigenereCipher(const std::string& key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    std::string key;
};

#endif // VIGENERE_CIPHER_H
