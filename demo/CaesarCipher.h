#ifndef CAESAR_CIPHER_H
#define CAESAR_CIPHER_H

#include <string>

class CaesarCipher {
public:
    explicit CaesarCipher(int key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    int key;
};

#endif // CAESAR_CIPHER_H
