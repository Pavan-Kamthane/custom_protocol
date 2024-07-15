#include <iostream>
#include "CaesarCipher.h"
#include "VigenereCipher.h"
#include "AES.h"

int main() {
    // Caesar Cipher
    CaesarCipher caesar(5);
    std::string caesarEncrypted = caesar.encrypt("Hello, World!");
    std::string caesarDecrypted = caesar.decrypt(caesarEncrypted);
    std::cout << "Caesar Encrypted: " << caesarEncrypted << std::endl;
    std::cout << "Caesar Decrypted: " << caesarDecrypted << std::endl;

    // Vigenere Cipher
    VigenereCipher vigenere("KEY");
    std::string vigenereEncrypted = vigenere.encrypt("Hello, World!");
    std::string vigenereDecrypted = vigenere.decrypt(vigenereEncrypted);
    std::cout << "Vigenere Encrypted: " << vigenereEncrypted << std::endl;
    std::cout << "Vigenere Decrypted: " << vigenereDecrypted << std::endl;

    // AES Encryption
    AES aes("01234567890123456789012345678901");
    std::string aesEncrypted = aes.encrypt("Hello, World!");
    std::string aesDecrypted = aes.decrypt(aesEncrypted);
    std::cout << "AES Encrypted: " << aesEncrypted << std::endl;
    std::cout << "AES Decrypted: " << aesDecrypted << std::endl;

    return 0;
}
