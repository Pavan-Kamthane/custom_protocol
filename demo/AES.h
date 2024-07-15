#ifndef AES_H
#define AES_H

#include <string>

class AES {
public:
    explicit AES(const std::string& key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    unsigned char key[32];
    void handleErrors(void);
};

#endif // AES_H
