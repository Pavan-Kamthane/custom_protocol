#include "AES.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>
#include <vector>

AES::AES(const std::string& key) {
    // Initialize the key to a 256-bit key
    if (key.length() == 32) {
        std::memcpy(this->key, key.c_str(), 32);
    } else {
        std::cerr << "Key length must be 32 characters for AES-256." << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

void AES::handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

std::string AES::encrypt(const std::string& plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char iv[AES_BLOCK_SIZE];
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Generate a random IV
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) handleErrors();

    // Initialize the encryption operation with AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    // Provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length())) handleErrors();
    ciphertext_len = len;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) handleErrors();
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Return the IV + ciphertext as a hex string
    std::string result;
    result.reserve(2 * (AES_BLOCK_SIZE + ciphertext_len));
    for (int i = 0; i < AES_BLOCK_SIZE; i++) result += "0123456789ABCDEF"[iv[i] >> 4], result += "0123456789ABCDEF"[iv[i] & 0xF];
    for (int i = 0; i < ciphertext_len; i++) result += "0123456789ABCDEF"[ciphertext[i] >> 4], result += "0123456789ABCDEF"[ciphertext[i] & 0xF];
    return result;
}

std::string AES::decrypt(const std::string& ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char iv[AES_BLOCK_SIZE];
    std::vector<unsigned char> plaintext(ciphertext.size());

    // Extract the IV from the ciphertext
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv[i] = (ciphertext[2 * i] > '9' ? ciphertext[2 * i] - 'A' + 10 : ciphertext[2 * i] - '0') << 4 | (ciphertext[2 * i + 1] > '9' ? ciphertext[2 * i + 1] - 'A' + 10 : ciphertext[2 * i + 1] - '0');
    }

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    // Initialize the decryption operation with AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) handleErrors();

    // Provide the message to be decrypted, and obtain the plaintext output
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.c_str()) + 2 * AES_BLOCK_SIZE, ciphertext.length() / 2 - AES_BLOCK_SIZE)) handleErrors();
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) handleErrors();
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}
