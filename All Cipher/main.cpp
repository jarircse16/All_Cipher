#include <iostream>
#include <string>
#include <cctype>
#include <openssl/aes.h>
#include <openssl/rand.h>

// Caesar Cipher
std::string caesarCipher(const std::string& text, int shift) {
    std::string encryptedText = "";
    for (char c : text) {
        if (std::isalpha(c)) {
            char base = std::isupper(c) ? 'A' : 'a';
            encryptedText += static_cast<char>((c - base + shift) % 26 + base);
        } else {
            encryptedText += c;
        }
    }
    return encryptedText;
}

// Substitution Cipher
std::string substitutionCipher(const std::string& text, const std::string& key) {
    std::string encryptedText = text;
    for (size_t i = 0; i < text.length(); i++) {
        if (std::isalpha(text[i])) {
            char base = std::isupper(text[i]) ? 'A' : 'a';
            encryptedText[i] = key[text[i] - base];
        }
    }
    return encryptedText;
}

// Feistel Cipher
std::string feistelCipher(const std::string& text, const std::string& key) {
    std::string encryptedText = text;
    for (size_t i = 0; i < text.length(); i++) {
        encryptedText[i] ^= key[i % key.length()];
    }
    return encryptedText;
}

// AES Encryption
std::string aesEncryption(const std::string& text, const std::string& key) {
    std::string encryptedText;

    // Generate initialization vector (IV)
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    // Set up AES key structure
    AES_KEY aesKey;
    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &aesKey);

    // Encrypt the text using AES-128 CBC mode
    size_t textLength = text.length();
    size_t encryptedLength = ((textLength + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char* encryptedBuffer = new unsigned char[encryptedLength];

    AES_cbc_encrypt(
        reinterpret_cast<const unsigned char*>(text.c_str()),  // input data
        encryptedBuffer,                                        // output buffer
        textLength,                                             // input data length
        &aesKey,                                                // encryption key
        iv,                                                     // initialization vector
        AES_ENCRYPT                                             // encryption mode
    );

    // Convert encrypted buffer to a string
    for (size_t i = 0; i < encryptedLength; i++) {
        encryptedText += static_cast<char>(encryptedBuffer[i]);
    }

    delete[] encryptedBuffer;

    return encryptedText;
}

// Mono Alphabetic Cipher
std::string monoAlphabeticCipher(const std::string& text, const std::string& key) {
    std::string encryptedText = text;
    for (size_t i = 0; i < text.length(); i++) {
        if (std::isalpha(text[i])) {
            char base = std::isupper(text[i]) ? 'A' : 'a';
            encryptedText[i] = key[text[i] - base];
        }
    }
    return encryptedText;
}

int main() {
    int cipherOption;
    std::string plaintext;
    std::string key;

    std::cout << "Choose a cipher to use:\n";
    std::cout << "1. Caesar Cipher\n";
    std::cout << "2. Substitution Cipher\n";
    std::cout << "3. Feistel Cipher\n";
    std::cout << "4. AES Encryption\n";
    std::cout << "5. Mono Alphabetic Cipher\n";
    std::cout << "Enter the cipher option (1-5): ";
    std::cin >> cipherOption;
    std::cin.ignore();

    std::cout << "Enter the plaintext: ";
    std::getline(std::cin, plaintext);

    std::cout << "Enter the key: ";
    std::getline(std::cin, key);

    std::string ciphertext;
    switch (cipherOption) {
        case 1:
            ciphertext = caesarCipher(plaintext, 3);
            break;
        case 2:
            ciphertext = substitutionCipher(plaintext, key);
            break;
        case 3:
            ciphertext = feistelCipher(plaintext, key);
            break;
        case 4:
            ciphertext = aesEncryption(plaintext, key);
            break;
        case 5:
            ciphertext = monoAlphabeticCipher(plaintext, key);
            break;
        default:
            std::cout << "Invalid option!";
            return 1;
    }

    std::cout << "Ciphertext: " << ciphertext << std::endl;

    return 0;
}
