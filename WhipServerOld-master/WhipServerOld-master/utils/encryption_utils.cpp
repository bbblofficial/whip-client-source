#include "encryption_utils.h"
#include <sstream>
#include <iomanip>
#include <iostream>
#include <openssl/rand.h>
#include "aes.h"

const std::vector<unsigned char> EncryptionUtils::FIXED_SALT(8, 0);
std::string EncryptionUtils::base64Chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void EncryptionUtils::initOpenSSL() {
    static bool initialized = false;
    if (!initialized) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        initialized = true;
    }
}

void EncryptionUtils::handleOpenSSLError(const char* operation) {
    char errBuf[256];
    unsigned long err = ERR_get_error();
    ERR_error_string_n(err, errBuf, sizeof(errBuf));

    char errorMsg[512];
    sprintf(errorMsg, "%s failed: %s", operation, errBuf);
    throw std::runtime_error(errorMsg);
}

const char* EncryptionUtils::encrypt(const char* input) {
    static std::string output;
    output.clear();

    for (size_t i = 0; input[i] != '\0'; i++) {
        char hexBuf[8];
        sprintf(hexBuf, "%02x-", (unsigned char)input[i]);
        output += hexBuf;
    }

    // Retirer le dernier '-'
    if (!output.empty() && output.back() == '-') {
        output.pop_back();
    }

    return output.c_str();
}

const char* EncryptionUtils::decrypt(const char* input) {
    static std::string output;
    output.clear();
    std::string currentHex;

    for (size_t i = 0; input[i] != '\0'; i++) {
        // Si c'est un tiret, vérifier s'il fait partie d'un délimiteur "-|x"
        if (input[i] == '-') {
            // Regarder si c'est le début de "-|x"
            if (input[i + 1] != '\0' && input[i + 2] != '\0' &&
                input[i + 1] == '|' && input[i + 2] == 'x') {
                // C'est un délimiteur, l'ajouter tel quel
                output += "-|x";
                i += 2;  // Sauter les 2 caractères suivants
                continue;
            }

            // C'est un tiret de séparation hex
            if (!currentHex.empty()) {
                // Convertir le hex en valeur
                int value = 0;
                for (char c : currentHex) {
                    value = value * 16 + (c >= 'a' ? c - 'a' + 10 :
                        c >= 'A' ? c - 'A' + 10 :
                        c - '0');
                }
                output += static_cast<char>(value);
                currentHex.clear();
            }
            continue;
        }

        // Ajouter au hex courant
        currentHex += input[i];

        // Si on a 2 caractères hex, convertir
        if (currentHex.length() == 2) {
            // Convertir le hex en valeur
            int value = 0;
            for (char c : currentHex) {
                value = value * 16 + (c >= 'a' ? c - 'a' + 10 :
                    c >= 'A' ? c - 'A' + 10 :
                    c - '0');
            }
            output += static_cast<char>(value);
            currentHex.clear();
        }
    }

    // Gérer le dernier hex si nécessaire
    if (!currentHex.empty()) {
        // Convertir le hex en valeur
        int value = 0;
        for (char c : currentHex) {
            value = value * 16 + (c >= 'a' ? c - 'a' + 10 :
                c >= 'A' ? c - 'A' + 10 :
                c - '0');
        }
        output += static_cast<char>(value);
    }

    return output.c_str();
}

const char* EncryptionUtils::aesEncrypt(const char* input, size_t input_len, const char* key) {
    try {
        std::cout << "\n[Server XorString] === Starting Encryption ===\n";
        std::cout << "[Server XorString] Input length: " << input_len << std::endl;
        std::cout << "[Server XorString] Key: " << key << std::endl;

        // Générer IV
        std::vector<uint8_t> iv(AES_BLOCKLEN);
        for (int i = 0; i < AES_BLOCKLEN; i++) {
            iv[i] = rand() % 256;
        }

        std::cout << "[Server XorString] IV (hex): ";
        for (int i = 0; i < AES_BLOCKLEN; i++)
            printf("%02x", (unsigned char)iv[i]);
        std::cout << std::endl;

        // Dériver la clé
        std::vector<uint8_t> derived_key(AES_KEYLEN);
        size_t keyLen = 0;
        for (keyLen = 0; keyLen < 128 && key[keyLen] != '\0'; keyLen++);

        for (size_t i = 0; i < AES_KEYLEN; i++) {
            derived_key[i] = key[i % keyLen] ^ (i * 13);
        }

        std::cout << "[Server XorString] Derived key (hex): ";
        for (size_t i = 0; i < derived_key.size(); i++)
            printf("%02x", derived_key[i]);
        std::cout << std::endl;

        // PKCS7 padding pour l'input original
        size_t padding_len = AES_BLOCKLEN - (input_len % AES_BLOCKLEN);

        // Créer un buffer avec la taille finale
        size_t padded_size = input_len + padding_len;
        std::vector<uint8_t> padded_input(padded_size);

        // Copier les données d'entrée
        memcpy(padded_input.data(), input, input_len);

        // Ajouter le padding standard PKCS7
        for (size_t i = input_len; i < padded_size; i++) {
            padded_input[i] = (uint8_t)padding_len;
        }

        std::cout << "[Server XorString] Original input length: " << input_len << std::endl;
        std::cout << "[Server XorString] Padding length: " << padding_len << std::endl;
        std::cout << "[Server XorString] Padded input length: " << padded_size << std::endl;

        // Chiffrer
        AES_ctx ctx;
        AES_init_ctx_iv(&ctx, derived_key.data(), iv.data());

        // Travailler sur une copie pour ne pas modifier l'original
        std::vector<uint8_t> encrypted = padded_input;
        AES_CBC_encrypt_buffer(&ctx, encrypted.data(), encrypted.size());

        // Message final: [MAGIC(4)][ORIGINAL_LEN(4)][IV(16)][ENCRYPTED_DATA]
        size_t header_size = 4 + 4 + AES_BLOCKLEN;
        size_t final_message_len = header_size + encrypted.size();
        std::vector<uint8_t> final_message(final_message_len);

        // 1. Magic number
        uint32_t magic = 0xAECBDAEF;
        memcpy(final_message.data(), &magic, 4);

        // 2. Taille originale
        uint32_t orig_len = static_cast<uint32_t>(input_len);
        memcpy(final_message.data() + 4, &orig_len, 4);

        // 3. IV
        memcpy(final_message.data() + 8, iv.data(), AES_BLOCKLEN);

        // 4. Données chiffrées
        memcpy(final_message.data() + header_size, encrypted.data(), encrypted.size());

        std::cout << "[Server XorString] Final message length before base64: " << final_message_len << std::endl;

        // Encoder en base64 - IMPORTANT: passer la taille explicitement et récupérer la taille de sortie
        size_t base64_len = 0;
        const char* base64Result = toBase64((const char*)final_message.data(), final_message_len, &base64_len);

        std::cout << "[Server XorString] Final base64 length: " << base64_len << std::endl;

        // Vérification que la taille n'est pas anormalement petite
        if (base64_len < 10) {
            std::cout << "[Server XorString] WARNING: Base64 output too small! Adding padding." << std::endl;

            // Créer une chaîne plus longue en répétant le résultat base64
            std::vector<char> padded_base64(base64_len * 20 + 1);
            for (int i = 0; i < 20; i++) {
                memcpy(padded_base64.data() + (i * base64_len), base64Result, base64_len);
            }
            padded_base64[base64_len * 20] = '\0';

            // Utiliser cette chaîne plus longue
            const char* thread_safe_result = ThreadSafeBuffer::allocate(base64_len * 20 + 1);
            memcpy((void*)thread_safe_result, padded_base64.data(), base64_len * 20 + 1);

            std::cout << "[Server XorString] Padded base64 length: " << base64_len * 20 << std::endl;
            return thread_safe_result;
        }

        // Allouer un buffer thread-safe pour le retour
        const char* thread_safe_result = ThreadSafeBuffer::allocate(base64_len + 1);
        memcpy((void*)thread_safe_result, base64Result, base64_len);
        ((char*)thread_safe_result)[base64_len] = '\0'; // S'assurer de la terminaison nulle

        return thread_safe_result;
    }
    catch (const std::exception& e) {
        std::cout << "[Server XorString] Error: " << e.what() << std::endl;
        throw;
    }
}

// Dans encryption_utils.cpp - Version EXACTEMENT compatible avec le client

const char* EncryptionUtils::aesDecrypt(const char* input, const char* key, size_t* output_len) {
    try {
        std::cout << "\n[FromXorString] === Starting Decryption ===\n";
        std::cout << "[FromXorString] Input: '" << input << "'" << std::endl;
        std::cout << "[FromXorString] Key: '" << key << "'" << std::endl;

        // Calculer la longueur de la chaîne base64 d'entrée EXACTEMENT comme le client
        size_t input_len = 0;
        for (input_len = 0; input[input_len] != '\0'; input_len++);

        std::cout << "[FromXorString] Input base64 length: " << input_len << std::endl;

        // Décoder base64 EXACTEMENT comme le client
        size_t decoded_len = 0;
        unsigned char* decoded = fromBase64(input, &decoded_len);

        if (!decoded || decoded_len < 8 + AES_BLOCKLEN) {
            if (decoded) delete[] decoded;
            throw std::runtime_error("Input too short or base64 decode failed");
        }

        std::cout << "[fromBase64] Decoded " << input_len << " bytes to " << decoded_len << " bytes" << std::endl;

        // Vérifier le magic number EXACTEMENT comme le client
        uint32_t magic = 0;
        memcpy(&magic, decoded, 4);
        if (magic != 0xAECBDAEF) {
            delete[] decoded;
            std::cout << "[FromXorString] Invalid magic: 0x" << std::hex << magic << std::dec << std::endl;
            throw std::runtime_error("Invalid magic number");
        }

        // Extraire la longueur originale EXACTEMENT comme le client
        uint32_t original_len = 0;
        memcpy(&original_len, decoded + 4, 4);
        std::cout << "[FromXorString] Original data length: " << original_len << std::endl;

        // VALIDATION STRICTE comme le client
        size_t encrypted_data_len = decoded_len - 8 - AES_BLOCKLEN;

        // REPRODUCTION EXACTE de la logique client pour original_len
        if (original_len > 1000000 || original_len > encrypted_data_len) {
            std::cout << "[FromXorString] WARNING: original_len seems invalid (" << original_len
                << "), using client-compatible recovery" << std::endl;

            // Utiliser EXACTEMENT la même logique que le client
            if (encrypted_data_len > AES_BLOCKLEN) {
                original_len = encrypted_data_len - (encrypted_data_len % AES_BLOCKLEN);
                // Réduire d'un bloc pour tenir compte du padding (comme le client)
                original_len -= AES_BLOCKLEN;
                std::cout << "[FromXorString] Adjusted original_len to: " << original_len << std::endl;
            }
            else {
                delete[] decoded;
                throw std::runtime_error("Invalid data size for recovery");
            }
        }

        // Extraire l'IV
        unsigned char iv[AES_BLOCKLEN];
        memcpy(iv, decoded + 8, AES_BLOCKLEN);

        // Extraire les données chiffrées
        unsigned char* encrypted_data = new unsigned char[encrypted_data_len];
        memcpy(encrypted_data, decoded + 8 + AES_BLOCKLEN, encrypted_data_len);

        delete[] decoded;

        std::cout << "[FromXorString] IV (hex): ";
        for (int i = 0; i < AES_BLOCKLEN; i++)
            printf("%02x", iv[i]);
        std::cout << std::endl;

        // Dériver la clé EXACTEMENT comme le client
        size_t key_len = 0;
        for (key_len = 0; key_len < 128 && key[key_len] != '\0'; key_len++);

        std::cout << "[FromXorString] Key length: " << key_len << std::endl;

        unsigned char derived_key[AES_KEYLEN];
        for (size_t i = 0; i < AES_KEYLEN; i++) {
            derived_key[i] = key[i % key_len] ^ (i * 13);
        }

        std::cout << "[FromXorString] Derived key (hex): ";
        for (size_t i = 0; i < AES_KEYLEN; i++)
            printf("%02x", derived_key[i]);
        std::cout << std::endl;

        // Déchiffrer EXACTEMENT comme le client
        AES_ctx ctx;
        AES_init_ctx_iv(&ctx, derived_key, iv);
        AES_CBC_decrypt_buffer(&ctx, encrypted_data, encrypted_data_len);

        // VALIDATION FINALE compatible client
        if (original_len > encrypted_data_len) {
            std::cout << "[FromXorString] Final check failed, original_len=" << original_len
                << " > encrypted_data_len=" << encrypted_data_len << std::endl;
            delete[] encrypted_data;
            throw std::runtime_error("Original length exceeds decrypted data");
        }

        // Allouer le résultat EXACTEMENT comme le client
        const char* result = ThreadSafeBuffer::allocate(original_len + 1);
        memcpy((void*)result, encrypted_data, original_len);
        ((char*)result)[original_len] = '\0';

        // DIAGNOSTIC DÉTAILLÉ
        std::cout << "[FromXorString] Decrypted " << original_len << " bytes successfully" << std::endl;
        std::cout << "[FromXorString] Raw decrypted (hex): ";
        for (size_t i = 0; i < std::min(original_len, (uint32_t)32); i++) {
            printf("%02x ", (unsigned char)result[i]);
        }
        std::cout << std::endl;

        std::cout << "[FromXorString] As string: '";
        for (size_t i = 0; i < original_len; i++) {
            char c = result[i];
            if (c >= 32 && c <= 126) {
                std::cout << c;
            }
            else {
                printf("\\x%02x", (unsigned char)c);
            }
        }
        std::cout << "'" << std::endl;

        // VALIDATION SPÉCIALE pour les données numériques (timestamps, etc.)
        bool allNumeric = true;
        bool hasValidChars = true;
        for (size_t i = 0; i < original_len; i++) {
            char c = result[i];
            if (c < '0' || c > '9') allNumeric = false;
            if (c < 32 || c > 126) hasValidChars = false;
        }

        if (!hasValidChars) {
            std::cout << "[FromXorString] WARNING: Result contains non-printable characters, "
                << "possible decryption issue" << std::endl;
        }

        if (output_len) {
            *output_len = original_len;
        }

        delete[] encrypted_data;
        return result;
    }
    catch (const std::exception& e) {
        std::cout << "[FromXorString] Error: " << e.what() << std::endl;
        throw;
    }
}

const char* EncryptionUtils::toBase64(const char* data, size_t data_len, size_t* output_len) {
    // Table de conversion optimisée
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Pré-calculer la taille nécessaire exacte
    size_t output_size = ((data_len + 2) / 3) * 4;

    // Allouer le buffer de sortie avec taille exacte
    char* encoded = new char[output_size + 1]; // +1 pour null terminator

    // Optimisation par blocs de 3 octets
    size_t i = 0;
    size_t j = 0;

    // Traiter les blocs complets de 3 octets (optimisation principale)
    while (i + 3 <= data_len) {
        // Combiner 3 octets en un entier 24 bits
        uint32_t val = ((unsigned char)data[i] << 16) |
            ((unsigned char)data[i + 1] << 8) |
            (unsigned char)data[i + 2];

        // Extraire les 6 bits pour chaque caractère en une seule opération
        encoded[j++] = base64_chars[(val >> 18) & 0x3F];
        encoded[j++] = base64_chars[(val >> 12) & 0x3F];
        encoded[j++] = base64_chars[(val >> 6) & 0x3F];
        encoded[j++] = base64_chars[val & 0x3F];

        i += 3;
    }

    // Gérer les octets restants si nécessaire
    if (i < data_len) {
        // Premier octet
        uint32_t val = (unsigned char)data[i] << 16;

        // Ajouter le deuxième octet s'il existe
        if (i + 1 < data_len) {
            val |= (unsigned char)data[i + 1] << 8;
        }

        // Toujours ajouter les 2 premiers caractères
        encoded[j++] = base64_chars[(val >> 18) & 0x3F];
        encoded[j++] = base64_chars[(val >> 12) & 0x3F];

        // Gérer le padding en fonction du nombre d'octets restants
        if (i + 1 < data_len) {
            encoded[j++] = base64_chars[(val >> 6) & 0x3F];
            encoded[j++] = '=';
        }
        else {
            encoded[j++] = '=';
            encoded[j++] = '=';
        }
    }

    // Ajout du terminateur nul
    encoded[j] = '\0';

    // Retourner la longueur si nécessaire
    if (output_len) {
        *output_len = j;
    }

    // Allocation thread-safe
    const char* result = ThreadSafeBuffer::allocate(j + 1);
    memcpy((void*)result, encoded, j + 1);
    delete[] encoded;

    return result;
}

unsigned char* EncryptionUtils::fromBase64(const char* input, size_t* output_len) {
    if (!input || !output_len) {
        std::cout << "[fromBase64] Null input or output_len" << std::endl;
        *output_len = 0;
        return nullptr;
    }

    // Create a static conversion table for faster decoding
    static unsigned char decode_table[256];
    static bool table_initialized = false;

    if (!table_initialized) {
        // Initialize with invalid values
        memset(decode_table, 0xFF, 256);

        // Set valid Base64 character values
        for (int i = 0; i < 64; i++) {
            decode_table[(unsigned char)base64Chars[i]] = i;
        }
        table_initialized = true;
    }

    // Get input length and allocate buffer
    size_t in_len = strlen(input);
    size_t pad_count = 0;

    // Count padding at the end
    if (in_len > 0 && input[in_len - 1] == '=') pad_count++;
    if (in_len > 1 && input[in_len - 2] == '=') pad_count++;

    // Calculate output size
    size_t out_len = (in_len * 3) / 4 - pad_count;
    unsigned char* output = new unsigned char[out_len + 1];

    // Process in chunks of 4 characters
    size_t i = 0, j = 0;
    while (i < in_len) {
        // Skip non-Base64 characters
        if (decode_table[(unsigned char)input[i]] == 0xFF) {
            i++;
            continue;
        }

        // Collect 4 valid Base64 characters (or padding)
        uint32_t sextet_a = input[i] == '=' ? 0 : decode_table[(unsigned char)input[i]]; i++;
        uint32_t sextet_b = (i >= in_len || input[i] == '=') ? 0 : decode_table[(unsigned char)input[i]]; i++;
        uint32_t sextet_c = (i >= in_len || input[i] == '=') ? 0 : decode_table[(unsigned char)input[i]]; i++;
        uint32_t sextet_d = (i >= in_len || input[i] == '=') ? 0 : decode_table[(unsigned char)input[i]]; i++;

        // Combine 4 sextets into 3 octets
        uint32_t triple = (sextet_a << 18) + (sextet_b << 12) + (sextet_c << 6) + sextet_d;

        if (j < out_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < out_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < out_len) output[j++] = triple & 0xFF;
    }

    output[j] = 0; // Null-terminate for debugging
    *output_len = j;

    std::cout << "[fromBase64] Decoded " << in_len << " bytes to " << j << " bytes" << std::endl;
    return output;
}

const char* EncryptionUtils::encryptXor(const char* input, size_t input_len, const char* key) {
    try {
        std::cout << "\n[Server EncryptXor] === Starting Encryption ===" << std::endl;
        std::cout << "[Server EncryptXor] Input length: " << input_len << std::endl;
        std::cout << "[Server EncryptXor] Key: " << key << std::endl;

        // Calculate key length
        size_t key_len = 0;
        for (key_len = 0; key_len < 128 && key[key_len] != '\0'; key_len++);

        // Create XOR encrypted buffer
        char* encrypted = new char[input_len + 1];

        // Apply advanced XOR with position-dependent modifier
        for (size_t i = 0; i < input_len; i++) {
            encrypted[i] = input[i] ^ key[i % key_len] ^ ((i * 13) & 0xFF);
        }
        encrypted[input_len] = '\0';

        // Copy to thread-safe buffer
        const char* thread_safe_result = ThreadSafeBuffer::allocate(input_len + 1);
        memcpy((void*)thread_safe_result, encrypted, input_len + 1);
        delete[] encrypted;

        return thread_safe_result;
    }
    catch (const std::exception& e) {
        std::cout << "[Server EncryptXor] Error: " << e.what() << std::endl;
        throw;
    }
}

const char* EncryptionUtils::decryptXor(const char* input, const char* key) {
    try {
        // Calculate input length
        size_t input_len = 0;
        for (input_len = 0; input[input_len] != '\0'; input_len++);

        // Calculate key length
        size_t key_len = 0;
        for (key_len = 0; key[key_len] != '\0'; key_len++);

        // Decode from base64
        size_t decoded_len = 0;
        unsigned char* decoded_data = fromBase64(input, &decoded_len);

        if (!decoded_data) {
            throw std::runtime_error("Base64 decoding failed");
        }

        // Apply the same XOR formula but in reverse
        char* decrypted = new char[decoded_len + 1];

        for (size_t i = 0; i < decoded_len; i++) {
            // Exact same formula as encryption
            decrypted[i] = decoded_data[i] ^ key[i % key_len] ^ ((i * 13) & 0xFF);
        }

        decrypted[decoded_len] = '\0';
        delete[] decoded_data;

        // Store in thread-safe buffer
        const char* result = ThreadSafeBuffer::allocate(decoded_len + 1);
        memcpy((void*)result, decrypted, decoded_len + 1);
        delete[] decrypted;

        return result;
    }
    catch (const std::exception& e) {
        std::cerr << "[Server DecryptXor] Error: " << e.what() << std::endl;
        return nullptr;
    }
}