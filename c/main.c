#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <ctype.h>
#include <time.h>

#define CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define KEY_LENGTH 16 // Keys have 16 bytes

// Check if the text is printable or new line
int is_valid_plaintext(const unsigned char *plaintext, int len) {
    for (int i = 0; i < len; i++) {
        if (!isprint(plaintext[i]) && !isspace(plaintext[i]) && plaintext[i] != '\n') {
            return 0;
        }
    }
    return 1;
}

// Just check the first 16 bytes first
int decrypt_aes_ecb_partial(const unsigned char *key, const unsigned char *ciphertext, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return is_valid_plaintext(plaintext, len);
}



int decrypt_aes_ecb(const unsigned char *key, const unsigned char *ciphertext, int cipher_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new");
        exit(EXIT_FAILURE);
    }

    int len, plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        perror("EVP_DecryptInit_ex");
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int brute_force_aes_ecb(const char *cipher_hex) {
    int cipher_len = strlen(cipher_hex) / 2;
    int keys_tested = 0;
    unsigned char *ciphertext = malloc(cipher_len);
    unsigned char *plaintext = malloc(cipher_len + 1);
    unsigned char key[KEY_LENGTH] = {"Security00"}; // Change if want

    for (int i = 0; i < cipher_len; i++) {
        sscanf(cipher_hex + (i * 2), "%2hhx", &ciphertext[i]);
    }

    int charset_len = strlen(CHARSET);

    for (int i = 0; i < charset_len; i++) {
        for (int j = 0; j < charset_len; j++) {
            for (int k = 0; k < charset_len; k++) {
                for (int l = 0; l < charset_len; l++) {
                    for (int m = 0; m < charset_len; m++) {
                        for (int n = 0; n < charset_len; n++) {
                            key[KEY_LENGTH - 6] = CHARSET[i];
                            key[KEY_LENGTH - 5] = CHARSET[i];
                            key[KEY_LENGTH - 4] = CHARSET[j];
                            key[KEY_LENGTH - 3] = CHARSET[k];
                            key[KEY_LENGTH - 2] = CHARSET[l];
                            key[KEY_LENGTH - 1] = CHARSET[m];

                            keys_tested ++;

                            // Attempt decryption.
                            if(decrypt_aes_ecb_partial(key, ciphertext, plaintext)) {
                                int plaintext_len = decrypt_aes_ecb(key, ciphertext, cipher_len, plaintext);
                                if (plaintext_len > 0 && is_valid_plaintext(plaintext, plaintext_len)) {
                                    plaintext[plaintext_len] = '\0'; // Null-terminate plaintext
                                    printf("Key found: %s\n",key);
                                    printf("Decrypted text: %s\n", plaintext);
                                    free(ciphertext);
                                    free(plaintext);
                                    return keys_tested;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    printf("No valid key found!\n");
    free(ciphertext);
    free(plaintext);
    return keys_tested;
}

int main() {
    // Example cipher text in hex (replace with your actual cipher text).
  const char *cipher_text_hex = "4cc3b372c3a96d20697073c3bb6d2064c3b36c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742e20536564206d6175726973206d617373612c2070756c76696e617220657420616363756d73616e20636f6e64696d656e74756d2c2072757472756d206672696e67696c6c61206a7573746f2e20496e74656765722068656e647265726974206c656f20766f6c7574706174206d616c6573756164612076656e656e617469732e20566976616d757320657569736d6f64207669766572726120657261742c206575206665726d656e74756d206e6973692076697665727261206e65632e20517569737175652070686172657472612076656e656e61746973206c696265726f2c206964206d6f6c6c6973206e6571756520636f6e73656374657475722061742e204d61757269732076656e656e61746973206c6f72656d2061742064696374756d20736f64616c65732e204e616d20736564206e697369206575206d65747573206d6178696d75732070686172657472612076697461652074696e636964756e742072697375732e204e756c6c616d2075726e61207175616d2c207361676974746973206567657420636f6e6775652061742c206c7563747573206e6563206c6f72656d2e20496e74656765722068656e64726572697420696d706572646965742061756775652061632073656d7065722e20566573746962756c756d20766172697573206665726d656e74756d20656c656966656e642e20447569732076697461652074656c6c75732070686172657472612c206c7563747573206c696265726f2076656c2c206c756374757320697073756d2e204d6f7262692074656d706f72206f726e617265206e69626820696e20766976657272612e2044756973206d6f6c65737469652064617069627573206c696265726f2076656c20636f6e7365717561742e20446f6e6563207669746165206d616c657375616461206d61676e612e2050656c6c656e746573717565206861626974616e74206d6f726269207472697374697175652073656e6563747573206574206e65747573206574206d616c6573756164612066616d65732061632074757270697320656765737461732e204e756c6c616d207072657469756d2074757270697320657520636f6d6d6f646f2066617563696275732e20496e2066696e696275732c206572617420717569732072686f6e63757320736f64616c65732c2073617069656e20656e696d20706f7375657265206e657175652c20696420656765737461732076656c69742073656d206e6563206e756c6c612e2050656c6c656e74657371756520697073756d206d61676e612c2076656e656e6174697320696420656c656966656e6420612c20616363756d73616e206575206c6f72656d2e20416c697175616d206572617420766f6c75747061742e2053656420757420756c74726963696573206e657175652c20612065676573746173206d692e2050656c6c656e7465737175652070656c6c656e7465737175652c206a7573746f2069642076617269757320766573746962756c756d2c20656e696d20726973757320657569736d6f642061756775652c206574207375736369706974206e6571756520656c69742065676574206d61676e612e204e616d2074656d706f722073697420616d6574206c6163757320696420766f6c75747061742e20446f6e65632065676573746173206661756369627573206d61757269732e20496e206d6f6c65737469652074696e636964756e74206d692e204d6175726973207363656c657269737175652c20746f72746f722076656c2070686172657472612073616769747469732c2074656c6c75732076656c697420706861726574726120657261742c206120756c747269636965732065782072697375732074656d706f722066656c69732e204372617320636f6e64696d656e74756d206163206572617420657520636f6e76616c6c69732e204e756c6c612073617069656e20697073756d2c20756c6c616d636f7270657220696e20696e74657264756d2061742c20636f6e7365637465747572207669746165207175616d2e2050686173656c6c7573206c6967756c61206d692c207363656c657269737175652073697420616d6574206c61637573206e65632c206c6163696e692e2e0a0ac38a7869746f206e6120666f72c3a7612062727574613a3a205a4931344443";

    clock_t start = clock();
    int keys_tested = brute_force_aes_ecb(cipher_text_hex);
    clock_t end = clock();

    double elapsed_time = (double)(end - start) / CLOCKS_PER_SEC;
    double keys_per_second = keys_tested/ elapsed_time;
    printf("Tested %d keys in %.2f seconds (%.2f keys/second)\n", keys_tested, elapsed_time, keys_per_second);

    return 0;
}
