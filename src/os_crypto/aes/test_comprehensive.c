/* Comprehensive test program for AES encryption/decryption */
#include <stdio.h>
#include <string.h>
#include "aes_op.h"

static int test_count = 0;
static int test_passed = 0;

void test_aes_roundtrip(const char *test_name, const char *key, const char *plaintext, size_t len) {
    char encrypted[1024];
    char decrypted[1024];
    size_t padded_len;
    int i;
    
    test_count++;
    printf("\nTest %d: %s\n", test_count, test_name);
    printf("  Input: \"%s\" (%zu bytes)\n", plaintext, len);
    
    /* Pad to 16-byte boundary */
    padded_len = ((len / 16) + 1) * 16;
    
    /* Prepare padded plaintext */
    memset(encrypted, 0, sizeof(encrypted));
    memcpy(encrypted, plaintext, len);
    
    /* Encrypt */
    if (!OS_AES_Str(encrypted, decrypted, key, padded_len, OS_ENCRYPT)) {
        printf("  ✗ FAILED: Encryption failed\n");
        return;
    }
    
    printf("  Encrypted: ");
    for (i = 0; i < 32 && i < (int)padded_len; i++) {
        printf("%02x", (unsigned char)decrypted[i]);
    }
    printf("...\n");
    
    /* Copy encrypted data back */
    memcpy(encrypted, decrypted, padded_len);
    memset(decrypted, 0, sizeof(decrypted));
    
    /* Decrypt */
    if (!OS_AES_Str(encrypted, decrypted, key, padded_len, OS_DECRYPT)) {
        printf("  ✗ FAILED: Decryption failed\n");
        return;
    }
    
    /* Verify */
    if (memcmp(plaintext, decrypted, len) == 0) {
        printf("  ✓ PASSED: Decrypted matches original\n");
        test_passed++;
    } else {
        printf("  ✗ FAILED: Decrypted does not match\n");
        printf("  Expected: \"%s\"\n", plaintext);
        printf("  Got:      \"%s\"\n", decrypted);
    }
}

int main(void) {
    const char *key1 = "test_key_12345";
    const char *key2 = "different_key_67890";
    
    printf("==============================================\n");
    printf("AES-256-CBC Comprehensive Test Suite\n");
    printf("==============================================\n");
    
    /* Test 1: Short message */
    test_aes_roundtrip("Short message", key1, "Hello!", 6);
    
    /* Test 2: Exactly 16 bytes (one block) */
    test_aes_roundtrip("One block (16 bytes)", key1, "1234567890123456", 16);
    
    /* Test 3: Multiple blocks */
    test_aes_roundtrip("Multiple blocks", key1, 
                       "This is a longer message that spans multiple AES blocks.", 57);
    
    /* Test 4: Different key */
    test_aes_roundtrip("Different key", key2,
                       "Same message, different key", 27);
    
    /* Test 5: Binary data (with nulls) */
    char binary[32];
    memset(binary, 0, sizeof(binary));
    binary[0] = 'A';
    binary[5] = 'B';
    binary[10] = 'C';
    binary[15] = 'D';
    test_aes_roundtrip("Binary data with nulls", key1, binary, 16);
    
    /* Test 6: Large message */
    char large[256];
    memset(large, 'X', sizeof(large));
    large[255] = '\0';
    test_aes_roundtrip("Large message (255 bytes)", key1, large, 255);
    
    /* Test 7: Empty-ish (just padding) */
    test_aes_roundtrip("Minimal message", key1, "A", 1);
    
    printf("\n==============================================\n");
    printf("Results: %d/%d tests passed\n", test_passed, test_count);
    printf("==============================================\n");
    
    return (test_passed == test_count) ? 0 : 1;
}
