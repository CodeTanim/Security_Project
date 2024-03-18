#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/err.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE | MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
#define MAC_LEN 32
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY *K, unsigned char *entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	unsigned char key[64];

	if (entropy) {
		HMAC(EVP_sha512(), KDF_KEY, 2*HM_LEN, entropy, entLen, key, NULL);
	} else {
		randBytes(key, 64);
	}
	memcpy(K->hmacKey, key, 32);
	memcpy(K->aesKey, key+32, 32);

	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}


size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */

	if (!IV) {
		randBytes(IV, 16);
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey,IV)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	int nWritten = 0;
	unsigned char cipherText[len];
	if (1!=EVP_EncryptUpdate(ctx, cipherText, &nWritten, inBuf, len)) {

		ERR_print_errors_fp(stderr);
		return -1;
	}

	unsigned char IVCipherText[16+nWritten];
	memcpy(IVCipherText, IV, 16);
	memcpy(IVCipherText+16, cipherText, nWritten);

	unsigned char computedMac[HM_LEN];
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, IVCipherText, nWritten+16, computedMac, NULL);
	
	memcpy(outBuf, IVCipherText, 16+nWritten);
	memcpy(outBuf + nWritten + 16, computedMac, HM_LEN);

	EVP_CIPHER_CTX_free(ctx);
	
	return nWritten + 16 + HM_LEN; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}

size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	return 0;
}
size_t ske_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   SKE_KEY *K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	unsigned char IV[16];
	unsigned char IVCipherText[len-HM_LEN];
	unsigned char receivedMac[HM_LEN];

  memcpy(IV, inBuf, 16);
	memcpy(IVCipherText, inBuf, len-HM_LEN);
	memcpy(receivedMac, inBuf+len-HM_LEN, HM_LEN);

	unsigned char computedMac[HM_LEN];
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, IVCipherText, len-HM_LEN, computedMac, NULL);

	if (memcmp(receivedMac, computedMac, HM_LEN) != 0) {
		return -1;
	}
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1 != EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(), 0, K->aesKey, IV)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	int nWritten = 0;
	if (1 != EVP_DecryptUpdate(ctx, outBuf, &nWritten, inBuf+16, len-16-HM_LEN)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
		
	EVP_CIPHER_CTX_free(ctx);
	
	return nWritten;
}


size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	int fd_in, fd_out;
    struct stat sb;
    unsigned char *mapped, *decrypted_data;
    size_t decrypted_size;

    // Open the input file
    fd_in = open(fnin, O_RDONLY);
    if (fd_in == -1) {
        perror("Error opening input file");
        return -1;
    }

    // Get the size of the file
    if (fstat(fd_in, &sb) == -1) {
        perror("Error getting file size");
        close(fd_in);
        return -1;
    }

    // Memory-map the input file
    mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd_in, 0);
    if (mapped == MAP_FAILED) {
        perror("Error memory-mapping the input file");
        close(fd_in);
        return -1;
    }

    // Assume decrypted_data is allocated by ske_decrypt or it directly modifies the 'mapped' buffer.
    // Also assume ske_decrypt adjusts the file size for any potential size changes due to padding, etc.
    decrypted_size = ske_decrypt(mapped + offset_in, sb.st_size - offset_in, decrypted_size, K);
    if (decrypted_size == (size_t)-1) {
        munmap(mapped, sb.st_size);
        close(fd_in);
        perror("Decryption failed");
        return -1;
    }

    // Open or create the output file
    fd_out = open(fnout, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd_out == -1) {
        perror("Error opening output file");
        munmap(mapped, sb.st_size);
        close(fd_in);
        return -1;
    }

    // Write the decrypted data to the output file
    if (write(fd_out, mapped + offset_in, decrypted_size) != decrypted_size) {
        perror("Error writing decrypted data to output file");
        munmap(mapped, sb.st_size);
        close(fd_in);
        close(fd_out);
        return -1;
    }

    // Clean up
    munmap(mapped, sb.st_size);
    close(fd_in);
    close(fd_out);

    return decrypted_size;
}