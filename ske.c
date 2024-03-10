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
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
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

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	if (entropy) {
		return HMAC(EVP_sha512(), KDF_KEY, HM_LEN, entropy, entLen, K->hmacKey, NULL);
	} else {
		unsigned char randomKey[32];
		randBytes(randomKey, 32);
		memcpy(K->hmacKey, randomKey, 32);
	}
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
		IV = malloc(16);
		randBytes(IV, 16);
	}
	memcpy(outBuf, IV, 16);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->hmacKey,IV)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	int nWritten;
	if (1!=EVP_EncryptUpdate(ctx, outBuf + 16, &nWritten, inBuf, len)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	unsigned char computed_mac[HM_LEN];
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, outBuf, len+32, computed_mac, NULL);
	memcpy(outBuf + len + 16, computed_mac, HM_LEN);

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
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */

	unsigned char received_mac[HM_LEN];
  memcpy(received_mac, inBuf+len-HM_LEN, HM_LEN);

	unsigned char computed_mac[HM_LEN];
	HMAC(EVP_sha256(), K->hmacKey, HM_LEN, inBuf+16, len-32, computed_mac, NULL);

	// printf("received mac: ");
	// for (size_t i = 0; i < HM_LEN; i++)
	// {
	// 		printf("%02x", received_mac[i]);
	// }

	// printf("computed mac: ");
	// for (size_t i = 0; i < HM_LEN; i++)
	// {
	// 		printf("%02x", computed_mac[i]);
	// }

	if (memcmp(received_mac, computed_mac, HM_LEN) != 0) {
		return -1;
	}
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	unsigned char IV[16];
  memcpy(IV, inBuf, 16);
	if (1 != EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(), 0, K->hmacKey, IV)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	int nWritten = 0;
	if (1 != EVP_DecryptUpdate(ctx, outBuf, &nWritten, inBuf+16, len-16)) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
		
	EVP_CIPHER_CTX_free(ctx);
	
	return nWritten;
}


size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	return -1;
}