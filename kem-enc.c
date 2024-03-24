/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */


int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	 //Generate a random key for symmetric encryption (x).
    size_t x_len = rsa_numBytesN(K); // Length based on RSA modulus size
    unsigned char* x = malloc(x_len);
    if (!x) {
        return -1;
    }
    if (RAND_bytes(x, x_len) != 1) {
        // Handle OpenSSL random bytes generation error
        free(x);
        fprintf(stderr, "Random bytes generation failed.\n");
        return -1;
    }

    //Encrypt x using RSA (Epk(x)).
    unsigned char* Epk_x = malloc(x_len); // Buffer for RSA encryption
    if (!Epk_x) {
        free(x);
        return -1;
    }
    size_t Epk_x_len = rsa_encrypt(Epk_x, x, x_len, K);

    //Compute the hash of x (H(x)).
    unsigned char H_x[SHA256_DIGEST_LENGTH];
    SHA256(x, x_len, H_x);

    //Concatenate Epk(x) and H(x) for the encapsulation.
    unsigned char* encapsulation = malloc(Epk_x_len + SHA256_DIGEST_LENGTH);
    if (!encapsulation) {
        perror("malloc");
        free(x);
        free(Epk_x);
        return -1;
    }
    memcpy(encapsulation, Epk_x, Epk_x_len);
    memcpy(encapsulation + Epk_x_len, H_x, SHA256_DIGEST_LENGTH);

    //Use ske_keyGen to derive the symmetric key from x via KDF.
    SKE_KEY SK;
    ske_keyGen(&SK, x, x_len);

    // Read input file into a buffer
    FILE* inFile = fopen(fnIn, "rb");
    if (!inFile) {
        free(x);
        free(Epk_x);
        free(encapsulation);
        return -1;
    }
    fseek(inFile, 0L, SEEK_END);
    size_t fSize = ftell(inFile);
    fseek(inFile, 0L, SEEK_SET);
    unsigned char* fData = malloc(fSize);
    fread(fData, 1, fSize, inFile);
    fclose(inFile);

    // Allocate output buffer for SKE encryption
    size_t ske_out_len = ske_getOutputLen(fSize);
    unsigned char* ske_ct = malloc(ske_out_len);
    unsigned char IV[16]; // IV for AES CTR mode
    RAND_bytes(IV, sizeof(IV)); // Generate a random IV
    ske_encrypt(ske_ct, fData, fSize, &SK, IV);

    //Concatenate the encapsulation and the SKE ciphertext.
    unsigned char* final_ct = malloc(Epk_x_len + SHA256_DIGEST_LENGTH + ske_out_len);
    if (!final_ct) {
        free(x);
        free(Epk_x);
        free(encapsulation);
        free(fData);
        free(ske_ct);
        return -1;
    }
    memcpy(final_ct, encapsulation, Epk_x_len + SHA256_DIGEST_LENGTH);
    memcpy(final_ct + Epk_x_len + SHA256_DIGEST_LENGTH, ske_ct, ske_out_len);

    // Write the result to the output file.
    FILE* outFile = fopen(fnOut, "wb");
    if (!outFile) {
        free(x);
        free(Epk_x);
        free(encapsulation);
        free(fData);
        free(ske_ct);
        free(final_ct);
        return -1;
    }
    fwrite(final_ct, 1, Epk_x_len + SHA256_DIGEST_LENGTH + ske_out_len, outFile);
    fclose(outFile);

    // Free all allocated resources
    free(x);
    free(Epk_x);
    free(encapsulation);
    free(fData);
    free(ske_ct);
    free(final_ct);

    return 0; 
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

    FILE* inFile = fopen(fnIn, "rb");
    if (!inFile) {
        perror("fopen");
        return -1;
    }

    // Read the RSA-KEM part from the input ciphertext.
    size_t rsa_cipher_len = rsa_numBytesN(K);  
    unsigned char* rsa_cipher = malloc(rsa_cipher_len);
    if (!rsa_cipher) {
        perror("malloc");
        fclose(inFile);
        return -1;
    }
    fread(rsa_cipher, 1, rsa_cipher_len, inFile);

    // Split it into C0 (RSA part) and C1 (hash part).
    unsigned char* hash_part = malloc(SHA256_DIGEST_LENGTH);
    if (!hash_part) {
        perror("malloc");
        free(rsa_cipher);
        fclose(inFile);
        return -1;
    }
    fread(hash_part, 1, SHA256_DIGEST_LENGTH, inFile);

    // Decrypt C0 using RSA to get x (Dpk(C0)).
    unsigned char* decrypted_x = malloc(rsa_cipher_len);
    if (!decrypted_x) {
        perror("malloc");
        free(rsa_cipher);
        free(hash_part);
        fclose(inFile);
        return -1;
    }
    size_t decrypted_x_len = rsa_decrypt(decrypted_x, rsa_cipher, rsa_cipher_len, K);

    // Hash x and compare it with C1.
    unsigned char computed_hash[SHA256_DIGEST_LENGTH];
    SHA256(decrypted_x, decrypted_x_len, computed_hash);

    if (memcmp(computed_hash, hash_part, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "Hash does not match. Decapsulation failed.\n");
        free(rsa_cipher);
        free(hash_part);
        free(decrypted_x);
        fclose(inFile);
        return -1;
    }

    // Use ske_keyGen to derive the symmetric key from x via KDF.
    SKE_KEY derived_SK;
    ske_keyGen(&derived_SK, decrypted_x, decrypted_x_len);

    // Determine the size of the remaining ciphertext
    fseek(inFile, 0L, SEEK_END);
    size_t total_ct_size = ftell(inFile);
    size_t remaining_ct_size = total_ct_size - rsa_cipher_len - SHA256_DIGEST_LENGTH;
    fseek(inFile, rsa_cipher_len + SHA256_DIGEST_LENGTH, SEEK_SET);

    // Decrypt the remaining part of the ciphertext using ske_decrypt.
    unsigned char* ciphertext = malloc(remaining_ct_size);
    if (!ciphertext) {
        perror("malloc");
        free(rsa_cipher);
        free(hash_part);
        free(decrypted_x);
        fclose(inFile);
        return -1;
    }
    fread(ciphertext, 1, remaining_ct_size, inFile);
    fclose(inFile);  

    unsigned char* plaintext = malloc(remaining_ct_size);
    if (!plaintext) {
        perror("malloc");
        free(rsa_cipher);
        free(hash_part);
        free(decrypted_x);
        free(ciphertext);
        return -1;
    }
    size_t plaintext_len = ske_decrypt(plaintext, ciphertext, remaining_ct_size, &derived_SK);
    if (plaintext_len == -1) {
        fprintf(stderr, "Decryption failed.\n");
        free(rsa_cipher);
        free(hash_part);
        free(decrypted_x);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // Write the plaintext to the output file.
    FILE* outFile = fopen(fnOut, "wb");
    if (!outFile) {
        perror("fopen");
        free(rsa_cipher);
        free(hash_part);
        free(decrypted_x);
        free(ciphertext);
        free(plaintext);
        return -1;
    }
    fwrite(plaintext, 1, plaintext_len, outFile);
    fclose(outFile);

    free(rsa_cipher);
    free(hash_part);
    free(decrypted_x);
    free(ciphertext);
    free(plaintext);

    return 0; 
}

int generate(char* fnOut, size_t nBits){
	RSA_KEY K;

	//create new file with .pub extension
	char* fPub = malloc(strlen(fnOut) + 5);
	strcpy(fPub, fnOut);
	strcat(fPub, ".pub");

	FILE* outPrivate = fopen(fnOut, "w");
	FILE* outPublic = fopen(fPub, "w");

	rsa_keyGen(nBits, &K);
	rsa_writePrivate(outPrivate, &K);
	rsa_writePublic(outPublic, &K);

	fclose(outPrivate);
	fclose(outPublic);
	rsa_shredKey(&K);
	free(fPub);
	return 0;
}

int encrypt_helper(char* fnOut, char* fnIn, char* fnKey){
	FILE* keyFile = fopen(fnKey, "r");
	printf("Key file: %s\n", fnKey);
	if(keyFile == NULL){
		printf("Key file does not exist\n");
		return -1;
	}

	RSA_KEY K;
	rsa_readPublic(keyFile, &K);
	kem_encrypt(fnOut, fnIn, &K);
	rsa_shredKey(&K);
	fclose(keyFile);
	return 0;
}

int decrypt_helper(char* fnOut, char* fnIn, char* fnKey){
	FILE* privateKey = fopen(fnKey, "r");
	printf("Key file: %s\n", fnKey);
	if(privateKey == NULL){
		printf("Key file does not exist\n");
		return -1;
	}

	RSA_KEY K;
	rsa_readPrivate(privateKey, &K);
	fclose(privateKey);
	kem_decrypt(fnOut, fnIn, &K);
	rsa_shredKey(&K);
	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */

    RSA_KEY K;
    int result = -1;

    switch (mode) {
        case GEN: {
            // Generate keys
            result = rsa_keyGen(nBits, &K);
            if (result != 0) {
                fprintf(stderr, "Key generation failed.\n");
                break;
            }
            // Write keys to files
            char pubKeyFilename[FNLEN+4];
            snprintf(pubKeyFilename, sizeof(pubKeyFilename), "%s.pub", fnOut);
            FILE* privKeyFile = fopen(fnOut, "wb");
            FILE* pubKeyFile = fopen(pubKeyFilename, "wb");
            if (privKeyFile == NULL || pubKeyFile == NULL) {
                result = 1;
            } else {
                rsa_writePrivate(privKeyFile, &K);
                rsa_writePublic(pubKeyFile, &K);
                fclose(privKeyFile);
                fclose(pubKeyFile);
                result = 0;
            }
            rsa_shredKey(&K);
            break;
        }
        case ENC: {
            // Encrypt with public key
            rsa_readPublic(fnKey, &K);
            result = kem_encrypt(fnOut, fnIn, &K);
            rsa_shredKey(&K);
            break;
        }
        case DEC: {
            // Decrypt with private key
            rsa_readPrivate(fnKey, &K);
            result = kem_decrypt(fnOut, fnIn, &K);
            rsa_shredKey(&K);
            break;
        }
        default:
            fprintf(stderr, "Invalid mode.\n");
            result = 1;
            break;
    }

    return result;
}