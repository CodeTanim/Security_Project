#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"
#include <time.h>

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x, 10)
#define NEWZ(x) \
	mpz_t x;    \
	mpz_init(x)
#define BYTES2Z(x, buf, len) mpz_import(x, len, -1, 1, 0, 0, buf)
#define Z2BYTES(buf, len, x) mpz_export(buf, &len, -1, 1, 0, 0, x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE *f, mpz_t x)
{
	size_t i, len = mpz_size(x) * sizeof(mp_limb_t);
	/* NOTE: len may overestimate the number of bytes actually required. */
	unsigned char *buf = malloc(len);
	Z2BYTES(buf, len, x);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++)
	{
		unsigned char b = (len >> 8 * i) % 256;
		fwrite(&b, 1, 1, f);
	}
	fwrite(buf, 1, len, f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf, 0, len);
	free(buf);
	return 0;
}
int zFromFile(FILE *f, mpz_t x)
{
	size_t i, len = 0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++)
	{
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b, 1, 1, f);
		len += (b << 8 * i);
	}
	unsigned char *buf = malloc(len);
	fread(buf, 1, len, f);
	BYTES2Z(x, buf, len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf, 0, len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY *K)
{
	rsa_initKey(K);
	/* TODO: write this.  Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

	// answer:
	size_t primeBytes = keyBits / 16;

	unsigned char *randomBytes = malloc(primeBytes); // allocate memory for prime bytes

	// Generate prime p and q

	NEWZ(p);

	int isPrime = 0;
	while (!isPrime)
	{
		// Generate random bytes
		randBytes(randomBytes, primeBytes);

		// Convert random bytes to mpz_t integer (p)
		BYTES2Z(p, randomBytes, primeBytes);

		mpz_setbit(p, keyBits / 2 - 1); // Ensure p is within the desired range

		// Test for primality
		isPrime = ISPRIME(p);
	}

	NEWZ(q);
	int isPrime2 = 0;

	while (!isPrime2)
	{

		// Generate random bytes
		randBytes(randomBytes, primeBytes);

		// Convert random bytes to mpz_t integer (p)
		BYTES2Z(q, randomBytes, primeBytes);

		mpz_setbit(q, keyBits / 2 - 1); // Ensure q is within the desired range

		// Test for primality
		isPrime2 = ISPRIME(q);
	}

	// Calculate  n = p*q and phi = (p-1)(q-1)

	NEWZ(phi);
	mpz_mul(K->n, p, q);
	mpz_sub_ui(p, p, 1); // p = p-1
	mpz_sub_ui(q, q, 1); // q = q-1
	mpz_mul(phi, p, q);	 // phi = (p-1)*(q-1)

	// public exponent e
	mpz_set_ui(K->e, 65537);

	// compute private exponent d as the modular inverse of e mod phi

	mpz_invert(K->d, K->e, phi);

	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(phi);
	free(randomBytes);

	return 0;
}

size_t rsa_encrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   RSA_KEY *K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */

	// Initialize GMP variables for the message, ciphertext, and n

	NEWZ(m);		   // holds plaintext message converted to an int
	NEWZ(c);		   // will hold th ciphertext message after encryption
	size_t outLen = 0; // holds the length of the output buffer

	// 1. Convert the inBuf (message) of length len  into an mpz_t integer m
	BYTES2Z(m, inBuf, len);

	// 2. Do the RSA Encryption: c = (m^e) mod n.
	mpz_powm(c, m, K->e, K->n); // e is the public exponent, n is the modulus part of the public key.

	// 3. After encryption, Convert ciphertext integer c back into byte array outBuf. Outlen is updated to reflect the size of the output buffer.
	Z2BYTES(outBuf, outLen, c);

	mpz_clear(m);
	mpz_clear(c);

	return outLen; // length of ciphertext in bytes.
}

size_t rsa_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   RSA_KEY *K)
{
	/* TODO: write this.  See remarks above. */

	// Initialize GMP variables for the ciphertext, decrypted message, and n
	NEWZ(m);
	NEWZ(c);

	size_t outLen = 0; // holds the length of the output buffer.

	// convert input buffer (ciphertext) into an mpz_t integer c.
	BYTES2Z(c, inBuf, len);

	// RSA Decryption: m = (c^d) mod n
	mpz_powm(m, c, K->d, K->n);

	// Convert the decrypted message m back into byte array outBuf.
	Z2BYTES(outBuf, outLen, m); // outLen will now hold the length of the new output buffer.

	mpz_clear(m);
	mpz_clear(c);

	return outLen; // length of the decrypted message in bytes.
}

size_t rsa_numBytesN(RSA_KEY *K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY *K)
{
	mpz_init(K->d);
	mpz_set_ui(K->d, 0);
	mpz_init(K->e);
	mpz_set_ui(K->e, 0);
	mpz_init(K->p);
	mpz_set_ui(K->p, 0);
	mpz_init(K->q);
	mpz_set_ui(K->q, 0);
	mpz_init(K->n);
	mpz_set_ui(K->n, 0);
	return 0;
}

int rsa_writePublic(FILE *f, RSA_KEY *K)
{
	/* only write n,e */
	printf("When writing to public we have:\n");
	gmp_printf("n: %Zx\n", K->n); // Prints the hexadecimal representation of mpz_t n
	gmp_printf("e: %Zx\n", K->e); // Prints the hexadecimal representation of mpz_t e

	zToFile(f, K->n);
	zToFile(f, K->e);
	return 0;
}
int rsa_writePrivate(FILE *f, RSA_KEY *K)
{
	zToFile(f, K->n);
	zToFile(f, K->e);
	zToFile(f, K->p);
	zToFile(f, K->q);
	zToFile(f, K->d);
	return 0;
}
int rsa_readPublic(FILE *f, RSA_KEY *K)

{
	rsa_initKey(K); /* will set all unused members to 0 */

	zFromFile(f, K->n);
	zFromFile(f, K->e);

	// for debugging purposes:
	printf("when read from public we have:\n");
	gmp_printf("n:%Zx\n", K->n); // Prints the hexadecimal representation of mpz_t n
	gmp_printf("e:%Zx\n", K->e); // Prints the hexadecimal representation of mpz_t e

	return 0;
}
int rsa_readPrivate(FILE *f, RSA_KEY *K)
{
	rsa_initKey(K);
	zFromFile(f, K->n);
	zFromFile(f, K->e);
	zFromFile(f, K->p);
	zFromFile(f, K->q);
	zFromFile(f, K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY *K)
{
	/* clear memory for key. */
	mpz_t *L[5] = {&K->d, &K->e, &K->n, &K->p, &K->q};
	size_t i;
	for (i = 0; i < 5; i++)
	{
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs)
		{
			memset(mpz_limbs_write(*L[i], nLimbs), 0, nLimbs * sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
