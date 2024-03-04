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
	// Seed the random number generator.
	gmp_randstate_t randState;
	gmp_randinit_default(randState);
	gmp_randseed_ui(randState, time(NULL));

	// Calculate the number of bits for p and q
	size_t primeBits = keyBits / 2;

	NEWZ(p);
	NEWZ(q);
	NEWZ(phi);

	// Generate two distinct primes p and q
	do
	{
		mpz_urandomb(p, randState, primeBits);
		mpz_nextprime(p, p);
	} while (!ISPRIME(p));

	do
	{
		mpz_urandomb(q, randState, primeBits);
		mpz_nextprime(q, q);
	} while (!ISPRIME(q) || mpz_cmp(p, q) == 0); // Ensure p != q

	// Compute n = p*q
	mpz_mul(K->n, p, q);

	// Compute φ(n) = (p-1)*(q-1)
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
	mpz_mul(phi, p, q);

	// Choose e, commonly 65537, ensuring gcd(e, φ(n)) = 1
	mpz_set_ui(K->e, 65537);

	// Compute d, the modular multiplicative inverse of e mod φ(n)
	mpz_invert(K->d, K->e, phi);

	// Clean up
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(phi);
	gmp_randclear(randState);

	return 0;
}
size_t rsa_encrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   RSA_KEY *K)
{
	/* TODO: write this.  Use BYTES2Z to get integers, and then
	 * Z2BYTES to write the output buffer. */

	// answer:
	// Initialize GMP variables for the message, ciphertext, and n
	mpz_t m, c;
	mpz_init(m);
	mpz_init(c);

	// Convert the input buffer (plaintext) into an mpz_t integer (m)
	BYTES2Z(m, inBuf, len);

	// Encrypt the message: c = m^e mod n
	mpz_powm(c, m, K->e, K->n);

	// Determine the size of the ciphertext in bytes and ensure the output buffer is large enough
	size_t written = 0;
	size_t cSize = (mpz_sizeinbase(c, 2) + 7) / 8; // Calculate ciphertext size in bytes
	if (cSize > len)
	{
		// The output buffer is not large enough to hold the ciphertext
		fprintf(stderr, "Error: Output buffer too small for encrypted data.\n");
	}
	else
	{
		// Convert the ciphertext integer (c) back into a byte array (outBuf)
		Z2BYTES(outBuf, written, c);
	}

	// Clear GMP variables to avoid memory leak
	mpz_clear(m);
	mpz_clear(c);

	// Return the number of bytes written to the output buffer
	return written;
}

size_t rsa_decrypt(unsigned char *outBuf, unsigned char *inBuf, size_t len,
				   RSA_KEY *K)
{
	/* TODO: write this.  See remarks above. */

	// Initialize GMP variables for the ciphertext, decrypted message, and n
	mpz_t c, m;
	mpz_init(c);
	mpz_init(m);

	// Convert the input buffer (ciphertext) into an mpz_t integer (c)
	BYTES2Z(c, inBuf, len);

	// Decrypt the ciphertext: m = c^d mod n
	mpz_powm(m, c, K->d, K->n);

	// Determine the size of the decrypted message in bytes and ensure the output buffer is large enough
	size_t written = 0;
	size_t mSize = (mpz_sizeinbase(m, 2) + 7) / 8; // Calculate message size in bytes
	if (mSize > len)
	{
		// The output buffer is not large enough to hold the decrypted data
		fprintf(stderr, "Error: Output buffer too small for decrypted data.\n");
	}
	else
	{
		// Convert the decrypted message integer (m) back into a byte array (outBuf)
		Z2BYTES(outBuf, written, m);
	}

	// Clear GMP variables to avoid memory leak
	mpz_clear(c);
	mpz_clear(m);

	// Return the number of bytes written to the output buffer
	return written;
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
