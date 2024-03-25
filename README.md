# CSC 380 - Project 1
### Team Members + Responsibilities
Tanim Islam - RSA Component <br/>
Abdul Andha - Ske on buffers <br/>
Johan Delao - Ske on files <br/>
Mansij Mishra - Kem-enc <br/>

## Debugging Kem-enc.c

During the development and testing of kem-enc.c, we encountered issues related to key generation and encryption, particularly with the .pub file. Here's a summary of our debugging process:

Key Generation
Running the command:


```bash
./kem-enc -b 2048 -g testkey
```

correctly generates the RSA key pair, writing the private key to testkey and the public key to testkey.pub. To verify the correct writing of the RSA key to testkey.pub, we inserted print statements in the rsa_readpublic and rsa_writepublic functions. The output confirmed the key was correctly generated:

```bash
When writing to public we have:
n:9daa79c950c350dcf0a1f041e59f3766164598da5f5c798d156bbe010695d2cecf220b8f44e864015af211be575f7511c9e72b177efc3294a19423fb92446d4f8aed6b8f3ad94933a4ab0cc45761bb416810623e565db7952968005553a6f86d10b5a7fc2b0f2215deeaec80e63d31195d676627db38db7b7723c5fb9c8ab8f86647b4b3c85fc613b72dccc04c0f789fd4b38a0b4680afb80bddc39edaffa8883ced4bfa9b2ef3c35c35050eb41391c989e2f1dd9b927d0900b6b6ea63b0dc28d272e37edb527985a7c750b42dba473f5dee841f0424eac553bab0ada20bc85d47cc5d5224bb0e4d8fd23684ceec11da6a606d497836c68de1d6e222d15c4223
e: 10001
```


To ensure testkey.pub wasn't empty and correctly stored the RSA key, we used:

bash
```
xxd testkey.pub
```
When doing encryption by running the command:

bash 
```
./kem-enc -e -i file -o ct.txt -k testkey.pub
```

We did further checking of the testkey.pub file content, and check the values of n and e after rsa_readpublic had been called, and found the following output and error (note that the output of the file has each byte printed in hexadecimal format:

bash
```
File content:
00 01 00 00 00 00 00 00 f3 38 74 17 f6 db 64 90 
b3 e0 a3 41 d2 58 42 ca 00 c8 4e 89 08 c9 7d bb 
38 79 f3 2a e9 b1 4e 2c 75 69 1c af 1c d0 08 39 
df ca 7b 80 4a cf aa 3f 57 ca db 8c df e8 74 38 
2f c5 d0 6f 2f a2 2e be 4a d4 1f 8f 8a 73 e6 db 
da c0 5a 2b 1b aa 44 76 70 da 76 a1 31 f4 91 e8 
ca 45 c8 84 73 cc a7 cb 6b d1 d0 0d e6 36 7f 37 
18 14 a2 18 f9 8e a1 cc 92 6f 3a ed 92 21 d4 9c 
4c c3 3a 7e 38 fc c0 50 7a ca e8 21 b2 1b f7 3e 
e1 db 8c 62 67 e5 1c 3a a5 4d 96 2e e1 0f dd 01 
d8 74 2f a3 1c 9f e3 92 e0 4a 96 5c f6 42 a8 08 
47 a7 ce 67 6a 77 fd 29 f7 88 fa 69 77 87 24 df 
35 c9 45 06 0c 03 8b d8 ca e3 85 d0 26 6a 6d 0a 
ed 1d 17 4f 35 89 14 8a ad c4 03 4b 73 64 bb 78 
8f da ad e7 c2 cd 06 49 e1 21 17 dc 35 c2 d0 c1 
3a d2 ab fb b9 98 55 58 dd 01 24 22 0c a0 73 63 
0f 4c fb 1f eb a5 43 b9 03 00 00 00 00 00 00 00 
01 00 01 
when read from public we have:
n:0
e:0
kem-enc(88797,0x1e6a3c140) malloc: Incorrect checksum for freed object 0x12ee069f8: probably modified after being freed.
Corrupt value: 0x2c4eb1e92af37938
kem-enc(88797,0x1e6a3c140) malloc: *** set a breakpoint in malloc_error_break to debug
[1]    88797 abort      ./kem-enc -e -i file -o ct.txt -k testkey.pub
```




Despite the file testkey.pub appearing correctly populated, the rsa_readPublic function was reading n and e as 0, suggesting an issue with extracting the n and e values. To diagnose, we examined how the file size was interpreted within the function, finding it interpreted as excessively large (e.g., 281474976710656 and 10610458615532067060 bytes).


Given the unusually large byte interpretations, we hypothesized that the ARM-based architecture might be misreading the file, potentially due to endianness issues. This led to a reevaluation of the zFromFile function, which is responsible for extracting the RSA key from the .pub file.

### Notes
- When `test.sh` runs, it stores the test result's output in “output” but shows that it failed for ske-on-files. However, if we run `./ske-on-files-test` separately it works. 
- Our Makefile needed to be adjusted to contain the paths to openssl and GNP installations to satisfy our ARM based computers. 
