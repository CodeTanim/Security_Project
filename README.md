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

Despite the file testkey.pub appearing correctly populated, the rsa_readPublic function was reading n and e as 0, suggesting an issue with extracting the n and e values. To diagnose, we examined how the file size was interpreted within the function, finding it interpreted as excessively large (e.g., 281474976710656 and 10610458615532067060 bytes).


Given the unusually large byte interpretations, we hypothesized that the ARM-based architecture might be misreading the file, potentially due to endianness issues. This led to a reevaluation of the zFromFile function, which is responsible for extracting the RSA key from the .pub file.

### Notes
- When `test.sh` runs, it stores the test result's output in “output” but shows that it failed for ske-on-files. However, if we run `./ske-on-files-test` separately it works. 
- Our Makefile needed to be adjusted to contain the paths to openssl and GNP installations to satisfy our ARM based computers. 
