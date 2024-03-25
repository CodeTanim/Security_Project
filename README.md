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


```./kem-enc -b 2048 -g testkey
```







### Notes
- When `test.sh` runs, it stores the test result's output in “output” but shows that it failed for ske-on-files. However, if we run `./ske-on-files-test` separately it works. 
- Our Makefile needed to be adjusted to contain the paths to openssl and GNP installations to satisfy our ARM based computers. 
