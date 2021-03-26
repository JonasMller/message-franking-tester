# BachelorWorkspace

This project is for a bachelor thesis and implements different schemes of Message Franking and measures the time taken for encryping, decrypting and verification (called an iteration).
For deeper insights of the schemes refer to:

1. [Message Franking via Commited Authenticated Encryption](https://eprint.iacr.org/2017/664.pdf)

2. [Fast Message Franking:From Invisible Salamanders to Encryptment](https://cs.nyu.edu/~dodis/ps/encryptment.pdf)


## Dependencies

1. Project done on Ubuntu 20+

2. Compiler with c++ version 17+
    * build tool: make

3. [CryptoPP](https://cryptopp.com/) library (compiled)


## Commands

1. Usage of the scheme tests
    * Compilation: make
    * Cleanup: make clean
    * <a name="schemeExec"></a>Execution: 
    * ./main [path-to-the-config-file] \(Example: ./main Config/CEPConfig.xml\)

2. <a name="UnitTests"></a> Handling the UnitTests:
    * For a test of a Unit: make \[name\_of\_the\_testfile\]
    * For example: make TestSHA256
    * Cleanup of all tests: make cleanTests

3. If you want to make some changes in the CryptoPP library go to the source code
    * Make your changes and then do the following commands
    * g++ -DNDEBUG -g2 -O3 -fPIC -pthread -pipe -c sha.cpp
    * sudo make install


## Config file <a name="configFile"></a>

The config file has the \<Tester\> tag at the beginning. Everything inside this tag will be parsed.
The Tester class gets the number of iterations \<Iterations\> (one iteration is encryption, decryption and verification of a scheme),
the path to the logfile \<Logfile\>,
the header \<Header\> (this can be a string or a path to an image),
a message \<Message\> (can be a string or a path to an image too),
the key \<Key\> or \<Keysize\> (when giving it a keysize a random string will be generated, when using \<Key\> the string inside will be used) and
the nonce \<Nonce\> or \<Noncesize\> (when giving it a noncesize a random string will be generated, when using \<Nonce\> the string inside will be used).
Then the Tester also needs a scheme, which will be defined inside the \<Scheme\> tag. At the moment there are 4 different schemes: CEP \<CEP\>, CtE1 \<CtE1\>, CtE2 \<CtE2\> and the CETransformation \<CETransform\> with a HFC scheme \<HFC\>.
Every scheme needs different components, for examples take a look at the xml files inside the Config directory.


## Parts of the project

|**CEP**|**CtE**|**HFC**|**AEAD**|**Config**|**UnitTests**|**Images**|_main_|_SchemeFactory_|_Tester_|_ConfigParser_|
|-------|-------|-------|--------|----------|-------------|----------|------|---------------|--------|--------------|
|Contains files for the CEP scheme      |Contains files for the CtE1 and CtE2 scheme     |Contains files for the HFC scheme and ccAEAD transformation    |Contains files for AEAD schemes     |Example config files for every scheme.      |Tests to compare different parts of the schemes and CryptoPP library, for the usage see [Handling the UnitTests](#UnitTests)    |Testimages for the schemes.      |Defines the main routine that is done for testing a provided scheme by user input.     |Factory which is used to provide the fitting objects (CEP, CtE1, Hashing, ...) for testing during parsing the config file    |Classes for general testing and the testing of the schemes. Handles testing routing of the schemes, reading the images, increasing the Nonce and so on.    |Parses the config file for a scheme, see [Config file](#configFile).|
