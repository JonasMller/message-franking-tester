#ifndef IAEADSCHEME_H
#define IAEADSCHEME_H

#include <string>

#include <cryptopp/osrng.h>

/// \brief Interface for an AEAD scheme
class IAEADScheme
{
public:
	/// \brief Construct a AEADScheme
    IAEADScheme()
    {};
	/// \brief Destruct a AEADScheme
    virtual ~IAEADScheme() {};
	/// \brief Key generation of the scheme
    std::string Kg()
    {
        CryptoPP::AutoSeededRandomPool Rnd;
        string Key(GetKeySize(), '0');
        Rnd.GenerateBlock((unsigned char*)Key.data(), Key.size());
        return Key;
    }
    /// \brief Authenticated encryption of the message with a header
	/// \param Key for the encryption
	/// \param Nonce for the encryption
	/// \param Header for the encryption
	/// \param Message for the encryption
	/// \param C reference outputs cipher with tag
    virtual void Enc(const std::string& Key,
                     const std::string& Nonce,
                     const std::string& Header,
                     const std::string& Message,
                     std::string& C) = 0;
    /// \brief Authenticated decryption of the cipher with a header
	/// \param Key for the decryption 
	/// \param Nonce for the decryption 
	/// \param Header for the decryption 
	/// \param C cipher for the decryption 
	/// \param Message reference outputs decrypted message
    virtual bool Dec(const std::string& Key,
                     const std::string& Nonce,
                     const std::string& Header,
                     const std::string& C,
                     std::string& Message) = 0;

    //======================================================//
    // We need to implement following functions to avoid string
    // constructions during our calculations to avoid time losses
    // for very larg strings

    /// \brief Start authenticated encryption and input provided data
	/// \param Key for the encryption
	/// \param Nonce for the encryption
	/// \param Header for the encryption
	/// \param Message pointer to input data for the encryption
	/// \param MessageLength length of input data
    virtual void StartEnc(const std::string& Key,
                          const std::string& Nonce,
                          const std::string& Header,
                          const unsigned char* Message,
                          uint32_t MessageLength) = 0;
    /// \brief Update the state of encryption with message
	/// \param Message pointer to the input data
	/// \param MessageLength length of the message
    virtual void UpdateEnc(const unsigned char* Message,
                           uint32_t MessageLength) = 0;
    /// \brief Finish encryption and return ciphertext
	/// \param Output receives ciphertext
    virtual void FinishEnc(std::string& Output) = 0;
    /// \brief Do authenticated decryption with a data pointer
	/// \param Key for the decryption
	/// \param Nonce for the decryption 
	/// \param Header for the decryption
	/// \param Cipher pointer to input data for the decryption
	/// \param CipherLength length of input data
	/// \param Output receives decrypted message
    virtual bool PDec(const std::string& Key,
                      const std::string& Nonce,
                      const std::string& Header,
                      const unsigned char* Cipher,
                      uint32_t CipherLength,
                      std::string& Output) = 0;
    virtual const std::string& GetClassDecription() = 0;
    virtual uint32_t GetKeySize() = 0;
    virtual uint32_t GetBlockSize() = 0;
    virtual uint32_t GetTagSize() = 0;
    virtual bool IsBlockCipher() = 0;

};
#endif
