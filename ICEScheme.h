#ifndef ICESCHEME_H
#define ICESCHEME_H

#include <string>

#include <cryptopp/osrng.h>

/// \brief Interface for a CE scheme
/// \details Gets implemented by the schemes to test,
/// there are four schemes at the moment CEP, CtE1, CtE2 
/// and CE Transformation from HFC
class ICEScheme
{
public:
	/// \brief Construct a CEScheme
    ICEScheme(): 
        mNonce("")
    {};
	/// \brief Destruct a CEScheme
    virtual ~ICEScheme() {};
	/// \brief Key generation of the scheme
    std::string Kg()
    {
        CryptoPP::AutoSeededRandomPool Rnd;
        string Key(GetKeySize(), '0');
        Rnd.GenerateBlock((unsigned char*)Key.data(), Key.size());
        return Key;
    }
    /// \brief Encryptes the message with a header
	/// \param Key for the encryption
	/// \param Header for the encryption
	/// \param Message for the encryption
	/// \param C1 reference outputs the cipher for the message
	/// \param C2 reference outputs the commitment
    virtual void Enc(const std::string& Key,
                     const std::string& Header,
                     const std::string& Message,
                     std::string& C1,
                     std::string& C2) = 0;
    /// \brief Decryptes the C1 and C2 with the Header
	/// \param Key for the decryption 
	/// \param Header for the decryption 
	/// \param C1 the cipher for the message
	/// \param C2 the commitment
	/// \param Message outputs the decrypted message
	/// \param Keyf outputs the opening key for verification
    virtual bool Dec(const std::string& Key,
                     const std::string& Header,
                     const std::string& C1,
                     const std::string& C2,
                     std::string& Message,
                     std::string& Keyf) = 0;
    /// \brief Verifies the Header and Message for a commitment
	/// \param Header for the verification
	/// \param Message for the verification
	/// \param Keyf opening key for the verification
	/// \param C2 the commitment to verify
    virtual bool Ver(const std::string& Header,
                     const std::string& Message,
                     const std::string& Keyf,
                     const std::string& C2) = 0;
    /// \brief Returns the class description
    /// \details Contains every component
    virtual const std::string& GetClassDecription() = 0;
    /// \brief Returns the needed key size
    virtual uint32_t GetKeySize() = 0;
    /// \brief Returns the needed nonce size
    virtual uint32_t GetNonceSize() = 0;
    /// \brief Sets the nonce
    void SetNonce(string& Nonce) 
    {
        mNonce.assign(Nonce);
    }

protected:
    string mNonce;
};
#endif
