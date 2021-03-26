#ifndef IHFCSCHEME_H
#define IHFCSCHEME_H 

#include <string>

#include <cryptopp/osrng.h>

class IHFCScheme
{
public:
	/// \brief Construct a HFC scheme
    IHFCScheme() {};
	/// \brief Destruct a HFC scheme
    virtual ~IHFCScheme() {};
    /// \brief Key generation for the scheme
    std::string EKg()
    {
        CryptoPP::AutoSeededRandomPool Rnd;
        string Key(GetBlockSize(), '0');
        Rnd.GenerateBlock((unsigned char*)Key.data(), Key.size());
        return Key;
    }
    /// \brief Encryptes the message with a header
	/// \param KEC Key for the encryption
	/// \param Nonce for the encryption
	/// \param Header for the encryption
	/// \param Message pointer to input for the encryption
	/// \param MessageSize size of input data for the encryption
	/// \param CEC reference outputs the cipher for the message
	/// \param BEC reference outputs the commitment
    /// \details We use a pointer to the input message to avoid
    ///          a string creation in any case
    virtual void EC(const std::string& KEC,
                    const std::string& Header,
                    const unsigned char* Message, 
                    uint32_t MessageSize, 
                    std::string& CEC,
                    std::string& BEC) = 0;
    /// \brief Decryptes the cipher with a header
	/// \param KEC Key for the decryption
	/// \param Nonce for the decryption
	/// \param Header for the decryption
	/// \param CEC ciphertext pointer for the decryption
	/// \param CECSize size of data of ciphertext
	/// \param BEC commitment for the decryption
	/// \param Message reference outputs the message
    /// \details We use a pointer to CEC to avoid
    ///          a string creation in any case
    virtual bool DO(const std::string& KEC,
                    const std::string& Header,
                    const unsigned char* CEC, 
                    uint32_t CECSize, 
                    const std::string& BEC,
                    std::string& Message) = 0;
    /// \brief Verifies the Header and Message for a commitment
	/// \param Nonce for the verification
	/// \param Header for the verification
	/// \param Message for the verification
	/// \param KEC for the verification
	/// \param BEC the commitment to verify
    virtual bool EVer(const std::string& Header,
                      const std::string& Message,
                      const std::string& KEC,
                      const std::string& BEC) = 0;
    virtual const std::string& GetClassDecription() = 0;
    virtual uint32_t GetBlockSize() = 0;
    virtual uint32_t GetStateSize() = 0;
    /// \brief Checks if the key size is correct
    /// for the scheme
    bool CheckInput(uint32_t Keysize)
    {
        if (Keysize != GetBlockSize())
        {
            throw runtime_error(std::string(typeid(this).name()) +
                                " Wrong key size (" +
                                std::to_string(Keysize) +
                                "), it should be " + to_string(GetBlockSize())); 
        }
        return true;
    };

    protected:
        const std::string mIV = "";
};
#endif
