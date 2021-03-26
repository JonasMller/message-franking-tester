#ifndef CEP_H
#define CEP_H

#include <string>
#include <assert.h>

#include <cryptopp/hmac.h>

#include "../ICEScheme.h"

class CEP: public ICEScheme
{
public:
    CEP(CryptoPP::MessageAuthenticationCode* Hash,
        CryptoPP::MessageAuthenticationCode* HashCr,
        CryptoPP::SymmetricCipher* PRF):
            mHash(Hash),
            mHashCr(HashCr),
            mG(PRF),
            cClassDescription("CEP[" + std::string(mHash->AlgorithmName()) + ", " + 
                                       std::string(mHashCr->AlgorithmName()) + ", " +
                                       std::string(mG->AlgorithmName()) + "]")
    {
        assert(mHash->DefaultKeyLength() == mHashCr->DefaultKeyLength());
    }
    ~CEP()
    {
        delete mHash;
        delete mHashCr;
    }

    void Enc(const std::string& Key,
             const std::string& Header,
             const std::string& Message,
             std::string& C1,
             std::string& C2);
    bool Dec(const std::string& Key,
             const std::string& Header,
             const std::string& C1,
             const std::string& C2,
             std::string& Message,
             std::string& Keyf);
    bool Ver(const std::string& Header,
             const std::string& Message,
             const std::string& Keyf,
             const std::string& C2);
    const std::string& GetClassDecription();
    uint32_t GetKeySize();
    uint32_t GetNonceSize();

private:
    CryptoPP::MessageAuthenticationCode* mHash;
    CryptoPP::MessageAuthenticationCode* mHashCr;
    CryptoPP::SymmetricCipher* mG;
    const std::string cClassDescription;
};
#endif
