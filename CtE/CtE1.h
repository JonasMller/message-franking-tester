#ifndef CTE1_H
#define CTE1_H

#include <string>

#include <cryptopp/cryptlib.h>

#include "../ICEScheme.h"
#include "../AEAD/IAEADScheme.h" 

class CtE1: public ICEScheme
{
public:
    CtE1(CryptoPP::MessageAuthenticationCode* Hash,
         IAEADScheme* AEAD):
            mHash(Hash),
            mAEAD(AEAD),
            cClassDescription("CtE1[" + std::string(mHash->AlgorithmName()) + ", "
                                      + mAEAD->GetClassDecription() + "]")
    {}
    ~CtE1()
    {
        delete mHash;
        delete mAEAD;
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
    IAEADScheme* mAEAD;
    const std::string cClassDescription;
};
#endif
