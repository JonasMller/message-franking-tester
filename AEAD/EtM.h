#ifndef ETM_H
#define ETM_H

#include <string>

#include <cryptopp/cryptlib.h>

#include "IAEADScheme.h" 

class EtM : public IAEADScheme
{
public:
    EtM(CryptoPP::MessageAuthenticationCode* Hash,
        CryptoPP::SymmetricCipher* Enc,
        CryptoPP::SymmetricCipher* Dec):
            mEnc(Enc),
            mDec(Dec),
            mHash(Hash),
            mTF(mEnc->Ref(), NULL),
            cClassDescription("EtM[" + std::string(mEnc->AlgorithmName()) + ", " + std::string(mHash->AlgorithmName()) + "]")
    {};
    ~EtM()
    {
        delete mEnc;
        delete mDec;
        delete mHash;
    };

    void Enc(const std::string& Key,
             const std::string& Nonce,
             const std::string& Header,
             const std::string& Message,
             std::string& C);
    bool Dec(const std::string& Key,
             const std::string& Nonce,
             const std::string& Header,
             const std::string& C,
             std::string& Message);
    void StartEnc(const std::string& Key,
                  const std::string& Nonce,
                  const std::string& Header,
                  const unsigned char* Message,
                  uint32_t MessageLength);
    void UpdateEnc(const unsigned char* Message,
                   uint32_t MessageLength);
    void FinishEnc(std::string& Output);
    bool PDec(const std::string& Key,
              const std::string& Nonce,
              const std::string& Header,
              const unsigned char* Cipher,
              uint32_t CipherLength,
              std::string& Output);
    const std::string& GetClassDecription();
    uint32_t GetKeySize();
    uint32_t GetBlockSize();
    uint32_t GetTagSize();
    bool IsBlockCipher();

private:
    CryptoPP::SymmetricCipher* mEnc;
    CryptoPP::SymmetricCipher* mDec;
    CryptoPP::MessageAuthenticationCode* mHash;
    CryptoPP::StreamTransformationFilter mTF;
    const std::string cClassDescription;

};
#endif
