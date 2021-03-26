#ifndef AES_GCM_H
#define AES_GCM_H

#include <string>

#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>

#include "IAEADScheme.h" 

class AES_GCM : public IAEADScheme
{
public:
    AES_GCM():
        mEnc(),
        mDec(),
        mEF(mEnc, NULL, false, cTagSize),
        mDF(mDec, NULL, 0, cTagSize),
        cClassDescription("AES_GCM[" + std::string(mEnc.AlgorithmName()) + "]")
    {};
    ~AES_GCM() {};

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
    CryptoPP::GCM<CryptoPP::AES>::Encryption mEnc;
    CryptoPP::GCM<CryptoPP::AES>::Decryption mDec;
    CryptoPP::AuthenticatedEncryptionFilter mEF;
    CryptoPP::AuthenticatedDecryptionFilter mDF;
    const std::string cClassDescription;
    const uint32_t cTagSize = 16;
};
#endif
