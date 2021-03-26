#ifndef SHA512_HFC_H
#define SHA512_HFC_H

#include <string>

#include <cryptopp/sha.h>

#include "IHFCScheme.h" 

class SHA512_HFC : public IHFCScheme
{
public:
    void EC(const std::string& KEC,
            const std::string& Header,
            const unsigned char* Message, 
            uint32_t MessageSize, 
            std::string& CEC,
            std::string& BEC);
    bool DO(const std::string& KEC,
            const std::string& Header,
            const unsigned char* CEC, 
            uint32_t CECSize, 
            const std::string& BEC,
            std::string& Message);
    bool EVer(const std::string& Header,
              const std::string& Message,
              const std::string& KEC,
              const std::string& BEC);
    const std::string& GetClassDecription();
    uint32_t GetBlockSize();
    uint32_t GetStateSize();

protected:
    const std::string mIV = std::string(GetStateSize(), '0');

private:
    const std::string cClassDescription = "HFC[" +
                                          std::string(CryptoPP::SHA512::StaticAlgorithmName()) +
                                          "]";

};
#endif
