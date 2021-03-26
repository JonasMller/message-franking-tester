#ifndef CETRANSFORMATION_H
#define CETRANSFORMATION_H

#include <string>

#include "../ICEScheme.h" 
#include "../AEAD/IAEADScheme.h" 
#include "IHFCScheme.h" 

class CETransformation : public ICEScheme
{
public:
    CETransformation(IHFCScheme* EC,
                     IAEADScheme* AEAD):
            mEC(EC),
            mAEAD(AEAD),
            cClassDescription("CETransform[" + EC->GetClassDecription() + ", " + mAEAD->GetClassDecription() + "]")
    {}

    ~CETransformation()
    {
        delete mEC;
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
    IHFCScheme* mEC;
    IAEADScheme* mAEAD;
    const std::string cClassDescription;

};
#endif
