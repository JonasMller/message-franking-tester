using namespace std;

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/chacha.h>
using namespace CryptoPP;

#include "SchemeFactory.h"
#include "CEP/CEP.h"
#include "CtE/CtE1.h"
#include "CtE/CtE2.h"
#include "HFC/CETransformation.h"
#include "AEAD/EtM.h"
#include "AEAD/AES_GCM.h"
#include "HFC/SHA256_HFC.h"
#include "HFC/SHA512_HFC.h"
#include "HFC/Whrlpool_HFC.h"
#include "HFC/SHA3_HFC.h"
#include "HFC/AltPad_SHA256_HFC.h"

ICEScheme* SchemeFactory::CreateCEP(string& Hash, string& HashCr, string& PRG)
{
    return new CEP(CreateMAC(Hash),
                   CreateMAC(HashCr),
                   CreatePRG(PRG));
}

ICEScheme* SchemeFactory::CreateCtE1(string& Hash, IAEADScheme* AEAD)
{
    return new CtE1(CreateMAC(Hash),
                    AEAD);
}

ICEScheme* SchemeFactory::CreateCtE2(string& Hash, IAEADScheme* AEAD)
{
    return new CtE2(CreateMAC(Hash),
                    AEAD);
}

ICEScheme* SchemeFactory::CreateCETransform(string& HFC, IAEADScheme* AEAD)
{
    return new CETransformation(CreateHFC(HFC),
                                AEAD);
}

IAEADScheme* SchemeFactory::CreateEtM(string& Hash, string& Enc)
{
    return new EtM(CreateMAC(Hash),
                   CreateEncryption(Enc),
                   CreateDecryption(Enc));
}

IAEADScheme* SchemeFactory::CreateAESGCM()
{
    return new AES_GCM();
}

IHFCScheme* SchemeFactory::CreateHFC(string& HFC)
{
    if ("SHA256_HFC" == HFC)
    {
        return new SHA256_HFC();
    }
    if ("SHA512_HFC" == HFC)
    {
        return new SHA512_HFC();
    }
    if ("Whrlpool_HFC" == HFC)
    {
        return new Whrlpool_HFC();
    }
    if ("SHA3_HFC" == HFC)
    {
        return new SHA3_HFC();
    }
    if ("AltPad_SHA256_HFC" == HFC)
    {
        return new AltPad_SHA256_HFC();
    }
    throw runtime_error("Not a valid HFC scheme: " + HFC);
}

SymmetricCipher* SchemeFactory::CreateEncryption(string& Enc)
{
    if ("CBC_Mode_AES" == Enc)
    {
        return new CBC_Mode<AES>::Encryption();
    }
    if ("CTR_Mode_AES" == Enc)
    {
        return new CTR_Mode<AES>::Encryption();
    }
    throw runtime_error("Not a valid encryption scheme: " + Enc);
}

SymmetricCipher* SchemeFactory::CreateDecryption(string& Dec)
{
    if ("CBC_Mode_AES" == Dec)
    {
        return new CBC_Mode<AES>::Decryption();
    }
    if ("CTR_Mode_AES" == Dec)
    {
        return new CTR_Mode<AES>::Decryption();
    }
    throw runtime_error("Not a valid decryption scheme: " + Dec);
}

MessageAuthenticationCode* SchemeFactory::CreateMAC(string& MAC)
{
    if ("SHA256" == MAC)
    {
        return new HMAC<SHA256>();
    }
    if ("SHA512" == MAC)
    {
        return new HMAC<SHA512>();
    }
    if ("SHA3" == MAC)
    {
        return new HMAC<SHA3_256>();
    }
    if ("Whrlpool" == MAC)
    {
        return new HMAC<Whirlpool>();
    }
    throw runtime_error("Not a valid mac scheme: " + MAC);
}

SymmetricCipher* SchemeFactory::CreatePRG(string& PRG)
{
    if ("CTR_Mode_AES" == PRG)
    {
        return new CTR_Mode<AES>::Encryption();
    }
    if ("ChaCha" == PRG)
    {
        return new ChaCha::Encryption();
    }
    throw runtime_error("Not a valid PRG scheme: " + PRG);
}
