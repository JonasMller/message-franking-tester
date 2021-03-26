using namespace std;

#include <cryptopp/filters.h>
using namespace CryptoPP;

#include "EtM.h"

void EtM::Enc(const string& Key,
              const string& Nonce,
              const string& Header,
              const string& Message,
              string& C)
{
    // Setup for the hash and the encryption
    string Key1 = Key.substr(0, mEnc->DefaultKeyLength());
    string Key2 = Key.substr(mEnc->DefaultKeyLength());
    mEnc->SetKeyWithIV((const unsigned char*)Key1.data(), Key1.size(),
                       (const unsigned char*)Nonce.data(), Nonce.size());
    mHash->SetKey((const unsigned char*)Key1.data(), Key2.size());
    // Encrypt Message
    StreamTransformationFilter TF(mEnc->Ref(), NULL);
    TF.ChannelPut(DEFAULT_CHANNEL, (unsigned char*)Message.data(), Message.size());
    TF.ChannelMessageEnd(DEFAULT_CHANNEL);
    // Remove data from channel
    size_t CipherSize = (size_t)-1;
    // Plain text recovered from enc.data()
    TF.SetRetrievalChannel(DEFAULT_CHANNEL);
    CipherSize = (size_t)TF.MaxRetrievable();
    C.resize(CipherSize);
    if (CipherSize > 0)
    {
        TF.Get((unsigned char*)C.data(), CipherSize);
    }
    // Calculate tag
    string T;
    mHash->Update((const unsigned char*)Header.data(), Header.size());
    mHash->Update((const unsigned char*)C.data(), C.size());
    T.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)T.data());
    // Return C || T
    C.append(T);
    return;
}

bool EtM::Dec(const string& Key,
              const string& Nonce,
              const string& Header,
              const string& C,
              string& Message)
{
    // Setup hash, decryption and split cipher
    string Key1 = Key.substr(0, mDec->DefaultKeyLength());
    string Key2 = Key.substr(mDec->DefaultKeyLength());
    mDec->SetKeyWithIV((const unsigned char*)Key1.data(), Key1.size(),
                       (const unsigned char*)Nonce.data(), Nonce.size());
    mHash->SetKey((const unsigned char*)Key1.data(), Key2.size());
    //string C1 = C.substr(0, C.size() - GetTagSize());
    string T = C.substr(C.size() - GetTagSize());
    // Check the tag
    string TNew;
    mHash->Update((const unsigned char*)Header.data(), Header.size());
    mHash->Update((const unsigned char*)C.data(), C.size() - GetTagSize());
    TNew.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)TNew.data());
    if (T.compare(TNew))
    {
        return false;
    }
    // Decrypt cipher
    StreamTransformationFilter TF(mDec->Ref(), NULL);
    TF.ChannelPut(DEFAULT_CHANNEL, (unsigned char*)C.data(), C.size() - GetTagSize());
    TF.ChannelMessageEnd(DEFAULT_CHANNEL);
    // Remove data from channel
    size_t MessageSize = (size_t)-1;
    // Plain text recovered from enc.data()
    TF.SetRetrievalChannel(DEFAULT_CHANNEL);
    MessageSize = (size_t)TF.MaxRetrievable();
    Message.resize(MessageSize);
    if (MessageSize > 0)
    {
        TF.Get((unsigned char*)Message.data(), MessageSize);
    }
    return true;
}

void EtM::StartEnc(const std::string& Key,
                       const std::string& Nonce,
                       const std::string& Header,
                       const unsigned char* Message,
                       uint32_t MessageLength)
{
    if (Message == NULL)
    {
        throw runtime_error("Null pointer for Message");
    }
    // Reset Filter
    mTF.Initialize();
    // Setup for the hash and the encryption
    string Key1 = Key.substr(0, mEnc->DefaultKeyLength());
    string Key2 = Key.substr(mEnc->DefaultKeyLength());
    mEnc->SetKeyWithIV((const unsigned char*)Key1.data(), Key1.size(),
                       (const unsigned char*)Nonce.data(), Nonce.size());
    mHash->SetKey((const unsigned char*)Key1.data(), Key2.size());
    // Encrypt Message
    mTF.ChannelPut(DEFAULT_CHANNEL, Message, MessageLength);
    // Input header to MAC
    mHash->Update((const unsigned char*)Header.data(), Header.size());
}

void EtM::UpdateEnc(const unsigned char* Message,
                    uint32_t MessageLength)
{
    if (Message == NULL)
    {
        throw runtime_error("Null pointer for Message");
    }
    // Input message to cipher
    mTF.ChannelPut(DEFAULT_CHANNEL, Message, MessageLength);
}

void EtM::FinishEnc(std::string& Output)
{
    // Finish ciphertext
    mTF.ChannelMessageEnd(DEFAULT_CHANNEL);
    // Remove data from channel
    size_t CipherSize = (size_t)-1;
    // Plain text recovered from enc.data()
    mTF.SetRetrievalChannel(DEFAULT_CHANNEL);
    CipherSize = (size_t)mTF.MaxRetrievable();
    Output.resize(CipherSize);
    if (CipherSize > 0)
    {
        mTF.Get((unsigned char*)Output.data(), CipherSize);
    }
    // Calculate tag
    string T;
    mHash->Update((const unsigned char*)Output.data(), Output.size());
    T.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)T.data());
    // Return C || T
    Output.append(T);
    return;
}

bool EtM::PDec(const std::string& Key,
               const std::string& Nonce,
               const std::string& Header,
               const unsigned char* Cipher,
               uint32_t CipherLength,
               string& Output)
{
    if (Cipher == NULL)
    {
        throw runtime_error("Null pointer for Cipher");
    }
    // Setup hash, decryption and split cipher
    string Key1 = Key.substr(0, mDec->DefaultKeyLength());
    string Key2 = Key.substr(mDec->DefaultKeyLength());
    mDec->SetKeyWithIV((const unsigned char*)Key1.data(), Key1.size(),
                       (const unsigned char*)Nonce.data(), Nonce.size());
    mHash->SetKey((const unsigned char*)Key1.data(), Key2.size());
    //string C1 = C.substr(0, C.size() - GetTagSize());
    string T((const char*)(Cipher + CipherLength - GetTagSize()), GetTagSize());
    // Check the tag
    string TNew;
    mHash->Update((const unsigned char*)Header.data(), Header.size());
    mHash->Update(Cipher, CipherLength - GetTagSize());
    TNew.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)TNew.data());
    if (T.compare(TNew))
    {
        return false;
    }
    // Decrypt cipher
    StreamTransformationFilter TF(mDec->Ref(), NULL);
    TF.ChannelPut(DEFAULT_CHANNEL, Cipher, CipherLength - GetTagSize());
    TF.ChannelMessageEnd(DEFAULT_CHANNEL);
    // Remove data from channel
    size_t MessageSize = (size_t)-1;
    // Plain text recovered from enc.data()
    TF.SetRetrievalChannel(DEFAULT_CHANNEL);
    MessageSize = (size_t)TF.MaxRetrievable();
    Output.resize(MessageSize);
    if (MessageSize > 0)
    {
        TF.Get((unsigned char*)Output.data(), MessageSize);
    }
    return true;
}

const string& EtM::GetClassDecription()
{
    return cClassDescription;
}

uint32_t EtM::GetKeySize()
{
    return mEnc->DefaultKeyLength() + mHash->DefaultKeyLength();
}

uint32_t EtM::GetBlockSize()
{
    return mEnc->IVSize();
}

uint32_t EtM::GetTagSize()
{
    return mHash->DigestSize();
}

bool EtM::IsBlockCipher()
{
    return (mEnc->MandatoryBlockSize() > 1 && mEnc->MinLastBlockSize() == 0);
}
