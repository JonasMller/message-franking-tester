using namespace std;

#include <cryptopp/filters.h>
using namespace CryptoPP;

#include "AES_GCM.h"

void AES_GCM::Enc(const string& Key,
                  const string& Nonce,
                  const string& Header,
                  const string& Message,
                  string& C)
{
    // Setup encryption
    mEnc.SetKeyWithIV((const unsigned char*)Key.data(), Key.size(),
                      (const unsigned char*)Nonce.data(), Nonce.size());
    // AuthenticatedEncryptionFilter defines two
    // channels: DEFAULT_CHANNEL and AAD_CHANNEL
    // DEFAULT_CHANNEL is encrypted and authenticated
    // AAD_CHANNEL is authenticated
    AuthenticatedEncryptionFilter EF(mEnc, NULL, false, cTagSize);
    // Authenticated data *must* be pushed before
    // Confidential/Authenticated data. Otherwise
    // we must catch the BadState exception
    EF.ChannelPut(AAD_CHANNEL, (const unsigned char*)Header.data(), Header.size());
    EF.ChannelMessageEnd(AAD_CHANNEL);
    // Confidential data comes after authenticated data.
    // This is a limitation due to CCM mode, not GCM mode.
    EF.ChannelPut(DEFAULT_CHANNEL, (const unsigned char*)Message.data(), Message.size());
    EF.ChannelMessageEnd(DEFAULT_CHANNEL);
    EF.SetRetrievalChannel(DEFAULT_CHANNEL);
    // Remove data from channel
    size_t CipherSize = (size_t)-1;
    // Ciphertext recovered
    CipherSize = (size_t)EF.MaxRetrievable();
    C.resize(CipherSize);
    EF.Get((unsigned char*)C.data(), CipherSize);
    return;
}

bool AES_GCM::Dec(const string& Key,
                  const string& Nonce,
                  const string& Header,
                  const string& C,
                  string& Message)
{
    // Setup decryption
    mDec.SetKeyWithIV((const unsigned char*)Key.data(), Key.size(),
                      (const unsigned char*)Nonce.data(), Nonce.size());
    // Break the cipher text out into it's
    // components: Encrypted and MAC
    string Tag = C.substr(C.size() - cTagSize);
    // Object *will* throw an exception
    // during decryption\verification _if_
    // verification fails.
    AuthenticatedDecryptionFilter DF(mDec, NULL, AuthenticatedDecryptionFilter::MAC_AT_BEGIN | AuthenticatedDecryptionFilter::THROW_EXCEPTION, cTagSize);
    // The order of the following calls are important
    DF.ChannelPut(DEFAULT_CHANNEL, (unsigned char*)Tag.data(), Tag.size());
    DF.ChannelPut(AAD_CHANNEL, (const unsigned char*)Header.data(), Header.size()); 
    DF.ChannelPut(DEFAULT_CHANNEL, (unsigned char*)C.data(), C.size() - cTagSize);               
    // If the object throws, it will most likely occur
    // during ChannelMessageEnd()
    DF.ChannelMessageEnd(AAD_CHANNEL);
    DF.ChannelMessageEnd(DEFAULT_CHANNEL);
    // If the object does not throw, here's the only
    // opportunity to check the data's integrity
    bool Success = false;
    Success = DF.GetLastResult();
    if (Success == false)
    {
        return false;
    }
    // Remove data from channel
    size_t MessageSize = (size_t)-1;
    // Plain text recovered from enc.data()
    DF.SetRetrievalChannel(DEFAULT_CHANNEL);
    MessageSize = (size_t)DF.MaxRetrievable();
    Message.resize(MessageSize);
    if (MessageSize > 0)
    {
        DF.Get((unsigned char*)Message.data(), MessageSize);
    }
    return true;
}

void AES_GCM::StartEnc(const std::string& Key,
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
    mEF.Initialize();
    // Setup encryption
    mEnc.SetKeyWithIV((const unsigned char*)Key.data(), Key.size(),
                      (const unsigned char*)Nonce.data(), Nonce.size());
    // Authenticated data *must* be pushed before
    // Confidential/Authenticated data. Otherwise
    // we must catch the BadState exception
    mEF.ChannelPut(AAD_CHANNEL, (const unsigned char*)Header.data(), Header.size() );
    mEF.ChannelMessageEnd(AAD_CHANNEL);
    mEF.ChannelPut(DEFAULT_CHANNEL, Message, MessageLength);
    return;
}

void AES_GCM::UpdateEnc(const unsigned char* Message,
                        uint32_t MessageLength)
{
    if (Message == NULL)
    {
        throw runtime_error("Null pointer for Message");
    }
    // Confidential data comes after authenticated data.
    // This is a limitation due to CCM mode, not GCM mode.
    mEF.ChannelPut(DEFAULT_CHANNEL, Message, MessageLength);
    return;
}

void AES_GCM::FinishEnc(std::string& Output)
{
    mEF.ChannelMessageEnd(DEFAULT_CHANNEL);
    mEF.SetRetrievalChannel(DEFAULT_CHANNEL);
    // Remove data from channel
    size_t CipherSize = (size_t)-1;
    // Ciphertext recovered
    CipherSize = (size_t)mEF.MaxRetrievable();
    Output.resize(CipherSize);
    mEF.Get((unsigned char*)Output.data(), CipherSize);
    return;
}

bool AES_GCM::PDec(const std::string& Key,
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
    // Reset Filter
    mDF.IsolatedInitialize(MakeParameters
            (Name::AuthenticatedDecryptionFilterFlags(), (word32)(AuthenticatedDecryptionFilter::MAC_AT_BEGIN | AuthenticatedDecryptionFilter::THROW_EXCEPTION)));
    // Setup decryption
    mDec.SetKeyWithIV((const unsigned char*)Key.data(), Key.size(),
                      (const unsigned char*)Nonce.data(), Nonce.size());
    // The order of the following calls are important
    mDF.ChannelPut(DEFAULT_CHANNEL, (unsigned char*)(Cipher + CipherLength - cTagSize), cTagSize);
    mDF.ChannelPut(AAD_CHANNEL, (const unsigned char*)Header.data(), Header.size());
    mDF.ChannelPut(DEFAULT_CHANNEL, Cipher, CipherLength - cTagSize);
    // If the object throws, it will most likely occur
    // during ChannelMessageEnd()
    mDF.ChannelMessageEnd(AAD_CHANNEL);
    mDF.ChannelMessageEnd(DEFAULT_CHANNEL);
    // If the object does not throw, here's the only
    // opportunity to check the data's integrity
    bool Success = false;
    Success = mDF.GetLastResult();
    if (Success == false)
    {
        return false;
    }
    // Remove data from channel
    size_t MessageSize = (size_t)-1;
    // Plain text recovered from enc.data()
    mDF.SetRetrievalChannel(DEFAULT_CHANNEL);
    MessageSize = (size_t)mDF.MaxRetrievable();
    Output.resize(MessageSize);
    if (MessageSize > 0)
    {
        mDF.Get((unsigned char*)Output.data(), MessageSize);
    }
    mDF.SkipMessages(1);
    return true;
}

const string& AES_GCM::GetClassDecription()
{
    return cClassDescription;
}

uint32_t AES_GCM::GetKeySize()
{
    return mEnc.DefaultKeyLength();
}

uint32_t AES_GCM::GetBlockSize()
{
    return mEnc.IVSize();
}

uint32_t AES_GCM::GetTagSize()
{
    return cTagSize;
}

bool AES_GCM::IsBlockCipher()
{
    return (mEnc.MandatoryBlockSize() > 1 && mEnc.MinLastBlockSize() == 0);
}
