using namespace std;

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
using namespace CryptoPP;

#include "CEP.h"

void CEP::Enc(const string& Key,
              const string& Header,
              const string& Message,
              string& C1,
              string& C2)
{
    const uint32_t MACKEYSIZE = mHash->DefaultKeyLength();
    // Setup G
    mG->SetKeyWithIV((const unsigned char*)Key.data(), Key.size(),
                     (const unsigned char*)mNonce.data(), mNonce.size());
    /* P <- G(K, N, |M| + 2*n), different than the paper */
    // Here we use the encryption that already xors the input
    // Thats why we get the ciphertext directly from the pad
    uint32_t MessageSize = Message.size();
    string Padding(2*MACKEYSIZE, 0x00);
    string P0;
    string P1;
    StreamTransformationFilter Encryptor(mG->Ref(), NULL);
    Encryptor.Put((unsigned char*)Padding.data(), Padding.size());
    Encryptor.Put((unsigned char*)Message.data(), Message.size());
    Encryptor.MessageEnd();
    // Remove data from filter
    size_t PadSize = (size_t)-1;
    PadSize = Encryptor.MaxRetrievable();
    // Split pad P into P0, P1 and C1
    if (PadSize == MessageSize + 2*MACKEYSIZE)
    {
        P0.resize(MACKEYSIZE);
        P1.resize(MACKEYSIZE);
        C1.resize(MessageSize);
        // Get P0
        Encryptor.Get((unsigned char*)P0.data(), P0.size());
        // Get P1
        Encryptor.Get((unsigned char*)P1.data(), P1.size());
        // Get C1 = (P2 || ... || Pm+1)
        Encryptor.Get((unsigned char*)C1.data(), MessageSize);
    }
    // Setup F_cr with P0
    mHashCr->SetKey((const unsigned char*)P0.data(), P0.size());
    /* C2 <- F_cr(P0, H || M)  */
    string C2_Part;
    mHashCr->Update((const unsigned char*)Header.data(), Header.size());
    mHashCr->Update((const unsigned char*)Message.data(), Message.size());
    C2_Part.resize(mHashCr->DigestSize());
    mHashCr->Final((unsigned char*)C2_Part.data());
    // Setup F with P1
    mHash->SetKey((const unsigned char*)P1.data(), P1.size());
    /* T <- F(P1, C2)  */
    string T;
    mHash->Update((const unsigned char*)C2_Part.data(), C2_Part.size());
    T.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)T.data());
    /* return (C1 || T, C2) */
    C1.append(T);
    C2.assign(C2_Part);
    return;
}

bool CEP::Dec(const string& Key,
              const string& Header,
              const string& C1,
              const string& C2,
              string& Message,
              string& Keyf)
{
    const uint32_t MACKEYSIZE = mHash->DefaultKeyLength();
    // Setup G
    mG->SetKeyWithIV((const unsigned char*)Key.data(), Key.size(),
                     (const unsigned char*)mNonce.data(), mNonce.size());
    /* P <- G(K, N, |M| + 2*n), different than the paper */
    // Here we use the encryption that already xors the input
    // Thats why we get the message directly from the pad
    uint32_t CipherSize = C1.size() - mHash->TagSize();
    string Padding(2*MACKEYSIZE, 0x00);
    string P0, P1;
    StreamTransformationFilter Encryptor(mG->Ref(), NULL);
    Encryptor.Put((unsigned char*)Padding.data(), Padding.size());
    Encryptor.Put((unsigned char*)C1.data(), CipherSize);
    Encryptor.MessageEnd();
    // Remove data from filter
    size_t PadSize = (size_t)-1;
    PadSize = Encryptor.MaxRetrievable();
    // Split pad P into P0, P1 and M
    if (PadSize == CipherSize + 2*MACKEYSIZE)
    {
        P0.resize(MACKEYSIZE);
        P1.resize(MACKEYSIZE);
        Message.resize(CipherSize);
        // Get P0
        Encryptor.Get((unsigned char*)P0.data(), P0.size());
        // Get P1
        Encryptor.Get((unsigned char*)P1.data(), P1.size());
        // Get M = (P2 || ... || Pm+1)
        Encryptor.Get((unsigned char*)Message.data(), CipherSize);
    }
    // Setup F_cr with P0
    mHashCr->SetKey((const unsigned char*)P0.data(), P0.size());
    /* C2' <- F_cr(P0, H || M)  */
    string C2New;
    mHashCr->Update((const unsigned char*)Header.data(), Header.size());
    // Message M is (P2 || ... || Pm+1)
    mHashCr->Update((const unsigned char*)Message.data(), Message.size());
    C2New.resize(mHashCr->DigestSize());
    mHashCr->Final((unsigned char*)C2New.data());
    // Setup F with P1
    mHash->SetKey((const unsigned char*)P1.data(), P1.size());
    /* T' <- F(P1, C2')  */
    string TNew;
    mHash->Update((const unsigned char*)C2New.data(), C2New.size());
    TNew.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)TNew.data());
    // Extract T from C1 = C1' || T
    string T = C1.substr(C1.size() - mHash->TagSize());
    // If T != T′ or C2' != C2 then Return 0
    if (T.compare(TNew) || C2.compare(C2New))
    {
        memset(Message.data(), 0x00, Message.size());
        return false;
    }
    /* return (M, Keyf) */
    Keyf.assign(P0);
    return true;
}

bool CEP::Ver(const string& Header,
              const string& Message,
              const string& Keyf,
              const string& C2)
{
    // Setup F_cr
    mHashCr->SetKey((const unsigned char*)Keyf.data(), Keyf.size());
    /* C2' <- F_cr(Kf, H || M)  */
    string C2New;
    mHashCr->Update((const unsigned char*)Header.data(), Header.size());
    mHashCr->Update((const unsigned char*)Message.data(), Message.size());
    C2New.resize(mHashCr->DigestSize());
    mHashCr->Final((unsigned char*)C2New.data());
    // If C2' != C2 then Return 0
    if (C2.compare(C2New))
    {
        return false;
    }
    return true;
}

const string& CEP::GetClassDecription()
{
    return cClassDescription;
}

uint32_t CEP::GetKeySize()
{
    return mG->DefaultKeyLength();
}

uint32_t CEP::GetNonceSize()
{
    return mG->IVSize();
}
