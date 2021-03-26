using namespace std;

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
using namespace CryptoPP;

#include "CtE2.h"

void CtE2::Enc(const string& Key,
               const string& Header,
               const string& Message,
               string& C1,
               string& C2)
{
    // (Kf, C2) <-$ Com(H || M), we do Com with HMAC
    AutoSeededRandomPool Rnd;
    SecByteBlock Keyf(0x00, mHash->DefaultKeyLength());
    /* Kf <-$ {0, 1}^n */
    Rnd.GenerateBlock(Keyf, Keyf.size());
    // Setup HMAC
    mHash->SetKey(Keyf, Keyf.size());
    /* C2 <- HMAC(Keyf, H || M || Keyf) */
    mHash->Update((const unsigned char*)Header.data(), Header.size());
    mHash->Update((const unsigned char*)Message.data(), Message.size());
    mHash->Update(Keyf.BytePtr(), Keyf.size());
    C2.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)C2.data());
    /* C1 <- Enc(Key, C2, M || Keyf), with AEAD scheme C1 = C || T */
    mAEAD->StartEnc(Key, mNonce, Header, (const unsigned char*)Message.data(), Message.size());
    mAEAD->UpdateEnc((const unsigned char*)Keyf.data(), Keyf.size());
    mAEAD->FinishEnc(C1);
    /* Return (C || T, C2), alread created before */
    return;
}

bool CtE2::Dec(const string& Key,
               const string& Header,
               const string& C1,
               const string& C2,
               string& Message,
               string& Keyf)
{
    /* M || Keyf <- Dec(Key, C2, C1), with AEAD scheme */
    bool Success = mAEAD->PDec(Key, mNonce, Header, (unsigned char*)C1.data(), C1.size(), Message);
    /* If M = 0 then Return 0 */
    if (!Success)
    {
        memset(Message.data(), 0x00, Message.size());
        return false;
    }
    /* Setup HMAC with Keyf */
    string KeyfString = (Message.substr(Message.size() - mHash->DefaultKeyLength()));
    mHash->SetKey((const unsigned char*)KeyfString.data(), KeyfString.size());
    /* b <- VerC(Keyf, C2, H || M), here with HMAC */
    /* HMAC(Keyf, M || Keyf) */
    string C2New;
    mHash->Update((const unsigned char*)Header.data(), Header.size());
    mHash->Update((const unsigned char*)Message.data(), Message.size());
    C2New.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)C2New.data());
    /* If C2 != HMAC(Keyf, H || M || Keyf) then Return 0 */
    if (C2.compare(C2New))
    {
        memset(Message.data(), 0x00, Message.size());
        return false;
    }
    /* Return (M, Keyf) */
    Message.resize(Message.size() - KeyfString.size());
    Keyf.assign(KeyfString);
    return true;
}

bool CtE2::Ver(const string& Header,
               const string& Message,
               const string& Keyf,
               const string& C2)
{
    // Setup HMAC
    mHash->SetKey((const unsigned char*)Keyf.data(), Keyf.size());
    /* C2' <- HMAC(Keyf, H || M || Keyf) */
    string C2New;
    mHash->Update((const unsigned char*)Header.data(), Header.size());
    mHash->Update((const unsigned char*)Message.data(), Message.size());
    mHash->Update((const unsigned char*)Keyf.data(), Keyf.size());
    C2New.resize(mHash->DigestSize());
    mHash->Final((unsigned char*)C2New.data());
    /* If C2 != C2' then Return 0 */
    if (C2.compare(C2New))
    {
        return false;
    }
    return true;
}

const string& CtE2::GetClassDecription()
{
    return cClassDescription;
}

uint32_t CtE2::GetKeySize()
{
    return mAEAD->GetKeySize();
}

uint32_t CtE2::GetNonceSize()
{
    return mAEAD->GetBlockSize();
}
