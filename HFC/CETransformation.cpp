using namespace std;

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
using namespace CryptoPP;

#include "CETransformation.h"

void CETransformation::Enc(const string& Key,
                           const string& Header,
                           const string& Message,
                           string& C1,
                           string& C2)
{
    /* Kf <-$ {0, 1}^n */
    string Keyf = mEC->EKg();
    // (CEC, BEC) <- EC(KEC, H, M)
    mEC->EC(Keyf, Header, (unsigned char*)Message.data(), Message.size(), C1, C2);
    /* C_AE <- AEAD.Enc(K, C2, Keyf) */
    string C;
    mAEAD->Enc(Key, mNonce, C2, Keyf, C);
    /* Return (CEC || C_AE, BEC) */
    C1.append(C);
    return;
}

bool CETransformation::Dec(const string& Key,
                           const string& Header,
                           const string& C1, 
                           const string& C2,
                           string& Message,
                           string& Keyf)
{
    // Get size of cipher with keyf (block size of encryptment scheme) plus padding
    // From the cryptopp library (m_cipher is the encryption used in the aead scheme):
    // bool IsBlockCipher = (m_cipher.MandatoryBlockSize() > 1 && m_cipher.MinLastBlockSize() == 0);
    // Padding = IsBlockCipher ? PKCS_PADDING : NO_PADDING;
    uint32_t KeyfCipherSize = mEC->GetBlockSize();
    if (mAEAD->IsBlockCipher())
    {
        KeyfCipherSize += (mAEAD->GetBlockSize() - (KeyfCipherSize % mAEAD->GetBlockSize()));
    }
    // C1 = CEC || C_AE and C_AE = Keyf || padding || AEAD.tag
    uint32_t CECSize = C1.size() - KeyfCipherSize - mAEAD->GetTagSize();
    /* Keyf <- AEAD.Dec(K, C2, C_AE) */
    string RKeyf;
    bool Success = mAEAD->PDec(Key, mNonce, C2, (const unsigned char*)(C1.data() + CECSize), C1.size() - CECSize, RKeyf);
    /* If KEC = 0 then Return 0 */
    if (!Success)
    {
        return false;
    }
    // Here we use a pointer to the CEC to avoid splitting the large ciphertext
    // and do not need to create a new large string
    /* M <- DO(KEC, H, CEC, BEC) */
    Success = mEC->DO(RKeyf, Header, (const unsigned char*)C1.data(), CECSize, C2, Message);
    /* If M = 0 then Return 0 */
    if (!Success)
    {
        memset(Message.data(), 0x00, Message.size());
        return false;
    }
    /* Return (M, KEC), M already assigned */
    Keyf.assign(RKeyf);
    return true;
}

bool CETransformation::Ver(const string& Header,
                           const string& Message,
                           const string& Keyf,
                           const string& C2)
{
    // b <- EVer(H, M, KEC, BEC)
    bool Success = mEC->EVer(Header, Message, Keyf, C2);
    if (!Success)
    {
        return false;
    }
    return true;
}

const string& CETransformation::GetClassDecription()
{
    return cClassDescription;
}

uint32_t CETransformation::GetKeySize()
{
    return mAEAD->GetKeySize();
}

uint32_t CETransformation::GetNonceSize()
{
    return mAEAD->GetBlockSize();
}
