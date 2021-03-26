using namespace std;

#include <cryptopp/cryptlib.h>
#include <cryptopp/misc.h>
using namespace CryptoPP;

#include "SHA512_HFC.h"

void SHA512_HFC::EC(const string& KEC,
                    const string& Header,
                    const unsigned char* Message,
                    uint32_t MessageSize,
                    string& CEC,
                    string& BEC)
{
    if (Message == NULL)
    {
        throw runtime_error("Null pointer for message");
    }
    CheckInput(KEC.size());
    uint32_t BLOCKSIZE = GetBlockSize();
    uint32_t STATESIZE = GetStateSize();
    uint32_t BLOCKUNITSIZE = BLOCKSIZE / sizeof(word64);
    uint32_t STATEUNITSIZE = STATESIZE / sizeof(word64);
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    // Initialize state with IV
    word64 State[STATEUNITSIZE];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    SHA512::Transform(State, (word64*)KeyPointer);
    /* Vh <- f+(V0, (KEC xor H1) || ... || (KEC xor Hh)) */
    uint8_t XorBuffer[BLOCKSIZE];
    uint32_t HLength = Header.size();
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    while (HLength >= BLOCKSIZE)
    {
        xorbuf(XorBuffer, HPointer, KeyPointer, BLOCKSIZE);
        SHA512::Transform(State, (word64*)XorBuffer);
        HPointer += BLOCKSIZE;
        HLength -= BLOCKSIZE;
    }
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    xorbuf(XorBuffer, HPointer, HLength);
    SHA512::Transform(State, (word64*)XorBuffer);

    /* C_EC <- e */
    uint32_t MLength = MessageSize;
    CEC.resize(MLength);
    uint8_t *OutputPointer = (uint8_t*)CEC.data();
    const uint8_t *MPointer = (const uint8_t*)Message;
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    /* For i=1,...,m-1 do */
    while (MLength > STATESIZE)
    {
        /* C_EC <- C_EC || (V_h+i-1 xor M_i) */
        xorbuf(OutputPointer, MPointer, (uint8_t*)State, STATESIZE);
        /* V_h+i <- f(V_h+i-1, (KEC xor M_i')) */
        xorbuf(XorBuffer, MPointer, KeyPointer, STATESIZE);
        SHA512::Transform(State, (word64*)XorBuffer);
        MPointer += STATESIZE;
        OutputPointer += STATESIZE;
        MLength -= STATESIZE;
    }

    /* C_EC <- C_EC || (V_h+m-1 xor M_m) */
    xorbuf(OutputPointer, MPointer, (uint8_t*)State, MLength);
    /* M_m', M_m+1' <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    word64 MessageSuf[2 * BLOCKUNITSIZE] = {0};
    memcpy(MessageSuf, MPointer, MLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = MessageSize;
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)) / sizeof(word64), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)) / sizeof(word64), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKUNITSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKUNITSIZE, KeyPointer, BLOCKUNITSIZE);
    /* B_EC <- f+(V_h+m-1, (K_EC xor M_m') || (K_EC xor M_m+1')) */
    SHA512::Transform(State, MessageSuf);
    SHA512::Transform(State, MessageSuf + BLOCKUNITSIZE);
    /* Return (C_EC, B_EC), C_EC is already constructed */
    BEC.assign(State, State + STATEUNITSIZE);
    return;
}

bool SHA512_HFC::DO(const string& KEC,
                    const string& Header,
                    const unsigned char* CEC,
                    uint32_t CECSize,
                    const string& BEC,
                    string& Message)
{
    if (CEC == NULL)
    {
        throw runtime_error("Null pointer for CEC");
    }
    CheckInput(KEC.size());
    uint32_t BLOCKSIZE = GetBlockSize();
    uint32_t STATESIZE = GetStateSize();
    uint32_t BLOCKUNITSIZE = BLOCKSIZE / sizeof(word64);
    uint32_t STATEUNITSIZE = STATESIZE / sizeof(word64);
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    // Initialize state with IV
    word64 State[STATEUNITSIZE];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    SHA512::Transform(State, (word64*)KeyPointer);
    /* Vh <- f+(V0, (KEC xor H1) || ... || (KEC xor Hh)) */
    uint8_t XorBuffer[BLOCKSIZE];
    uint32_t HLength = Header.size();
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    while (HLength >= BLOCKSIZE)
    {
        xorbuf(XorBuffer, HPointer, KeyPointer, BLOCKSIZE);
        SHA512::Transform(State, (word64*)XorBuffer);
        HPointer += BLOCKSIZE;
        HLength -= BLOCKSIZE;
    }
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    xorbuf(XorBuffer, HPointer, HLength);
    SHA512::Transform(State, (word64*)XorBuffer);

    /* M <- e */
    uint32_t CLength = CECSize;
    Message.resize(CLength);
    uint8_t *OutputPointer = (uint8_t*)Message.data();
    const uint8_t *CPointer = (const uint8_t*)CEC;
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    /* For i=1,...,m-1 do */
    while (CLength > STATESIZE)
    {
        /* M <- M || (V_h+i-1 xor CEC_i) */
        xorbuf(OutputPointer, CPointer, (uint8_t*)State, STATESIZE);
        /* V_h+i <- f(V_h+i-1, (KEC xor M_i')) */
        xorbuf(XorBuffer, OutputPointer, KeyPointer, STATESIZE);
        SHA512::Transform(State, (word64*)XorBuffer);
        CPointer += STATESIZE;
        OutputPointer += STATESIZE;
        CLength -= STATESIZE;
    }

    /* M <- M || (V_h+m-1 xor CEC_m) */
    xorbuf(OutputPointer, CPointer, (uint8_t*)State, CLength);
    /* M_m', M_m+1' <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    word64 MessageSuf[2 * BLOCKUNITSIZE] = {0};
    memcpy(MessageSuf, OutputPointer, CLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = Message.size();
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)) / sizeof(word64), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)) / sizeof(word64), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKUNITSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKUNITSIZE, KeyPointer, BLOCKUNITSIZE);
    /* B_EC <- f+(V_h+m-1, (K_EC xor M_m') || (K_EC xor M_m+1')) */
    SHA512::Transform(State, MessageSuf);
    SHA512::Transform(State, MessageSuf + BLOCKUNITSIZE);
    /* If B_EC' != B_EC then Return 0 */
    string BECNew(State, State + STATEUNITSIZE);
    if (BEC.compare(BECNew))
    {
        memset(Message.data(), 0x00, Message.size());
        return false;
    }
    return true;
}

bool SHA512_HFC::EVer(const string& Header,
                      const string& Message,
                      const string& KEC,
                      const string& BEC)
{
    CheckInput(KEC.size());
    uint32_t BLOCKSIZE = GetBlockSize();
    uint32_t STATESIZE = GetStateSize();
    uint32_t BLOCKUNITSIZE = BLOCKSIZE / sizeof(word64);
    uint32_t STATEUNITSIZE = STATESIZE / sizeof(word64);
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    // Initialize state with IV
    word64 State[STATEUNITSIZE];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    SHA512::Transform(State, (word64*)KeyPointer);
    /* Vh <- f+(V0, (KEC xor H1) || ... || (KEC xor Hh)) */
    uint8_t XorBuffer[BLOCKSIZE];
    uint32_t HLength = Header.size();
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    while (HLength >= BLOCKSIZE)
    {
        xorbuf(XorBuffer, HPointer, KeyPointer, BLOCKSIZE);
        SHA512::Transform(State, (word64*)XorBuffer);
        HPointer += BLOCKSIZE;
        HLength -= BLOCKSIZE;
    }
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    xorbuf(XorBuffer, HPointer, HLength);
    SHA512::Transform(State, (word64*)XorBuffer);

    /* V_m-1 <- f+(V0, (KEC xor M_1') || ... || (KEC xor M_m-1')) */
    uint32_t MLength = Message.size();
    const uint8_t *MPointer = (const uint8_t*)Message.data();
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    while (MLength > STATESIZE)
    {
        xorbuf(XorBuffer, MPointer, KeyPointer, STATESIZE);
        SHA512::Transform(State, (word64*)XorBuffer);
        MPointer += STATESIZE;
        MLength -= STATESIZE;
    }

    /* M_m', M_m+1' <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    word64 MessageSuf[2 * BLOCKUNITSIZE] = {0};
    memcpy(MessageSuf, MPointer, MLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = Message.size();
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)) / sizeof(word64), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)) / sizeof(word64), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKUNITSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKUNITSIZE, KeyPointer, BLOCKUNITSIZE);
    /* B_EC <- f+(V_h+m-1, (K_EC xor M_m') || (K_EC xor M_m+1')) */
    SHA512::Transform(State, MessageSuf);
    SHA512::Transform(State, MessageSuf + BLOCKUNITSIZE);
    /* If B_EC' != B_EC then Return 0 */
    string BECNew(State, State + STATEUNITSIZE);
    if (BEC.compare(BECNew))
    {
        return false;
    }
    return true;
}

const string& SHA512_HFC::GetClassDecription()
{
    return cClassDescription;
}

uint32_t SHA512_HFC::GetBlockSize()
{
    return 128;
}

uint32_t SHA512_HFC::GetStateSize()
{
    return 64;
}
