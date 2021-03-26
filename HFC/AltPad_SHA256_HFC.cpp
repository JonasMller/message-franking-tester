using namespace std;

#include <cryptopp/cryptlib.h>
#include <cryptopp/misc.h>
using namespace CryptoPP;

#include "AltPad_SHA256_HFC.h"

void AltPad_SHA256_HFC::EC(const string& KEC,
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
    uint32_t BLOCKUNITSIZE = BLOCKSIZE / sizeof(word32);
    uint32_t STATEUNITSIZE = STATESIZE / sizeof(word32);
    uint32_t PadDiff = BLOCKSIZE - STATESIZE;
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    const unsigned char* KeyPointerPad = KeyPointer + PadDiff;
    // Initialize state with IV
    word32 State[STATEUNITSIZE];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    SHA256::Transform(State, (word32*)KeyPointer);
    /* Vh <- f+(V0, (KEC xor Hb) || ... || (KEC xor Hh)) */
    uint8_t XorBuffer[BLOCKSIZE];
    // We use the block M_m for the last padding with SufPad
    // therefore we cannot pad it with the header
    uint32_t HLength = Header.size();
    uint32_t MBlocks = MessageSize != 0 ? (ceil((float)MessageSize / STATESIZE) - 1) : 0;
    uint32_t HBlocks = ceil((float)Header.size() / PadDiff);
    if (HBlocks > MBlocks)
    {
        uint32_t HLengthR = Header.size() - (MBlocks * PadDiff);
        HLength -= HLengthR;
        const uint8_t *HPointer = (const uint8_t*)(Header.data() + (Header.size() - HLengthR));
        while (HLengthR >= BLOCKSIZE)
        {
            xorbuf(XorBuffer, HPointer, KeyPointer, BLOCKSIZE);
            SHA256::Transform(State, (word32*)XorBuffer);
            HPointer += BLOCKSIZE;
            HLengthR -= BLOCKSIZE;
        }
        memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
        xorbuf(XorBuffer, HPointer, HLengthR);
        SHA256::Transform(State, (word32*)XorBuffer);
    }

    /* C_EC <- e */
    uint32_t MLength = MessageSize;
    CEC.resize(MLength);
    uint8_t *OutputPointer = (uint8_t*)CEC.data();
    const uint8_t *MPointer = (const uint8_t*)Message;
    // Use the header blocks to pad message
    uint8_t *XorBufferPad = XorBuffer + PadDiff;
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    /* For i=1,...,b do */
    while (HLength >= PadDiff)
    {
        /* C_EC <- C_EC || (V_h+i-1 xor M_i) */
        xorbuf(OutputPointer, MPointer, (uint8_t*)State, STATESIZE);
        /* V_h+i <- f(V_h+i-1, (KEC xor M_i')) */
        xorbuf(XorBuffer, MPointer, KeyPointer, STATESIZE);
        xorbuf(XorBufferPad, HPointer, KeyPointerPad, PadDiff);
        SHA256::Transform(State, (word32*)XorBuffer);
        MPointer += STATESIZE;
        OutputPointer += STATESIZE;
        MLength -= STATESIZE;
        HLength -= PadDiff;
    }
    // If last block of header is not exact (d-n) bits long
    if (HLength > 0)
    {
        /* C_EC <- C_EC || (V_h+b-1 xor M_b) */
        xorbuf(OutputPointer, MPointer, (uint8_t*)State, STATESIZE);
        /* V_h+i <- f(V_h+b-1, (KEC xor M_b')) */
        memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
        xorbuf(XorBuffer, MPointer, KeyPointer, STATESIZE);
        xorbuf(XorBufferPad, HPointer, KeyPointerPad, HLength);
        SHA256::Transform(State, (word32*)XorBuffer);
        MPointer += STATESIZE;
        OutputPointer += STATESIZE;
        MLength -= STATESIZE;
    }
    // Use zero padding for the remaining message blocks
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    /* For i=b,...,m-1 do */
    while (MLength > STATESIZE)
    {
        /* C_EC <- C_EC || (V_h+i-1 xor M_i) */
        xorbuf(OutputPointer, MPointer, (uint8_t*)State, STATESIZE);
        /* V_h+i <- f(V_h+i-1, (KEC xor M_i')) */
        xorbuf(XorBuffer, MPointer, KeyPointer, STATESIZE);
        SHA256::Transform(State, (word32*)XorBuffer);
        MPointer += STATESIZE;
        OutputPointer += STATESIZE;
        MLength -= STATESIZE;
    }

    /* C_EC <- C_EC || (V_h+m-1 xor M_m) */
    xorbuf(OutputPointer, MPointer, (uint8_t*)State, MLength);
    /* M_m', M_m+1' <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    word32 MessageSuf[2 * BLOCKUNITSIZE] = {0};
    memcpy(MessageSuf, MPointer, MLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = MessageSize;
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)) / sizeof(word32), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)) / sizeof(word32), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKUNITSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKUNITSIZE, KeyPointer, BLOCKUNITSIZE);
    /* B_EC <- f+(V_h+m-1, (K_EC xor M_m') || (K_EC xor M_m+1')) */
    SHA256::Transform(State, MessageSuf);
    SHA256::Transform(State, MessageSuf + BLOCKUNITSIZE);
    /* Return (C_EC, B_EC), C_EC is already constructed */
    BEC.assign(State, State + STATEUNITSIZE);
    return;
}

bool AltPad_SHA256_HFC::DO(const string& KEC,
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
    uint32_t BLOCKUNITSIZE = BLOCKSIZE / sizeof(word32);
    uint32_t STATEUNITSIZE = STATESIZE / sizeof(word32);
    uint32_t PadDiff = BLOCKSIZE - STATESIZE;
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    const unsigned char* KeyPointerPad = KeyPointer + PadDiff;
    // Initialize state with IV
    word32 State[STATEUNITSIZE];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    SHA256::Transform(State, (word32*)KeyPointer);
    /* Vh <- f+(V0, (KEC xor H1) || ... || (KEC xor Hh)) */
    uint8_t XorBuffer[BLOCKSIZE];
    // We use the block M_m for the last padding with SufPad
    // therefore we cannot pad it with the header
    uint32_t HLength = Header.size();
    uint32_t CBlocks = CECSize != 0 ? (ceil((float)CECSize / STATESIZE) - 1) : 0;
    uint32_t HBlocks = ceil((float)Header.size() / PadDiff);
    if (HBlocks > CBlocks)
    {
        uint32_t HLengthR = Header.size() - (CBlocks * PadDiff);
        HLength -= HLengthR;
        const uint8_t *HPointer = (const uint8_t*)(Header.data() + (Header.size() - HLengthR));
        while (HLengthR >= BLOCKSIZE)
        {
            xorbuf(XorBuffer, HPointer, KeyPointer, BLOCKSIZE);
            SHA256::Transform(State, (word32*)XorBuffer);
            HPointer += BLOCKSIZE;
            HLengthR -= BLOCKSIZE;
        }
        memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
        xorbuf(XorBuffer, HPointer, HLengthR);
        SHA256::Transform(State, (word32*)XorBuffer);
    }

    /* M <- e */
    uint32_t CLength = CECSize;
    Message.resize(CLength);
    uint8_t *OutputPointer = (uint8_t*)Message.data();
    const uint8_t *CPointer = (const uint8_t*)CEC;
    // Use the header blocks to pad message
    uint8_t *XorBufferPad = XorBuffer + PadDiff;
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    /* For i=1,...,b do */
    while (HLength >= PadDiff)
    {
        /* M <- M || (V_h+i-1 xor CEC_i) */
        xorbuf(OutputPointer, CPointer, (uint8_t*)State, STATESIZE);
        /* V_h+i <- f(V_h+i-1, (KEC xor M_i')) */
        xorbuf(XorBuffer, OutputPointer, KeyPointer, STATESIZE);
        xorbuf(XorBufferPad, HPointer, KeyPointerPad, PadDiff);
        SHA256::Transform(State, (word32*)XorBuffer);
        CPointer += STATESIZE;
        OutputPointer += STATESIZE;
        CLength -= STATESIZE;
        HLength -= PadDiff;
    }
    // If last block of header is not exact (d-n) bits long
    if (HLength > 0)
    {
        /* C_EC <- C_EC || (V_h+b-1 xor M_b) */
        xorbuf(OutputPointer, CPointer, (uint8_t*)State, STATESIZE);
        /* V_h+i <- f(V_h+b-1, (KEC xor M_b')) */
        memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
        xorbuf(XorBuffer, OutputPointer, KeyPointer, STATESIZE);
        xorbuf(XorBufferPad, HPointer, KeyPointerPad, HLength);
        SHA256::Transform(State, (word32*)XorBuffer);
        CPointer += STATESIZE;
        OutputPointer += STATESIZE;
        CLength -= STATESIZE;
    }
    // Use zero padding for the remaining message blocks
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    /* For i=b,...,m-1 do */
    while (CLength > STATESIZE)
    {
        /* M <- M || (V_h+i-1 xor CEC_i) */
        xorbuf(OutputPointer, CPointer, (uint8_t*)State, STATESIZE);
        /* V_h+i <- f(V_h+i-1, (KEC xor M_i')) */
        xorbuf(XorBuffer, OutputPointer, KeyPointer, STATESIZE);
        SHA256::Transform(State, (word32*)XorBuffer);
        CPointer += STATESIZE;
        OutputPointer += STATESIZE;
        CLength -= STATESIZE;
    }

    /* M <- M || (V_h+m-1 xor CEC_m) */
    xorbuf(OutputPointer, CPointer, (uint8_t*)State, CLength);
    /* M_m', M_m+1' <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    word32 MessageSuf[2 * BLOCKUNITSIZE] = {0};
    memcpy(MessageSuf, OutputPointer, CLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = Message.size();
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)) / sizeof(word32), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)) / sizeof(word32), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKUNITSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKUNITSIZE, KeyPointer, BLOCKUNITSIZE);
    /* B_EC <- f+(V_h+m-1, (K_EC xor M_m') || (K_EC xor M_m+1')) */
    SHA256::Transform(State, MessageSuf);
    SHA256::Transform(State, MessageSuf + BLOCKUNITSIZE);
    /* If B_EC' != B_EC then Return 0 */
    string BECNew(State, State + STATEUNITSIZE);
    if (BEC.compare(BECNew))
    {
        memset(Message.data(), 0x00, Message.size());
        return false;
    }
    return true;
}

bool AltPad_SHA256_HFC::EVer(const string& Header,
                      const string& Message,
                      const string& KEC,
                      const string& BEC)
{
    CheckInput(KEC.size());
    uint32_t BLOCKSIZE = GetBlockSize();
    uint32_t STATESIZE = GetStateSize();
    uint32_t BLOCKUNITSIZE = BLOCKSIZE / sizeof(word32);
    uint32_t STATEUNITSIZE = STATESIZE / sizeof(word32);
    uint32_t PadDiff = BLOCKSIZE - STATESIZE;
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    const unsigned char* KeyPointerPad = KeyPointer + PadDiff;
    // Initialize state with IV
    word32 State[STATEUNITSIZE];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    SHA256::Transform(State, (word32*)KeyPointer);
    /* Vh <- f+(V0, (KEC xor Hb) || ... || (KEC xor Hh)) */
    uint8_t XorBuffer[BLOCKSIZE];
    // We use the block M_m for the last padding with SufPad
    // therefore we cannot pad it with the header
    uint32_t HLength = Header.size();
    uint32_t MBlocks = Message.size() != 0 ? (ceil((float)Message.size() / STATESIZE) - 1) : 0;
    uint32_t HBlocks = ceil((float)Header.size() / PadDiff);
    if (HBlocks > MBlocks)
    {
        uint32_t HLengthR = Header.size() - (MBlocks * PadDiff);
        HLength -= HLengthR;
        const uint8_t *HPointer = (const uint8_t*)(Header.data() + (Header.size() - HLengthR));
        while (HLengthR >= BLOCKSIZE)
        {
            xorbuf(XorBuffer, HPointer, KeyPointer, BLOCKSIZE);
            SHA256::Transform(State, (word32*)XorBuffer);
            HPointer += BLOCKSIZE;
            HLengthR -= BLOCKSIZE;
        }
        memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
        xorbuf(XorBuffer, HPointer, HLengthR);
        SHA256::Transform(State, (word32*)XorBuffer);
    }

    uint32_t MLength = Message.size();
    const uint8_t *MPointer = (const uint8_t*)Message.data();
    // Use the header blocks to pad message
    uint8_t *XorBufferPad = XorBuffer + PadDiff;
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    /* For i=1,...,b do */
    while (HLength >= PadDiff)
    {
        /* V_h+i <- f(V_h+i-1, (KEC xor M_i')) */
        xorbuf(XorBuffer, MPointer, KeyPointer, STATESIZE);
        xorbuf(XorBufferPad, HPointer, KeyPointerPad, PadDiff);
        SHA256::Transform(State, (word32*)XorBuffer);
        MPointer += STATESIZE;
        MLength -= STATESIZE;
        HLength -= PadDiff;
    }
    // If last block of header is not exact (d-n) bits long
    if (HLength > 0)
    {
        /* V_h+i <- f(V_h+b-1, (KEC xor M_b')) */
        memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
        xorbuf(XorBuffer, MPointer, KeyPointer, STATESIZE);
        xorbuf(XorBufferPad, HPointer, KeyPointerPad, HLength);
        SHA256::Transform(State, (word32*)XorBuffer);
        MPointer += STATESIZE;
        MLength -= STATESIZE;
    }
    // Use zero padding for the remaining message blocks
    memcpy(XorBuffer, KeyPointer, BLOCKSIZE);
    /* For i=b,...,m-1 do */
    while (MLength > STATESIZE)
    {
        /* V_h+i <- f(V_h+i-1, (KEC xor M_i')) */
        xorbuf(XorBuffer, MPointer, KeyPointer, STATESIZE);
        SHA256::Transform(State, (word32*)XorBuffer);
        MPointer += STATESIZE;
        MLength -= STATESIZE;
    }

    /* M_m', M_m+1' <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    word32 MessageSuf[2 * BLOCKUNITSIZE] = {0};
    memcpy(MessageSuf, MPointer, MLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = Message.size();
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)) / sizeof(word32), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)) / sizeof(word32), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKUNITSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKUNITSIZE, KeyPointer, BLOCKUNITSIZE);
    /* B_EC <- f+(V_h+m-1, (K_EC xor M_m') || (K_EC xor M_m+1')) */
    SHA256::Transform(State, MessageSuf);
    SHA256::Transform(State, MessageSuf + BLOCKUNITSIZE);
    /* If B_EC' != B_EC then Return 0 */
    string BECNew(State, State + STATEUNITSIZE);
    if (BEC.compare(BECNew))
    {
        return false;
    }
    return true;
}

const string& AltPad_SHA256_HFC::GetClassDecription()
{
    return cClassDescription;
}

uint32_t AltPad_SHA256_HFC::GetBlockSize()
{
    return 64;
}

uint32_t AltPad_SHA256_HFC::GetStateSize()
{
    return 32;
}
