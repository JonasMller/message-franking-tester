using namespace std;

#include <cryptopp/cryptlib.h>
#include <cryptopp/misc.h>
using namespace CryptoPP;

#include "SHA3_HFC.h"

NAMESPACE_BEGIN(CryptoPP)
// The Keccak core function
extern void KeccakF1600(word64 *state);
NAMESPACE_END

void SHA3_HFC::EC(const string& KEC,
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
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    // Initialize state with IV
    word64 State[GetStateSize() / sizeof(word64)];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    xorbuf((uint8_t*)State, KeyPointer, BLOCKSIZE);
    KeccakF1600(State);
    /* Vh <- f+(V0, H1 || ... || Hh) */
    uint32_t HLength = Header.size();
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    while (HLength >= BLOCKSIZE)
    {
        xorbuf((uint8_t*)State, HPointer, BLOCKSIZE);
        KeccakF1600(State);
        HPointer += BLOCKSIZE;
        HLength -= BLOCKSIZE;
    }
    xorbuf((uint8_t*)State, HPointer, HLength);
    KeccakF1600(State);

    /* C_EC <- e */
    uint32_t MLength = MessageSize;
    CEC.resize(MLength);
    uint8_t *OutputPointer = (uint8_t*)CEC.data();
    const uint8_t *MPointer = (const uint8_t*)Message;
    /* For i=1,...,m-1 do */
    while (MLength > BLOCKSIZE)
    {
        /* C_EC <- C_EC || (V_h+i-1 xor M_i) */
        xorbuf(OutputPointer, MPointer, (uint8_t*)State, BLOCKSIZE);
        /* V_h+i <- f(V_h+i-1, M_i) */
        xorbuf((uint8_t*)State, MPointer, BLOCKSIZE);
        KeccakF1600(State);
        MPointer += BLOCKSIZE;
        OutputPointer += BLOCKSIZE;
        MLength -= BLOCKSIZE;
    }

    /* C_EC <- C_EC || (V_h+m-1 xor M_m) */
    xorbuf(OutputPointer, MPointer, (uint8_t*)State, MLength);
    /* M_m, M_m+1 <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    uint8_t MessageSuf[2 * BLOCKSIZE] = {0};
    memcpy(MessageSuf, MPointer, MLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = MessageSize;
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKSIZE, KeyPointer, BLOCKSIZE);
    /* B_EC <- f+(V_h+m-1, M_m || M_m+1) */
    xorbuf((uint8_t*)State, MessageSuf, BLOCKSIZE);
    KeccakF1600(State);
    xorbuf((uint8_t*)State, MessageSuf + BLOCKSIZE, BLOCKSIZE);
    KeccakF1600(State);
    /* Return (C_EC, B_EC), C_EC is already constructed */
    BEC.assign(State, State + (GetStateSize() / sizeof(word64)));
    return;
}

bool SHA3_HFC::DO(const string& KEC,
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
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    // Initialize state with IV
    word64 State[GetStateSize() / sizeof(word64)];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    xorbuf((uint8_t*)State, KeyPointer, BLOCKSIZE);
    KeccakF1600(State);
    /* Vh <- f+(V0, H1 || ... || Hh) */
    uint32_t HLength = Header.size();
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    while (HLength >= BLOCKSIZE)
    {
        xorbuf((uint8_t*)State, HPointer, BLOCKSIZE);
        KeccakF1600(State);
        HPointer += BLOCKSIZE;
        HLength -= BLOCKSIZE;
    }
    xorbuf((uint8_t*)State, HPointer, HLength);
    KeccakF1600(State);

    /* C_EC <- e */
    uint32_t CLength = CECSize;
    Message.resize(CLength);
    uint8_t *OutputPointer = (uint8_t*)Message.data();
    const uint8_t *CPointer = (const uint8_t*)CEC;
    /* For i=1,...,m-1 do */
    while (CLength > BLOCKSIZE)
    {
        /* M <- M || (V_h+i-1 xor CEC_i) */
        xorbuf(OutputPointer, CPointer, (uint8_t*)State, BLOCKSIZE);
        /* V_h+i <- f(V_h+i-1, M_i) */
        xorbuf((uint8_t*)State, OutputPointer, BLOCKSIZE);
        KeccakF1600(State);
        CPointer += BLOCKSIZE;
        OutputPointer += BLOCKSIZE;
        CLength -= BLOCKSIZE;
    }

    /* C_EC <- C_EC || (V_h+m-1 xor M_m) */
    xorbuf(OutputPointer, CPointer, (uint8_t*)State, CLength);
    /* M_m, M_m+1 <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    uint8_t MessageSuf[2 * BLOCKSIZE] = {0};
    memcpy(MessageSuf, OutputPointer, CLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = Message.size();
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKSIZE, KeyPointer, BLOCKSIZE);
    /* B_EC <- f+(V_h+m-1, M_m || M_m+1) */
    xorbuf((uint8_t*)State, MessageSuf, BLOCKSIZE);
    KeccakF1600(State);
    xorbuf((uint8_t*)State, MessageSuf + BLOCKSIZE, BLOCKSIZE);
    KeccakF1600(State);
    /* If B_EC' != B_EC then Return 0 */
    string BECNew(State, State + (GetStateSize() / sizeof(word64)));
    if (BEC.compare(BECNew))
    {
        memset(Message.data(), 0x00, Message.size());
        return false;
    }
    return true;
}

bool SHA3_HFC::EVer(const string& Header,
                    const string& Message,
                    const string& KEC,
                    const string& BEC)
{
    CheckInput(KEC.size());
    uint32_t BLOCKSIZE = GetBlockSize();
    const unsigned char* KeyPointer = (const unsigned char*)KEC.data();
    // Initialize state with IV
    word64 State[GetStateSize() / sizeof(word64)];
    memcpy(State, mIV.data(), mIV.size());
    /* V0 <- f(IV, KEC) */
    xorbuf((uint8_t*)State, KeyPointer, BLOCKSIZE);
    KeccakF1600(State);
    /* Vh <- f+(V0, H1 || ... || Hh) */
    uint32_t HLength = Header.size();
    const uint8_t *HPointer = (const uint8_t*)Header.data();
    while (HLength >= BLOCKSIZE)
    {
        xorbuf((uint8_t*)State, HPointer, BLOCKSIZE);
        KeccakF1600(State);
        HPointer += BLOCKSIZE;
        HLength -= BLOCKSIZE;
    }
    xorbuf((uint8_t*)State, HPointer, HLength);
    KeccakF1600(State);

    /* V_m-1 <- f+(V0, M_1 || ... || M_m-1) */
    uint32_t MLength = Message.size();
    const uint8_t *MPointer = (const uint8_t*)Message.data();
    while (MLength > BLOCKSIZE)
    {
        xorbuf((uint8_t*)State, MPointer, BLOCKSIZE);
        KeccakF1600(State);
        MPointer += BLOCKSIZE;
        MLength -= BLOCKSIZE;
    }

    /* M_m, M_m+1 <- Parse_d(PadSuf(|H|, |M|, M_m)) */
    uint8_t MessageSuf[2 * BLOCKSIZE] = {0};
    memcpy(MessageSuf, MPointer, MLength);
    uint64_t HSize = Header.size();
    uint64_t MSize = Message.size();
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(HSize) - sizeof(MSize)), &HSize, sizeof(HSize));
    memcpy(MessageSuf + (sizeof(MessageSuf) - sizeof(MSize)), &MSize, sizeof(MSize));
    xorbuf((unsigned char*)MessageSuf, KeyPointer, BLOCKSIZE);
    xorbuf((unsigned char*)MessageSuf + BLOCKSIZE, KeyPointer, BLOCKSIZE);
    /* B_EC <- f+(V_h+m-1, M_m || M_m+1) */
    xorbuf((uint8_t*)State, MessageSuf, BLOCKSIZE);
    KeccakF1600(State);
    xorbuf((uint8_t*)State, MessageSuf + BLOCKSIZE, BLOCKSIZE);
    KeccakF1600(State);
    /* If B_EC' != B_EC then Return 0 */
    string BECNew(State, State + (GetStateSize() / sizeof(word64)));
    if (BEC.compare(BECNew))
    {
        return false;
    }
    return true;
}

const string& SHA3_HFC::GetClassDecription()
{
    return cClassDescription;
}

uint32_t SHA3_HFC::GetBlockSize()
{
    return 1088/8;
}

uint32_t SHA3_HFC::GetStateSize()
{
    return 1600/8;
}
