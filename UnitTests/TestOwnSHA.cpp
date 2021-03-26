#include <iostream>
using namespace std;

#include <cryptopp/cryptlib.h>
#include <cryptopp/misc.h>
#include <cryptopp/sha.h>
using namespace CryptoPP;

#include "../Tester.h"

class TestOwnSHA: public Tester, public SHA256
{
public:
    TestOwnSHA(uint32_t Iterations,
               string& Logfile,
               string& Header,
               string& Message):
        Tester(Iterations, Logfile),
        mH(ReadImage(Header)),
        mM(ReadImage(Message))
    {}
    ~TestOwnSHA()
    {}
    bool TestRound()
    {
        StartTime(0);
        word32 State[32 / sizeof(word32)];
        const uint32_t BLOCKSIZE = 64;
        // Process header
        uint32_t HLength = mH.size();
        const uint8_t *HPointer = (const uint8_t*)mH.data();
        while (HLength >= BLOCKSIZE)
        {
            SHA256::Transform(State, (const word32*)HPointer);
            HPointer += BLOCKSIZE;
            HLength -= BLOCKSIZE;
        }
        uint8_t XorBuffer[BLOCKSIZE] = {0};
        memcpy(XorBuffer, HPointer, HLength);
        SHA256::Transform(State, (word32*)XorBuffer);
        // Process message
        uint32_t MLength = mM.size();
        const uint8_t *MPointer = (const uint8_t*)mM.data();
        while (MLength > BLOCKSIZE)
        {
            SHA256::Transform(State, (const word32*)MPointer);
            MPointer += BLOCKSIZE;
            MLength -= BLOCKSIZE;
        }
        uint8_t Buffer[BLOCKSIZE] = {0};
        memcpy(Buffer, MPointer, MLength);
        SHA256::Transform(State, (word32*)Buffer);
        AddTime(0);
        return true;
    }

private:
    string mH;
    string mM;
};

int main(int argc, char** argv)
{
    uint32_t TestIterations = 200;
    string Logfile = "LogUnitTests.txt";
    string TestHeader = "";
    string TestImage = "../images/big.jpg";
    if (argc > 1)
    {
        TestImage = string(argv[1]);
    }
    try
    {
        TestOwnSHA Test(TestIterations,
                        Logfile,
                        TestHeader,
                        TestImage);
        uint32_t i;
        for (i = 1;Test.TestRound() && i < TestIterations; i++);
        Test.PrintTime(i, 0, "Own SHA");
        Test.HandleOutput("", false);
    }
    catch (const exception& e)
    {
        cout << e.what() << endl;
        return 0;
    }
}
