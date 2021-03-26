#include <iostream>
using namespace std;

#include "../AEAD/AES_GCM.h"
#include "../Tester.h"

class TestAESGCM: public Tester
{
public:
    TestAESGCM(uint32_t Iterations,
               string& Logfile,
               string& Key,
               string& Nonce,
               string& Header,
               string& Message,
               AES_GCM* GCM):
        Tester(Iterations, Logfile),
        mKey(Key),
        mNonce(Nonce),
        mM(ReadImage(Message)),
        mH(ReadImage(Header)),
        mC(mM.size(), '0'),
        mGCM(GCM)
    {}
    ~TestAESGCM()
    {
        delete mGCM;
    }
    bool TestRound()
    {
        IncreaseString(mNonce);
        // Encryption
        StartTime(0);
        mGCM->Enc(mKey, mNonce, mH, mM, mC);
        AddTime(0);
        // Decryption
        StartTime(1);
        bool Success = mGCM->Dec(mKey, mNonce, mH, mC, mM);
        AddTime(1);
        if (!Success)
        {
            return false;
        }
        return true;
    }

private:
    string mKey;
    string mNonce;
    string mM;
    string mH;
    string mC;
    AES_GCM* mGCM;
};

int main(int argc, char** argv)
{
    AES_GCM* GCM = new AES_GCM();
    uint32_t TestIterations = 200;
    string Logfile = "LogUnitTests.txt";
    string TestKey(GCM->GetKeySize(), 'a');
    string TestNonce(GCM->GetBlockSize(), 'b');
    string TestHeader = "";
    string TestImage = "../Images/big.jpg";
    if (argc > 1)
    {
        TestImage = string(argv[1]);
    }
    try
    {
        TestAESGCM Test(TestIterations,
                        Logfile,
                        TestKey,
                        TestNonce,
                        TestHeader,
                        TestImage,
                        GCM);
        uint32_t i;
        for (i = 1;Test.TestRound() && i < TestIterations; i++);
        Test.PrintTime(i, 0, GCM->GetClassDecription() + " encryption");
        Test.PrintTime(i, 1, GCM->GetClassDecription() + " decryption");
        Test.HandleOutput("", false);
    }
    catch (const exception& e)
    {
        cout << e.what() << endl;
        return 0;
    }
}
