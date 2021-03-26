#include <iostream>
using namespace std;

#include "../HFC/SHA256_HFC.h"
#include "../HFC/SHA512_HFC.h"
#include "../HFC/SHA3_HFC.h"
#include "../HFC/Whrlpool_HFC.h"
#include "../HFC/AltPad_SHA256_HFC.h"
#include "../Tester.h"

class TestHFC: public Tester
{
public:
    TestHFC(uint32_t Iterations,
            string& Logfile,
            string& Key,
            string& Header,
            string& Message,
            IHFCScheme* HFC):
        Tester(Iterations, Logfile),
        mKey(Key),
        mH(ReadImage(Header)),
        mM(ReadImage(Message)),
        mC1(mM.size(), '0'),
        mC2(""),
        mHFC(HFC)
    {}
    ~TestHFC()
    {
        delete mHFC;
    }
    bool TestRound()
    {
        // Encryption
        StartTime(0);
        mHFC->EC(mKey, mH, (unsigned char*)mM.data(), mM.size(), mC1, mC2);
        AddTime(0);
        // Decryption
        StartTime(1);
        bool Success = mHFC->DO(mKey, mH, (unsigned char*)mC1.data(), mC1.size(), mC2, mM);
        AddTime(1);
        if (!Success)
        {
            return false;
        }
        // Verification
        StartTime(2);
        Success = mHFC->EVer(mH, mM, mKey, mC2);
        AddTime(2);
        if (!Success)
        {
            return false;
        }
        return true;
    }

private:
    string mKey;
    string mH;
    string mM;
    string mC1 = "";
    string mC2 = "";
    IHFCScheme* mHFC;
};

int main(int argc, char** argv)
{
    IHFCScheme* HFC = new SHA256_HFC();
    uint32_t TestIterations = 200;
    string Logfile = "LogUnitTests.txt";
    string TestKey(HFC->GetBlockSize(), 'a');
    string TestHeader = "";
    string TestImage = "../Images/big.jpg";
    if (argc > 1)
    {
        TestImage = string(argv[1]);
    }
    try
    {
        TestHFC Test(TestIterations,
                     Logfile,
                     TestKey,
                     TestHeader,
                     TestImage,
                     HFC);
        uint32_t i;
        for (i = 1;Test.TestRound() && i < TestIterations; i++);
        Test.PrintTime(i, 0, HFC->GetClassDecription() + " encryption");
        Test.PrintTime(i, 1, HFC->GetClassDecription() + " decryption");
        Test.PrintTime(i, 2, HFC->GetClassDecription() + " verification");
        Test.HandleOutput("", false);
    }
    catch (const exception& e)
    {
        cout << e.what() << endl;
        return 0;
    }
}
