#include <iostream>
using namespace std;

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
using namespace CryptoPP;

#include "../AEAD/EtM.h"
#include "../Tester.h"

class TestEtM: public Tester
{
public:
    TestEtM(uint32_t Iterations,
            string& Logfile,
            string& Key,
            string& Nonce,
            string& Header,
            string& Message,
            EtM* AEAD):
        Tester(Iterations, Logfile),
        mKey(Key),
        mNonce(Nonce),
        mM(ReadImage(Message)),
        mH(ReadImage(Header)),
        mC(mM.size(), '0'),
        mEtM(AEAD)
    {}
    ~TestEtM()
    {
        delete mEtM;
    }
    bool TestRound()
    {
        // Encryption
        StartTime(0);
        mEtM->Enc(mKey, mNonce, mH, mM, mC);
        AddTime(0);
        // Decryption
        StartTime(1);
        bool Success = mEtM->Dec(mKey, mNonce, mH, mC, mM);
        AddTime(1);
        if (!Success)
        {
            return false;
        }
        IncreaseString(mNonce);
        return true;
    }

private:
    string mKey;
    string mNonce;
    string mM;
    string mH;
    string mC;
    EtM* mEtM;
};

int main(int argc, char** argv)
{
    EtM* AEAD = new EtM(new HMAC<SHA256>(), new CBC_Mode<AES>::Encryption(), new CBC_Mode<AES>::Decryption());
    uint32_t TestIterations = 200;
    string Logfile = "LogUnitTests.txt";
    string TestKey(AEAD->GetKeySize(), 'a');
    string TestNonce(AEAD->GetBlockSize(), 'b');
    string TestHeader = "";
    string TestImage = "../Images/big.jpg";
    if (argc > 1)
    {
        TestImage = string(argv[1]);
    }
    try
    {
        TestEtM Test(TestIterations,
                     Logfile,
                     TestKey,
                     TestNonce,
                     TestHeader,
                     TestImage,
                     AEAD);
        uint32_t i;
        for (i = 1;Test.TestRound() && i < TestIterations; i++);
        Test.PrintTime(i, 0, AEAD->GetClassDecription() + " encryption");
        Test.PrintTime(i, 1, AEAD->GetClassDecription() + " decryption");
        Test.HandleOutput("", false);
    }
    catch (const exception& e)
    {
        cout << e.what() << endl;
        return 0;
    }
}
