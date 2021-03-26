#include <iostream>
using namespace std;

#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
using namespace CryptoPP;

#include "../Tester.h"

class TestPRG: public Tester
{
public:
    TestPRG(uint32_t Iterations,
            string& Logfile,
            string& Key,
            string& Nonce,
            string& Message,
            SymmetricCipher* PRG):
        Tester(Iterations, Logfile),
        mKey(Key),
        mNonce(Nonce),
        mM(ReadImage(Message)),
        mP(mM.size(), '0'),
        mPRG(PRG)
    {}
    ~TestPRG()
    {
        delete mPRG;
    }
    bool TestRound()
    {
        // Create P
        StartTime(0);
        mPRG->SetKeyWithIV((const unsigned char*)mKey.data(), mKey.size(),
                           (const unsigned char*)mNonce.data(), mNonce.size());
        StreamTransformationFilter Encryptor(mPRG->Ref(), NULL);
        Encryptor.Put((unsigned char*)mM.data(), mM.size());
        Encryptor.MessageEnd();
        // Remove data from filter
        size_t PadSize = (size_t)-1;
        PadSize = Encryptor.MaxRetrievable();
        if (PadSize > 0)
        {
            mP.resize(PadSize);
            Encryptor.Get((unsigned char*)mP.data(), mP.size());
        }
        AddTime(0);
        // Increase nonce
        IncreaseString(mNonce);
        return true;
    }

private:
    string mKey;
    string mNonce;
    string mM;
    string mP;
    SymmetricCipher* mPRG;
};

int main(int argc, char** argv)
{
    SymmetricCipher* PRG = new CTR_Mode<AES>::Encryption();
    uint32_t TestIterations = 200;
    string Logfile = "LogUnitTests.txt";
    string TestKey(PRG->DefaultKeyLength(), 'a');
    string TestNonce(PRG->OptimalBlockSize(), 'b');
    string TestImage = "../Images/big.jpg";
    if (argc > 1)
    {
        TestImage = string(argv[1]);
    }
    try
    {
        TestPRG Test(TestIterations,
                     Logfile,
                     TestKey,
                     TestNonce,
                     TestImage,
                     PRG);
        uint32_t i;
        for (i = 1;Test.TestRound() && i < TestIterations; i++);
        Test.PrintTime(i, 0, PRG->AlgorithmName() + " randomness for message");
        Test.HandleOutput("", false);
    }
    catch (const exception& e)
    {
        cout << e.what() << endl;
        return 0;
    }
}
