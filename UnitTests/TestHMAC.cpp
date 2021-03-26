#include <iostream>
using namespace std;

#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/hmac.h>
using namespace CryptoPP;

#include "../Tester.h"

class TestHMAC: public Tester
{
public:
    TestHMAC(uint32_t Iterations,
             string& Logfile,
             string& Key,
             string& Header,
             string& Message,
             MessageAuthenticationCode* MAC):
        Tester(Iterations, Logfile),
        mKey(Key),
        mH(ReadImage(Header)),
        mM(ReadImage(Message)),
        mMAC(MAC)
    {
        mMAC->SetKey((unsigned char*)mKey.data(), mKey.size());
    }
    ~TestHMAC()
    {
        delete mMAC;
    }
    bool TestRound()
    {
        string Output;
        StartTime(0);
        mMAC->Update((const unsigned char*)mH.data(), mH.size());
        mMAC->Update((const unsigned char*)mM.data(), mM.size());
        Output.resize(mMAC->DigestSize());
        mMAC->Final((unsigned char*)Output.data());
        AddTime(0);
        return true;
    }

private:
    string mKey;
    string mH;
    string mM;
    MessageAuthenticationCode* mMAC;
};

int main(int argc, char** argv)
{
    HMAC<SHA256>* MAC = new HMAC<SHA256>();
    uint32_t TestIterations = 200;
    string Logfile = "LogUnitTests.txt";
    string TestKey(MAC->DefaultKeyLength(), 'a');
    string TestHeader = "";
    string TestImage = "../Images/big.jpg";
    if (argc > 1)
    {
        TestImage = string(argv[1]);
    }
    try
    {
        TestHMAC Test(TestIterations,
                      Logfile,
                      TestKey,
                      TestHeader,
                      TestImage,
                      MAC);
        uint32_t i;
        for (i = 1;Test.TestRound() && i < TestIterations; i++);
        Test.PrintTime(i, 0, MAC->AlgorithmName());
        Test.HandleOutput("", false);
    }
    catch (const exception& e)
    {
        cout << e.what() << endl;
        return 0;
    }
}
