#include <iostream>
using namespace std;

#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
using namespace CryptoPP;

#include "../Tester.h"

class TestSHA256: public Tester
{
public:
    TestSHA256(uint32_t Iterations,
               string& Logfile,
               string& Header,
               string& Message,
               HashTransformation* Hash):
        Tester(Iterations, Logfile),
        mH(ReadImage(Header)),
        mM(ReadImage(Message)),
        mHash(Hash)
    {}
    ~TestSHA256()
    {
        delete mHash;
    }
    bool TestRound()
    {
        string Output;
        StartTime(0);
        StringSource(mM, true, new HashFilter(mHash->Ref(), new StringSink(Output)));
        AddTime(0);

        return true;
    }

private:
    string mH;
    string mM;
    HashTransformation* mHash;
};

int main(int argc, char** argv)
{
    SHA256* Hash = new SHA256();
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
        TestSHA256 Test(TestIterations,
                        Logfile,
                        TestHeader,
                        TestImage,
                        Hash);
        uint32_t i;
        for (i = 1;Test.TestRound() && i < TestIterations; i++);
        Test.PrintTime(i, 0, Hash->AlgorithmName());
        Test.HandleOutput("", false);
    }
    catch (const exception& e)
    {
        cout << e.what() << endl;
        return 0;
    }
}
