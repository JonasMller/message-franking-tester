#include <iostream>
#include <fstream>
#include <filesystem>
#include <ctime>
#include <string.h>
using namespace std;
using namespace std::chrono;

#include "Tester.h"

void Timer::StartTime(uint8_t VectorPosition)
{
    if (VectorPosition >= mStartTimes.size())
    {
        mStartTimes.resize(VectorPosition + 1);
    }
    mStartTimes[VectorPosition] = high_resolution_clock::now();
}

void Timer::AddTime(uint8_t VectorPosition)
{
    high_resolution_clock::time_point StopTime = high_resolution_clock::now();
    if (VectorPosition >= mStartTimes.size())
    {
        mStartTimes.resize(VectorPosition + 1);
    }
    if (VectorPosition >= mDurations.size())
    {
        mDurations.resize(VectorPosition + 1);
    }
    mDurations[VectorPosition] += duration_cast<nanoseconds>(StopTime - mStartTimes[VectorPosition]);
}

double Timer::GetTime(uint8_t VectorPosition)
{
    return mDurations[VectorPosition].count() / 1000000;
}

void Timer::PrintTime(uint32_t TestRounds, uint8_t VectorPosition, string Description)
{
    if (VectorPosition >= mDurations.size())
    {
        mDurations.resize(VectorPosition + 1);
    }
    double Milliseconds = mDurations[VectorPosition].count() / 1000000;
    cout << Description << " - Time taken by crypto: " << to_string((uint32_t)Milliseconds) << " milliseconds" << endl;
    cout << Description << " - Average time taken by crypto: " << to_string(Milliseconds/TestRounds) << " milliseconds" << endl;
    cout << Description << " - Average of " << to_string(TestRounds) << " test rounds" << endl;
}

/*========================================================================*/

Tester::Tester(uint32_t Iterations,
               string& Logfile):
    mIterations(Iterations),
    cLogFileName(Logfile)
{}

bool Tester::TestRound()
{
    cout << "Base function, nothing to do here." << endl;
    return true;
}

string Tester::ReadImage(const string& File)
{
    if(!filesystem::exists(File))
    {
        //throw runtime_error("File not found " + File);
        cout << "Image not found, using string: " << File << endl;
        return File;
    }
    ifstream InStream(File, ios::in | ios::binary);
    ostringstream OSS;
    OSS << InStream.rdbuf();
    return OSS.str();
}

bool Tester::WriteImage(const string& OutputFile, string& OutputData)
{
    fstream Out(OutputFile, ios::out | ios::binary);
    Out.write((char*)OutputData.data(), OutputData.size());
    Out.close();
    return true;
}

void Tester::IncreaseString(string& Data)
{
    for (uint32_t i = 0; i < Data.size(); i++)
    {
        unsigned char IncChar = static_cast<unsigned char>(Data[i] + 0x01);
        Data[i] = IncChar;
        if (IncChar != 0x00)
        {
            break;
        }
    }
    return;
}

bool Tester::HandleOutput(const string& Log, bool PrintOut)
{
    if (PrintOut)
    {
        cout << Log << endl;
    }
    fstream LogFile(cLogFileName, ios::out | ios::binary | ios::app);
    if (LogFile.is_open())
    {
        LogFile << Log << endl;
        LogFile.close();
        return true;
    }
    return false;
}

void Tester::PrintTime(uint32_t TestRounds, uint8_t VectorPosition, string Description)
{
    if (VectorPosition >= mDurations.size())
    {
        mDurations.resize(VectorPosition + 1);
    }
    double Milliseconds = mDurations[VectorPosition].count() / 1000000;
    string Output = "";
    Output = Description + " - Time taken by crypto: " + to_string((uint32_t)Milliseconds) + " milliseconds";
    HandleOutput(Output);
    Output = Description + " - Average time taken by crypto: " + to_string(Milliseconds/TestRounds) + " milliseconds";
    HandleOutput(Output);
    Output = Description + " - Average of " + to_string(TestRounds) + " test rounds";
    HandleOutput(Output);
}

void Tester::PrintCommand(int argc, char** argv)
{
    string Command = "";
    for (int i = 0; i < argc; i++)
    {
        Command += argv[i];
        Command += " ";
    }
    HandleOutput("Executed command: " + Command, false);
    // Log the current time to the logfile
    // format: weekday month  dd hh:mm:ss yyyy
    time_t tt;
    struct tm * ti;
    time(&tt);
    ti = localtime(&tt);
    char* TimeOutput = asctime(ti);
    TimeOutput[strlen(TimeOutput) - 1] = '\0';
    HandleOutput(TimeOutput, false);
}

uint32_t Tester::GetTestIterations()
{
    return mIterations;
}

/*========================================================================*/

SchemeTester::SchemeTester(uint32_t Iterations,
                           string& Logfile,
                           string& Key,
                           string& Nonce,
                           string& Header,
                           string& Message,
                           ICEScheme* CE):
    Tester(Iterations, Logfile),
    mKey(Key),
    mNonce(Nonce),
    mH(Tester::ReadImage(Header)),
    mM(Tester::ReadImage(Message)),
    mC1(""),
    mC2(""),
    mKeyf(""),
    mCE(CE)
{
    // Set parameters for the scheme to test
    mCE->SetNonce(mNonce);
    // Make gap for the Log
    HandleOutput("", false);
    HandleOutput("", false);
    // Log the class description for the scheme to test
    HandleOutput("Test scheme: " + mCE->GetClassDecription(), true);
    // Log the given parameter sizes
    HandleOutput("Key size: " + to_string(mKey.size()), false);
    HandleOutput("None size: " + to_string(mNonce.size()), false);
    // Log the input data for the scheme to test
    if (Header == mH)
    {
        HandleOutput("Use string as header: " + Header +
                     " (size: " + to_string(mH.size()) + ")"
                     ,false);
    }
    else
    {
        HandleOutput("Use image as header: " + Header +
                     " (size: " + to_string(mH.size()) + ")"
                     ,false);
    }
    if (Message == mM)
    {
        HandleOutput("Use string as message: " + Message +
                     " (size: " + to_string(mM.size()) + ")"
                     ,false);
    }
    else
    {
        HandleOutput("Use image as message: " + Message +
                     " (size: " + to_string(mM.size()) + ")"
                     ,false);
    }
    // Test round to setup the sizes for the members
    if (!Round())
    {
        throw runtime_error("Setup round failed.");
    }
}

bool SchemeTester::TestRound()
{
    // Increase Nonce
    IncreaseString(mNonce);
    mCE->SetNonce(mNonce);
    // Encryption
    StartTime(0);
    mCE->Enc(mKey, mH, mM, mC1, mC2);
    AddTime(0);
    // Decryption
    StartTime(1);
    bool Success = mCE->Dec(mKey, mH, mC1, mC2, mM, mKeyf);
    AddTime(1);
    if (!Success)
    {
        HandleOutput("Decryption has failed");
        return false;
    }
    // Verification
    StartTime(2);
    Success = mCE->Ver(mH, mM, mKeyf, mC2);
    AddTime(2);
    if (!Success)
    {
        HandleOutput("Verification has failed");
        return false;
    }
    return true;
}

bool SchemeTester::Round()
{
    // Encryption
    mCE->Enc(mKey, mH, mM, mC1, mC2);
    // Decryption
    bool Success = mCE->Dec(mKey, mH, mC1, mC2, mM, mKeyf);
    if (!Success)
    {
        HandleOutput("Decryption has failed");
        return false;
    }
    // Verification
    Success = mCE->Ver(mH, mM, mKeyf, mC2);
    if (!Success)
    {
        HandleOutput("Verification has failed");
        return false;
    }
    return true;
}

uint32_t SchemeTester::GetMessageSize()
{
    return mM.size();
}
