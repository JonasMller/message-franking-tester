#include <iostream>
#include <sstream>
#include <fstream>
using namespace std;

#include <cryptopp/osrng.h>
using namespace CryptoPP;

#include "ConfigParser.h"
#include "ICEScheme.h"
#include "Tester.h"

/* A really simple "kind of" xml parser 
 * for creating the tester to test different schemes
 * ConfigName: Path to the config file to read
*/
SchemeTester* ConfigParser::ReadConfig(const string& ConfigName)
{
    ifstream ConfigFile;
    ConfigFile.open(ConfigName);
    if(ConfigFile.is_open())
    {
        // Read the whole content of the config file to a string
        // This is reasonable because the config files are pretty small
        stringstream ConfigContent;
        ConfigContent << ConfigFile.rdbuf();
        string Content(ConfigContent.str());
        // Remove all comments from the xml file
        Content = RemoveXMLComments(Content);
        // Get the content inside the Tester tag
        Content = ReadToken(Content, {"Tester"});
        // Construct the Tester class from the config
        string IterationsString = ReadToken(Content, {"Iterations"});
        uint32_t Iterations = StringToInt(IterationsString);
        string Logfile = ReadToken(Content, {"Logfile"});
        string Token = "";
        string Key = ReadToken(Content, {"Key", "Keysize"}, Token);
        if("Keysize" == Token)
        {
            Key = GenerateRandomString(Key);
        }
        string Nonce = ReadToken(Content, {"Nonce", "Noncesize"}, Token);
        if("Noncesize" == Token)
        {
            Nonce = GenerateRandomString(Nonce);
        }
        string Header = ReadToken(Content, {"Header"});
        string Message = ReadToken(Content, {"Message"});
        ICEScheme* Scheme = ReadScheme(Content);
        return new SchemeTester(Iterations,
                                Logfile,
                                Key,
                                Nonce,
                                Header,
                                Message,
                                Scheme);
    }
    throw runtime_error("Could not open file: " + ConfigName);
}

string ConfigParser::RemoveXMLComments(const string& ConfigString)
{
    string ReturnConfig = ConfigString;
    string CommentBegin = "<!--";
    string CommentEnd = "-->";
    size_t First = ReturnConfig.find(CommentBegin);
    while(First != string::npos)
    {
        size_t Last = ReturnConfig.find(CommentEnd);
        ReturnConfig.erase(First, Last - First + CommentEnd.size());
        First = ReturnConfig.find(CommentBegin);
    }
    return ReturnConfig;
}

string ConfigParser::ReadToken(const string& ConfigString,
                               vector<string> Tokens)
{
    for(string Token: Tokens)
    {
        size_t First = ConfigString.find("<" + Token + ">");
        size_t Last = ConfigString.find("</" + Token + ">");
        if(First != string::npos && Last != string::npos && First < Last)
        {
            First += Token.size() + 2;
            return ConfigString.substr(First, Last - First);
        }
    }
    string TokenString = "[";
    for(string Token: Tokens)
    {
        TokenString += "<" + Token + ">" + ", ";
    }
    TokenString += "]";
    throw runtime_error("Could not find " + TokenString + " in config file");
}

string ConfigParser::ReadToken(const string& ConfigString,
                               vector<string> Tokens,
                               string& SuccessToken)
{
    for(string Token: Tokens)
    {
        size_t First = ConfigString.find("<" + Token + ">");
        size_t Last = ConfigString.find("</" + Token + ">");
        if(First != string::npos && Last != string::npos && First < Last)
        {
            First += Token.size() + 2;
            SuccessToken.assign(Token);
            return ConfigString.substr(First, Last - First);
        }
    }
    string TokenString = "[";
    for(string Token: Tokens)
    {
        TokenString += "<" + Token + ">" + ", ";
    }
    TokenString += "]";
    throw runtime_error("Could not find " + TokenString + " in config file");
}

ICEScheme* ConfigParser::ReadScheme(const string& ConfigString)
{
    vector<string> SchemeToken{"CEP", "CtE1", "CtE2", "CETransform"};
    string SchemeString = ReadToken(ConfigString, {"Scheme"});
    string Token = "";
    string SchemeConfig = ReadToken(SchemeString, SchemeToken, Token);
    if ("CEP" == Token)
    {
        string Hash = ReadToken(SchemeConfig, {"Hash"});
        string HashCr = ReadToken(SchemeConfig, {"HashCr"});
        string PRG = ReadToken(SchemeConfig, {"PRG"});
        return mFactory.CreateCEP(Hash, HashCr, PRG);
    }
    if ("CtE1" == Token)
    {
        string Hash = ReadToken(SchemeConfig, {"Hash"});
        return mFactory.CreateCtE1(Hash, ReadAEAD(SchemeConfig));
    }
    if ("CtE2" == Token)
    {
        string Hash = ReadToken(SchemeConfig, {"Hash"});
        return mFactory.CreateCtE2(Hash, ReadAEAD(SchemeConfig));
    }
    if ("CETransform" == Token)
    {
        string HFC = ReadToken(SchemeConfig, {"HFC"});
        return mFactory.CreateCETransform(HFC, ReadAEAD(SchemeConfig));
    }
    string TokenString = "[";
    for(string Token: SchemeToken)
    {
        TokenString += "<" + Token + ">" + ", ";
    }
    TokenString += "]";
    throw runtime_error("Could not find " + TokenString + " in config file");
}

IAEADScheme* ConfigParser::ReadAEAD(const string& ConfigString)
{
    vector<string> AEADToken{"EtM", "AES_GCM"};
    string AEADString = ReadToken(ConfigString, {"AEAD"});
    string Token = "";
    string AEADConfig = ReadToken(AEADString, AEADToken, Token);
    if ("EtM" == Token)
    {
        string Hash = ReadToken(AEADConfig, {"Hash"});
        string Encryption = ReadToken(AEADConfig, {"Encryption"});
        return mFactory.CreateEtM(Hash, Encryption);
    }
    if ("AES_GCM" == Token)
    {
        return mFactory.CreateAESGCM();
    }
    string TokenString = "[";
    for(string Token: AEADToken)
    {
        TokenString += "<" + Token + ">" + ", ";
    }
    TokenString += "]";
    throw runtime_error("Could not find " + TokenString + " in config file");
}

string ConfigParser::GenerateRandomString(const string& NumberString)
{
    AutoSeededRandomPool Rnd;
    uint32_t Size = StringToInt(NumberString);
    SecByteBlock Buffer(0x00, Size);
    Rnd.GenerateBlock(Buffer, Buffer.size());
    string Key((const char*)Buffer.data(), Buffer.size());
    return Key;
}

uint32_t ConfigParser::StringToInt(const string& NumberString)
{
    if (!Is_Number(NumberString))
    {
        throw runtime_error("Not a valid number");
    }
    if (NumberString.size() > 9)
    {
        throw runtime_error("Number is too large");
    }
    return stoi(NumberString);
}

bool ConfigParser::Is_Number(const string& NumberString)
{
    string::const_iterator It = NumberString.begin();
    while (It != NumberString.end() && isdigit(*It))
    {
        ++It; 
    }
    return !NumberString.empty() && It == NumberString.end();
}
