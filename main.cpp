#include <iostream>
using namespace std;

#include "ConfigParser.h"
#include "Tester.h"

int main(int argc, char** argv)
{
    try
    {
        // Check if second argument was provided
        if(argc < 2)
        {
            string ProgramName(argv[0]);
            string Output = string("Need to provide config file.\n")
                            + "Usage " + ProgramName + " [path to config file]";
            cout << Output << endl;
            return 0;
        }
        string InputFile(argv[1]);
        // Parse the second argument
        ConfigParser Parser;
        SchemeTester* Test = NULL;
        Test = Parser.ReadConfig(InputFile);
        Test->PrintCommand(argc, argv);
        // Get the number of iterations from the Tester
        uint32_t Iterations = Test->GetTestIterations();
        uint32_t i = 0;
        // Test the scheme with the Tester
        for (i = 1; Test->TestRound() && i < Iterations; i++);
        // Check if every run was successful
        if (i != Iterations)
        {
            string Output = string("Only ") + to_string(i) + " out of " 
                            + to_string(Iterations) + " were successful.";
            Test->HandleOutput(Output);
        }
        // Print the times from the tester
        // ToDo: Put the handling into the tester
        Test->HandleOutput("");
        Test->PrintTime(i, 0, "Encryption");
        Test->HandleOutput("");
        Test->PrintTime(i, 1, "Decryption");
        Test->HandleOutput("");
        Test->PrintTime(i, 2, "Verification");
        delete Test;
    }
    catch (const exception& e)
    {
        cout << e.what() << endl;
        return 0;
    }
}
