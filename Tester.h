#ifndef TESTER_H
#define TESTER_H

#include <string>
#include <vector>
#include <chrono>

#include "ICEScheme.h"

/// \brief Timer class provides necessary time measurement functions
class Timer
{
public:
	/// \brief Construct a Timer
    Timer() {}
    /// \brief Destruct a Tester
    /// \details Need to delete the scheme provided by the SchemeFactory
    virtual ~Timer() {}
    /// \brief Saving the time point when called
	/// \param VectorPosition can save multiple timepoints in a vector at this position
    void StartTime(uint8_t VectorPosition = 0);
    /// \brief Add the time from start
	/// \param VectorPosition adds the time to the position in vector
    void AddTime(uint8_t VectorPosition = 0);
    /// \brief Get the time for the specified position
	/// \param VectorPosition position in vector to get the overall added time
    double GetTime(uint8_t VectorPosition = 0);
    /// \brief Prints the time
	/// \param TestRounds the number of iterations that were successful
	/// \param VectorPosition the vector position for the time
	/// \param Description adds a description to the output
    /// \details It calculates the average time and prints results with the description
    virtual void PrintTime(uint32_t TestRounds = 1, uint8_t VectorPosition = 0, std::string Description = "");

protected:
    std::vector<std::chrono::high_resolution_clock::time_point> mStartTimes;
    std::vector<std::chrono::nanoseconds> mDurations;
};

/// \brief Tester class which has everything to analyse the timing of the provided scheme
/// \details The Tester measures the time, increases the nonce, handles the logfile,
/// reads the images if a path is provided and executes the schemes
class Tester: public Timer
{
public:
	/// \brief Construct a Tester
	/// \param Iterations number of enc, dec and ver for a run
	/// \param Logfile path of the logfile
    Tester(uint32_t Iterations,
           std::string& Logfile);
    /// \brief Destruct a Tester
    /// \details Need to delete the scheme provided by the SchemeFactory
    virtual ~Tester() {}
    /// \brief Function to call for testing
    virtual bool TestRound();
    /// \brief Read image data to string
	/// \param File path to an image
    /// \details If the File is not a valid path to an image we will 
    /// return File string instead
    std::string ReadImage(const std::string& File);
    /// \brief Writes data to an image
	/// \param OutputFile path to the image where to store the data
	/// \param OutputData data to store in the file
    bool WriteImage(const std::string& OutputFile, std::string& OutputData);
    /// \brief Increase the Data string by one
	/// \param Data reference to the string to increase
    void IncreaseString(std::string& Data);
    /// \brief Logs a string to the logfile and prints it if specified
	/// \param Log data to print
	/// \param PrintOut when true the logged string will be printed to the console
    bool HandleOutput(const std::string& Log, bool PrintOut = true);
    /// \brief Prints the time
	/// \param TestRounds the number of iterations that were successful
	/// \param VectorPosition the vector position for the time
	/// \param Description adds a description to the output
    /// \details It calculates the average time and logs the output with the description
    void PrintTime(uint32_t TestRounds = 1, uint8_t VectorPosition = 0, std::string Description = "");
    /// \brief Prints the called command and the current time
	/// \param argc number of strings
	/// \param argv reference to char*
    void PrintCommand(int argc, char** argv);
    /// \brief Getter for the iterations
    uint32_t GetTestIterations();

private:
    uint32_t mIterations;
    const std::string cLogFileName;
};

/*=======================================================================================*/

/// \brief SchemeTester class which tests a provided CE scheme
/// \details The Tester measures the time, increases the nonce, handles the logfile,
/// reads the images if a path is provided and executes the schemes
class SchemeTester: public Tester
{
public:
	/// \brief Construct a SchemeTester
	/// \param Key for the scheme to test
	/// \param Nonce for the scheme to test
	/// \param Header for the tester, can be path to image or string
	/// \param Message for the tester, can be path to image or string
	/// \param CE reference to the scheme to test
    SchemeTester(uint32_t Iterations,
                 std::string& Logfile,
                 std::string& Key,
                 std::string& Nonce,
                 std::string& Header,
                 std::string& Message,
                 ICEScheme* CE);
    /// \brief Destruct a SchemeTester
    /// \details Need to delete the scheme provided by the SchemeFactory
    ~SchemeTester()
    {
        delete mCE;
    }
    /// \brief Calls enc, dec and ver of the scheme and measures time
    bool TestRound();
    /// \brief Calls enc, dec and ver of the scheme without measuring time
    bool Round();
    /// \brief Get size of the input message
    uint32_t GetMessageSize();

private:
    std::string mKey;
    std::string mNonce;
    std::string mH;
    std::string mM;
    std::string mC1;
    std::string mC2;
    std::string mKeyf;
    ICEScheme* mCE;
};

#endif
