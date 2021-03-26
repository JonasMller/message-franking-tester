#ifndef CONFIGPARSER_H
#define CONFIGPARSER_H

#include <string>
#include <vector>

#include "SchemeFactory.h"
class ICEScheme;
class IAEADScheme;
class SchemeTester;

/// \brief ConfigParser class which parses a provided config file
/// \details It parses the config file and returns a fitting Tester
/// class which contains the declared components
class ConfigParser
{
public:
	/// \brief Construct a ConfigParser
    ConfigParser():
        mFactory()
    {}
	/// \brief Destruct a ConfigParser
    ~ConfigParser() {}
	/// \brief Reads a config file and returns a Tester reference
	/// \param ConfigName path to the config file
    SchemeTester* ReadConfig(const std::string& ConfigName);

private:
	/// \brief Removes the comments in the string
	/// \param ConfigString a string with a xml config
    /// \details A recognized comment starts with <!- and ends with ->
    std::string RemoveXMLComments(const std::string& ConfigString);
	/// \brief Returns the content between the first found token
	/// \param ConfigString a string with a xml config
	/// \param Tokens vector containing the tokens to search for
    /// \details Starts at the beginning of the token vector and
    /// if one token is found returns the content between
    /// throws an exception otherwise
    /// \details If you want to search for <Tester> you need to 
    /// provide the vector {"Tester"}
    std::string ReadToken(const std::string& ConfigString,
                          std::vector<std::string> Tokens);
	/// \brief Overrides ReadToken
	/// \param SuccessToken reference outputs the found token
    std::string ReadToken(const std::string& ConfigString,
                          std::vector<std::string> Tokens,
                          std::string& SuccessToken);
	/// \brief Returns a CE scheme from the provided config
	/// \param ConfigString a string with a xml config
    /// \details Searches for the <Scheme> tag and parses the
    /// scheme inside
    ICEScheme* ReadScheme(const std::string& ConfigString);
	/// \brief Returns a AEAD scheme from the provided config
	/// \param ConfigString a string with a xml config
    /// \details Searches for the <AEAD> tag and parses the
    /// scheme inside
    IAEADScheme* ReadAEAD(const std::string& ConfigString);
	/// \brief Generates a random string
	/// \param NumberString string of a number
    std::string GenerateRandomString(const std::string& NumberString);
	/// \brief Converts string to an integer
	/// \param NumberString string of a number
    uint32_t StringToInt(const std::string& NumberString);
	/// \brief Returns true if string is a number
	/// \param NumberString string of a number
    bool Is_Number(const std::string& NumberString);

    SchemeFactory mFactory;
};
#endif
