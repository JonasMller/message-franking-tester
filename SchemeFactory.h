#ifndef SCHEMEFACTORY_H
#define SCHEMEFACTORY_H

#include <string>

#include <cryptopp/cryptlib.h>

class ICEScheme;
class IAEADScheme;
class IHFCScheme;

/// \brief SchemeFactory class which creates the different schemes and their compontents
/// \details When looking at the config file, there needs to be a function for every tag
/// that describes a scheme or a component (<CEP>, <CtE1>, <CETransform>, <EtM> or <AES_GCM>)
class SchemeFactory
{
public:
    /// \brief Creates a CEP scheme
	/// \param Hash name of the hash
	/// \param HashCr name of collision resistant hash
    ICEScheme* CreateCEP(std::string& Hash, std::string& HashCr, std::string& PRG);
    /// \brief Creates a CtE1 scheme
	/// \param Hash name of the hash
	/// \param AEAD reference to a AEAD scheme
    ICEScheme* CreateCtE1(std::string& Hash, IAEADScheme* AEAD);
    /// \brief Creates a CtE2 scheme
	/// \param Hash name of the hash
	/// \param AEAD reference to a AEAD scheme
    ICEScheme* CreateCtE2(std::string& Hash, IAEADScheme* AEAD);
    /// \brief Creates a CETransformation
	/// \param HFC name of a HFC scheme
	/// \param AEAD reference to a AEAD scheme
    ICEScheme* CreateCETransform(std::string& HFC, IAEADScheme* AEAD);
    /// \brief Creates a EtM AEAD scheme
	/// \param Hash name of the hash
	/// \param Enc name of the encryption scheme
    IAEADScheme* CreateEtM(std::string& Hash, std::string& Enc);
    /// \brief Creates a GCM<AES> AEAD scheme
    IAEADScheme* CreateAESGCM();
    /// \brief Creates a HFC scheme
	/// \param HFC name of a HFC scheme
    IHFCScheme* CreateHFC(std::string& HFC);
    /// \brief Creates a encryption scheme
	/// \param Enc name of the encryption scheme
    CryptoPP::SymmetricCipher* CreateEncryption(std::string& Enc);
    /// \brief Creates a decryption scheme 
	/// \param Enc name of the decryption scheme
    CryptoPP::SymmetricCipher* CreateDecryption(std::string& Dec);
    /// \brief Creates a MAC scheme
	/// \param MAC name of the MAC scheme
    /// \details only outpus HMAC with different hashes at the moment
    CryptoPP::MessageAuthenticationCode* CreateMAC(std::string& MAC);
    /// \brief Creates a PRG
	/// \param PRG name of the PRG scheme
    /// \details Will be used for the PRG in the CEP scheme
    CryptoPP::SymmetricCipher* CreatePRG(string& PRG);
};

#endif
