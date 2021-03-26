# the compiler: gcc for C program, define as g++ for C++
CC = g++

# compiler flags:
#  -g3    		   adds debugging information to the executable file
#  -O3  		   using better comiling optimizations
#  -std  		   specifiy version of c++
#  -Wall, -Wextra  turns on most, but not all, compiler warnings
CFLAGS  = -DNDEBUG -g3 -std=c++17 -O2 -Wall -Wextra

# the build target executable:
TARGET = main

# define the source files:
SRCS = Tester.cpp \
	   ConfigParser.cpp \
	   HFC/SHA256_HFC.cpp \
	   HFC/SHA512_HFC.cpp \
	   HFC/Whrlpool_HFC.cpp \
	   HFC/SHA3_HFC.cpp \
	   HFC/AltPad_SHA256_HFC.cpp \
	   HFC/CETransformation.cpp \
	   CEP/CEP.cpp \
	   CtE/CtE1.cpp \
	   CtE/CtE2.cpp \
	   AEAD/EtM.cpp \
	   AEAD/AES_GCM.cpp \
	   SchemeFactory.cpp

# the used libraries:
LIBS = -lcryptopp

# for testing
TESTPATH = UnitTests
TESTIMAGE = Images/big.jpg

all: $(TARGET)

$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp $(SRCS) $(LIBS)

.PHONY: clean
clean:
	$(RM) $(TARGET)

.PHONY: cleanTests
cleanTests:
	$(RM) $(TESTPATH)/*.o

.PHONY: TestSHA256
TestSHA256: $(TESTPATH)/TestSHA256.cpp Tester.cpp
	$(CC) $(CFLAGS) -o $(patsubst %.cpp,%.o,$<) $^ $(LIBS) 
	./$(patsubst %.cpp,%.o,$<) $(TESTIMAGE)

.PHONY: TestHMAC
TestHMAC: $(TESTPATH)/TestHMAC.cpp Tester.cpp
	$(CC) $(CFLAGS) -o $(patsubst %.cpp,%.o,$<) $^ $(LIBS) 
	./$(patsubst %.cpp,%.o,$<) $(TESTIMAGE)

.PHONY: TestAESGCM
TestAESGCM: $(TESTPATH)/TestAESGCM.cpp Tester.cpp AEAD/AES_GCM.cpp
	$(CC) $(CFLAGS) -o $(patsubst %.cpp,%.o,$<) $^ $(LIBS) 
	./$(patsubst %.cpp,%.o,$<) $(TESTIMAGE)

.PHONY: TestEtM
TestEtM: $(TESTPATH)/TestEtM.cpp Tester.cpp AEAD/EtM.cpp
	$(CC) $(CFLAGS) -o $(patsubst %.cpp,%.o,$<) $^ $(LIBS) 
	./$(patsubst %.cpp,%.o,$<) $(TESTIMAGE)

.PHONY: TestOwnSHA
TestOwnSHA: $(TESTPATH)/TestOwnSHA.cpp Tester.cpp
	$(CC) $(CFLAGS) -o $(patsubst %.cpp,%.o,$<) $^ $(LIBS) 
	./$(patsubst %.cpp,%.o,$<) $(TESTIMAGE)

.PHONY: TestHFC
TestHFC: $(TESTPATH)/TestHFC.cpp Tester.cpp HFC/SHA256_HFC.cpp HFC/Whrlpool_HFC.cpp HFC/SHA512_HFC.cpp HFC/SHA3_HFC.cpp HFC/AltPad_SHA256_HFC.cpp
	$(CC) $(CFLAGS) -o $(patsubst %.cpp,%.o,$<) $^ $(LIBS) 
	./$(patsubst %.cpp,%.o,$<) $(TESTIMAGE)

.PHONY: TestPRG
TestPRG: $(TESTPATH)/TestPRG.cpp Tester.cpp
	$(CC) $(CFLAGS) -o $(patsubst %.cpp,%.o,$<) $^ $(LIBS) 
	./$(patsubst %.cpp,%.o,$<) $(TESTIMAGE)
