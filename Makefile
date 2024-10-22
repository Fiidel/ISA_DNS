CXX = g++
CXXFLAGS = -Wall --std=c++11
SRC_DIR = ./src
EXECUTABLE = dns-monitor

all: clean $(EXECUTABLE)

$(EXECUTABLE): main.o CLParser.o Configuration.o PacketCapture.o DomainNameLogger.o TranslationLogger.o hashTable.o
	$(CXX) $(CXXFLAGS) -o $(EXECUTABLE) main.o CLParser.o Configuration.o PacketCapture.o DomainNameLogger.o TranslationLogger.o hashTable.o -lpcap

main.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/main.cpp

CLParser.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/CLParser.cpp

Configuration.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/Configuration.cpp

PacketCapture.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/PacketCapture.cpp

DomainNameLogger.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/DomainNameLogger.cpp

TranslationLogger.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/TranslationLogger.cpp

hashTable.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/hashTable.cpp

clean:
	rm -f $(EXECUTABLE) *.o
