CXX = g++
CXXFLAGS = -Wall --std=c++11
SRC_DIR = ./src
EXECUTABLE = dns-monitor

all: $(EXECUTABLE)

$(EXECUTABLE): main.o CLParser.o Configuration.o PacketCapture.o
	$(CXX) $(CXXFLAGS) -o $(EXECUTABLE) main.o CLParser.o Configuration.o PacketCapture.o -lpcap

main.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/main.cpp

CLParser.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/CLParser.cpp

Configuration.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/Configuration.cpp

PacketCapture.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/PacketCapture.cpp

clean:
	rm -f $(EXECUTABLE) *.o
