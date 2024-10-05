CXX = g++
CXXFLAGS = -Wall --std=c++11
SRC_DIR = ./src
EXECUTABLE = dns-monitor

all: $(EXECUTABLE)

$(EXECUTABLE): main.o CLParser.o
	$(CXX) $(CXXFLAGS) -o $(EXECUTABLE) main.o CLParser.o

main.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/main.cpp

CLParser.o:
	$(CXX) $(CXXFLAGS) -c $(SRC_DIR)/CLParser.cpp

clean:
	rm -f $(EXECUTABLE) *.o
