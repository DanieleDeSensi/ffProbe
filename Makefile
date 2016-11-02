CC                  = gcc 
CXX                 = g++ 
LINK_OPT            = 
VERSION             = 
OPTIMIZE_FLAGS      = -finline-functions -O3 
CXXFLAGS            = --std=c++11 -Wall -DFF_BOUNDED_BUFFER
CFLAGS              =
LDFLAGS             = -Xlinker -zmuldefs
INCS                = -I ./ -I ./fastflow
LIBS                = -lpthread -lpfring -lpcap
INCLUDES            =
TARGET              = ffProbe

.PHONY: all clean cleanall install uninstall
.SUFFIXES: .cpp .o

all: $(TARGET)

%.o: %.cpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) -c $? -o $@
ffProbe: flow.o hashTable.o task.o utils.o workers.o ffProbe.o
	$(CXX) ffProbe.o flow.o hashTable.o task.o utils.o workers.o -o ffProbe $(CXXFLAGS) $(LIBS) $(LDFLAGS)
	sh analyze_cpuinfo.sh
clean: 
	-rm -fr *.o *~ tmpcpuinfo
cleanall: clean
	-rm -fr $(TARGET)
install:
	cp ./ffProbe /usr/local/bin/ffProbe
uninstall:
	rm -fr /usr/local/bin/ffProbe
