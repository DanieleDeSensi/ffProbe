CC                  = gcc 
CXX					= g++ 
LINK_OPT            = 
VERSION             = 
OPTIMIZE_FLAGS      = -finline-functions -O3
CXXFLAGS            = -Wall -g -DFF_BOUNDED_BUFFER
CFLAGS              =
LDFLAGS             = 
INCS                = -I ./
LIBS                = -lpthread -lpfring
INCLUDES            =
TARGET              = ffProbe

.PHONY: all clean cleanall install uninstall
.SUFFIXES: .cpp .o

all: $(TARGET)

ffProbe.o: ffProbe.cpp *.hpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) -c -o $@ $<

ffProbe: ffProbe.o
	$(CXX) ffProbe.o -o ffProbe $(CXXFLAGS) $(LIBS)
	sh analyze_cpuinfo.sh
clean: 
	-rm -fr *.o *~ tmpcpuinfo
cleanall: clean
	-rm -fr $(TARGET)
install:
	cp ./ffProbe /usr/local/bin/ffProbe
uninstall:
	rm -fr /usr/local/bin/ffProbe
