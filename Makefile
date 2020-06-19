COMP = clang++

ifndef COMP
	COMP = g++
	ifndef COMP
		$(error No suitable compiler is available. Download either clang (recommended) or gcc)
	endif
endif

BINNAME = umd
COMPFLAGS = $(CXXSTD) $(CXX17) $(THREADLIB) $(OPTIMIZATIONS) $(BINRENAME)
#DEBUG = -g#add the debugging flag ($(DEBUG)) to COMPFLAGS for getting a debugger symbols after the compilation 
OPTIMIZATIONS = -O3
BINRENAME = -o
CXX17 = -std=c++17
CXXSTD = -lstdc++
THREADLIB = -pthread

all:
	$(COMP) ./src/*.cpp $(COMPFLAGS) $(BINNAME)
	$(info Relocating the $(BINNAME) binary to the PATH...)
	sudo mv $(BINNAME) /usr/local/bin
	sudo setcap cap_sys_ptrace,cap_sys_nice=+ep /usr/local/bin/$(BINNAME)
clean:
	sudo rm /usr/local/bin/$(BINNAME)
	$(warning $(BINNAME) has been successfully deleted)
