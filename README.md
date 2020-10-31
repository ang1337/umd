# umd
Simple yet powerful memory dumper for Linux userspace processes. Suitable for x86 and x86_64 ELF binaries.
# Features
This is 1.1 version! umd was rewritten, new feature: JSON memory dump metadata file alongside with a raw memory dump, so that external programs will be able to parse JSON file and freely manipulate the corresponding memory dump.
- Two execution modes: **attach mode** and **inspect mode**.
    - **Attach mode**: umd attaches to any userspace process and dumps the entire process memory. This mode requires root privileges.
    - **Inspect mode**: umd loads a dump and a corresponding JSON file with all memory metadata relevant for the given memory dump. The JSON file is parsed and the dump is ready for inspection afterwards. There is an option to get dumped registers as well. You can read an arbitrary amount of data from the dump, access validation is applied.
- **Addresses to offsets mapping**: umd maps all virtual addresses to a corresponding offsets in a buffer that contains full process memory dump. Thus, memory layout "holes" are handled, it's possible to fetch bytes from a dump buffer via providing the virtual address to read bytes from. 
- **Multithreaded dumping phase**: umd utilizes multithreading for faster dumping phase, which is pretty fast = ~10 seconds for 2.5 gigabytes memory + registers dump on a computer with SSD and 8 logical CPU cores (4 physical cores * 2 threads per core - ```Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz```).
  
  Example:
  ![image](https://user-images.githubusercontent.com/45107680/97784029-533c9d80-1ba4-11eb-9446-bea626549a9f.png)

  Example of a part of JSON memory metadata file:
  ![image](https://user-images.githubusercontent.com/45107680/97783834-f12f6880-1ba2-11eb-93c0-5346cf52706f.png)

# Dependencies
- GNU gcc compiler with C++ 17 support
- nlohmann 

# Usage
Launch in attach mode

    $ sudo ./umd -a PID

Launch in inspect mode

    $ ./umd -i /path/to/dump /path/to/json 
        
# How to install
    $ git clone https://github.com/ang1337/umd.git
    $ cd umd
    $ chmod +x install.sh && ./install.sh
The umd binary is located in ```./build``` directory
