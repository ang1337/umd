# ?
Simple yet powerful memory dumper for Linux userspace processes. Suitable for 32 and 64 bit ELF binaries.
# Features
- Two execution modes: **attach mode** and **inspect mode**.
    - **Attach mode**: umd attaches to any userspace process and dumps the entire process memory. Inspect option is available immediately after a dumping phase. The utility dumps a memory as a raw binary file and a content of the corresponding /proc/pid/maps as a text file which represents full process memory layout.
    - **Inspect mode**: loads a memory layout of a dumped process represented by the saved content of /proc/pid/maps and a memory dump of a corresponding process from a disk. Thus, full dump analysis is available at any time.
- **Addresses to offsets mapping**: umd maps all virtual addresses to a corresponding offsets in a buffer that contains full process memory dump. Thus, memory layout "holes" are handled, it's possible to fetch bytes from a dump buffer via providing the virtual address to read bytes from. 
- **Multithreaded dumping phase**: umd picks an optimal amount of threads before a dumping phase according to a CPU capabilities. The dumping phase is blazingly fast. Nonetheless, dumping speed may slightly vary.
  
  Example:
  ![dumping_phase](https://user-images.githubusercontent.com/45107680/85208354-542d0b00-b338-11ea-801f-e493de1093d9.png)
# Usage
Launch attach mode

    $ umd /path/to/dump/directory --attach PID
        
or
        
    $ umd /path/to/dump/directory -a PID
Launch inspect mode

    $ umd /path/to/memory/layout --inspect /path/to/dump
        
or

    $ umd /path/to/memory/layout -i /path/to/dump
# How to install
    $ git clone https://github.com/ang1337/umd.git
    $ cd umd
    $ make install
# How to uninstall
    $ cd umd
    $ make clean
