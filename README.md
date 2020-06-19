# ?
Simple yet powerful memory dumper for Linux userspace processes. Suitable for 32 and 64 bit ELF binaries.
# Features
- Two execution modes: **attach mode** and **inspect mode**.
    - **Attach mode**: umd attaches to any userspace process and dumps whole process memory. Inspect option is available immediately after a dumping phase. The utility dumps a memory as a raw binary file and a content of the corresponding /proc/pid/maps as a text file which represents full process memory layout.
    - **Inspect mode**: loads a memory layout of a dumped process represented by saved content of /proc/pid/maps and a memory dump of a corresponding process from a disk. Umd internally maps all virtual addresses to offsets in a buffer that contains a memory dump.
- **Multithreaded dumping phase**: umd picks an optimal amount of threads before a dumping phase according to a CPU capabilities. The dumping phase is blazingly fast.
  
  Example:
  ![Screenshot_20200619_185435](https://user-images.githubusercontent.com/45107680/85154973-d3e7a680-b260-11ea-8bd2-125c1079c8f7.png)
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
        $ make
# How to uninstall
        $ cd umd
        $ make clean
