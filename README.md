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
# FAQ
- Q: Why the dump contains only null bytes?

    - A: Probably, the process is in a swap area, reload/interact with the process in order to load it back into RAM.



- Q: Why the dump size varies between attach and inspect mode sometimes?

    - A: There are situations when some pages content cannot be dumped (such as vvar or vsyscall pages range). Dump buffer is padded with null bytes in these areas. It doesn't affect the dumper correctness, but anyway may be fixed in further versions.



- Q: Why the dumper is killed in dumping phase

    - A: Probably, you want to dump a big process while OS doesn't have enough resources to handle the dump (low amount of available RAM, for example).
