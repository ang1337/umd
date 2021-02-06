# umd
Simple yet powerful memory dumping library for Linux userspace processes. 
# Features
 - Multithreaded in-memory dumping and inspection of a dumped memory
 - Dump to disk option

# Dependencies
- GNU gcc compiler with C++ 17 support
- Python 3
- Meson build system

# How to install
```
git clone https://github.com/ang1337/umd.git
cd umd
./install.sh
```

# Usage
See ```api_usage_example.cpp``` file that uses pretty much all the API exposed for an external umd library usage. Compile the program that uses umd library with ```-lumd```, ```-lpthread``` and ```-std=c++17``` flags.
       
