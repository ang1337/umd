project('umd', 'cpp', license : 'GPL')

add_project_arguments(['-std=c++17', '-O3'], language : 'cpp')

inc = include_directories('inc')

thr_dep = dependency('threads')

subdir('inc')
subdir('src')

pkg_mod = import('pkgconfig')
pkg_mod.generate(
    libraries : umdlib,
    name : 'libumd',
    description : 'Minimal memory dumping API for userspace processes'
)