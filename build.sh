#!/bin/bash

# Debuging build
optim='-g -fsanitize=address -DDEBUG'
# Relase build
# optim='-O2'

opts=$optim' -Wall -Wextra -Wno-write-strings -Wno-unused-function -Wno-class-memaccess'
libs='-lGL -ldl -pthread -lX11 -lelf -lz -lunwind -lunwind-generic -lunwind-ptrace'
static_libs='libs/libimgui_static.a libs/libcapstone.a libs/libglfw3.a libs/libdwarf.a'
g++ $opts -I./ debag.cpp $static_libs -o debag $libs
