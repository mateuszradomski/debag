#!/bin/bash

# Debuging build
optim='-g -fsanitize=address -DDEBUG'
# Relase build
# optim='-O2'

opts=$optim' -Wall -Wextra -Wno-write-strings -Wno-unused-function -Wno-class-memaccess -Wno-format-security'
libs='-lGL -ldl -pthread -lX11 -lelf -lz -lcapstone -lglfw -ldwarf -lunwind -lunwind-generic -lunwind-ptrace'
static_libs='libs/libimgui_static.a'
g++ $opts -I./ -I./src src/main.cpp $static_libs -o debag $libs
