#!/bin/sh

# Debuging build
optim='-g -DDEBUG'
# Relase build
# optim='-O2'

# Build the testing bins
mkdir -p bin

for src_file in src/*.c
do
    bin_name=$(basename -s .c $src_file)
    gcc $src_file -o bin/$bin_name
done

opts=$optim' -Wall -Wextra -Wno-write-strings -Wno-unused-function -Wno-class-memaccess -Wno-format-security'
libs='-lGL -ldl -pthread -lX11 -lelf -lz -lcapstone -lglfw -ldwarf -lunwind -lunwind-generic -lunwind-ptrace'
#static_libs='libs/libimgui_static.a'

g++ $opts $optim test.cpp -o test $libs $static_libs
