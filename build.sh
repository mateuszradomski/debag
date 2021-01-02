#!/bin/bash

# Debuging build
optim='-g -fsanitize=address'
# Relase build
# optim='-O2'

opts=$optim' -Wall -Wextra -Wno-write-strings -Wno-unused-function -Wno-class-memaccess'
libs='-lGL -lglfw -ldwarf'
static_libs='libs/libimgui_static.a libs/libcapstone.a'
g++ $opts -I./ debag.cpp $static_libs -o debag $libs
