#!/bin/bash

opts='-g -fsanitize=address'
libs='-lGL -lglfw -lGLEW -lcapstone -ldwarf'
g++ $opts -I./ debag.cpp libimgui_static.a -o debag $libs
