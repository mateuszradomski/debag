#!/bin/bash

flags='-g -no-pie'

for f in test/*
do
	out=${f%%.c*}
	echo tests_bin/${out##test/}
	gcc $f $flags -o tests_bin/${out##test/}
done