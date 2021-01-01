#!/bin/sh

if ! [ $# -eq 2 ]; then
    # TODO: print usage
    echo $0 srcfile.cpp headerfile.h
    exit 1
fi

# Generate return types and put them in rett.txt
ctags -x --c++-types=f --extra=q --format=1 $1 | awk '{print $2 "-1"}' | bc | xargs -n 1 -I {} sed '{}q;d' $1 > rett.txt

# Generate prototypes and put them in prot.txt
ctags -x --c++-types=f --extra=q --format=1 $1 | awk '{print $2}' | xargs -n 1 -I {} sed '{}q;d' $1 > prot.txt

# Interleve the return types and prototypes
paste -d ' ' rett.txt prot.txt | sed 's/$/;/g' | sed 's/\*\ /\*/g' >> $2

rm rett.txt
rm prot.txt
