#! /bin/bash
if [  -d build ]; then
    rm -rf build
    mkdir build
fi
else {
    mkdir build
}

cd build
rm -rf *
cmake .. 
make
mv cidr-ping ..
mv sort-rtts ..
