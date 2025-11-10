
if(Test-Path build) {
    Remove-Item build -Recurse
    mkdir build
}
else {
    mkdir build
}

& cd build
& cmake .. -G "MinGW Makefiles"
& mingw32-make
& cmake --install .
& mv cidr-ping.exe ..
& mv sort-rtts.exe ..

& cd ..