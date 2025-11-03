@echo off
echo Building Module Dumper...
g++ -std=c++11 -Wall -O2 -o ModuleDumper.exe ModuleDumper.cpp -lpsapi -ladvapi32
if %errorlevel%==0 (
    echo Build successful!
    echo.
    echo Run as Administrator for best results
    echo Example: ModuleDumper.exe dump notepad.exe notepad.exe dump.bin
) else (
    echo Build failed!
)
pause