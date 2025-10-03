@echo off
setlocal

set CLFLAGS=/nologo /std:c++17 /Zi /EHsc /MD
set INCLUDES=/Iinclude /Isuperv /Iinclude\capstone
set LIBPATHS=/LIBPATH:lib
set LIBS=capstone.lib kernel32.lib user32.lib gdi32.lib advapi32.lib
cl %CLFLAGS% %INCLUDES% superv\main.cpp /Fe:build\superv.exe /link %LIBPATHS% %LIBS%

endlocal
