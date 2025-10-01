@echo off
setlocal

set CL=/nologo /std:c++17 /Zi /EHsc /MD   
set INCLUDES=/Iinclude /Isuperv /Iinclude\capstone
set LIBS=/LIBPATH:lib capstone.lib ucrt.lib msvcrt.lib legacy_stdio_definitions.lib
cl %CL% superv\main.cpp %INCLUDES% /Fe:build\superv.exe /link %LIBS%

endlocal
