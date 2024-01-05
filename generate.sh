#!/bin/bash

dmd source/secured/windows/bcrypt.c -Hf=source/secured/windows/bcrypt.di -verrors=0 -main -P="/Zc:wchar_t /I\"C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.22621.0\\shared\""
rm -f *.exe
rm -f *.obj