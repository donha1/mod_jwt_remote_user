call "D:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

cl.exe /nologo /MD /W3 /O2 /D WIN32 /D WINDOWS /D NDEBUG -I"D:\httpd-latest\Apache24\include" /c mod_jwt_remote_user.c

link.exe kernel32.lib ws2_32.lib "D:\httpd-latest\Apache24\lib\*.lib" /nologo /subsystem:windows /dll /machine:x64 /out:mod_jwt_remote_user.so mod_jwt_remote_user.obj


