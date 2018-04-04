#include <stdio.h>
#include <Windows.h>

#include "internet_read_file.h"
#include "win_http_read_data.h"
#include "winsock_recv.h"
#include "win_http_web_socket_receive.h"

// cmake -G"Visual Studio 15 Win64" ..
// cmake --build . --config Release

// RegQueryValueEx
int test_RegQueryValueEx() {
    BYTE buf[4096];
    DWORD size = 4096;

    HKEY key;
    DWORD err = RegOpenKeyEx(
        HKEY_CURRENT_USER, 
        L"Environment", 
        NULL, 
        KEY_READ, 
        &key);

    if(err != ERROR_SUCCESS) {
        printf("Open key error: %x\n", err);
        return 1;
    }

    err = RegQueryValueEx(
        key,
        L"Path", 
        NULL, 
        NULL, 
        buf,
        &size);

    if(err != ERROR_SUCCESS || size < 8) {
        printf("Query key error: %x\n", err);
        return 1;
    }

    int *crashPtr = *(int **)buf;
    printf("CRASH PTR: %p\n", crashPtr);
    printf("*CRASH PTR: %x\n", *crashPtr);
}

// ReadFile
int prep_read_file_test(LPWSTR name) {
    HANDLE file = CreateFile(name, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("ERROR: CreateFile (%x)\n", GetLastError());
        return 1;
    }

    char *buf = "AAAAAAAA";
    DWORD bytes_written = 0;
    if(!WriteFile(file, buf, 8, &bytes_written, NULL) || bytes_written != 8) {
        printf("ERROR: CreateFile (%x)\n", GetLastError());
        return 1;   
    }

    CloseHandle(file);
    return 0;
}

int read_file_test() {
    LPWSTR name = L"read_file_test.txt";
    prep_read_file_test(name);
    HANDLE file = CreateFile(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("ERROR: CreateFile (%x)\n", GetLastError());
        return 1;
    }

    BYTE buf[0x1000];
    DWORD bytes_to_read = 8;
    DWORD bytes_read;
    if (!ReadFile(file, buf, bytes_to_read, &bytes_read, NULL) || bytes_read != bytes_to_read) {
        printf("ERROR: ReadFile (ms_buf) (%x)\n", GetLastError());
        return 1;
    }

    buf[8] = 0;
    printf("BUF: %s\n", buf);

    int *crashPtr = *(int **)buf;
    printf("CRASH PTR: %p\n", crashPtr);
    printf("*CRASH PTR: %x\n", *crashPtr);
    
    CloseHandle(file);
    return 0;
}

int show_help(LPWSTR *argv) {
    printf("USAGE: %S [OPTION]\n", argv[0]);
    printf("OPTIONS:\n");
    printf("\t0: read_file_test\n");
    printf("\t1: test_recv\n");
    printf("\t2: test_WinHttpReadData\n");
    printf("\t3: test_InternetReadFile\n");
    printf("\t4: test_RegQueryValueEx\n");
    printf("\t5: test_WinHttpWebSocketReceive\n");
    return 0;
}

int main()
{
    int argc;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    int opt = 0;    
    if (argc > 1) {
        opt = _wtoi(argv[1]);
    } else {
        show_help(argv);
        return 0;
    }

    switch(opt) {
        case 0:
            read_file_test();
            break;
        case 1:
            test_recv();
            break;
        case 2:
            test_WinHttpReadData();
            break;
        case 3:
            test_InternetReadFile();
            break;
        case 4:
            test_RegQueryValueEx();
            break;
        case 5:
            test_WinHttpWebSocketReceive();
            break;
        default:
            show_help(argv);
            break;
    }


    return 0;
}

