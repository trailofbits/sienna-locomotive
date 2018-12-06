#include <stdio.h>
#include <Windows.h>
#include <stdint.h>

#include "internet_read_file.h"
#include "win_http_read_data.h"
#include "winsock_recv.h"
#include "win_http_web_socket_receive.h"

/*! Force a crash */
void crash() {
    printf("Crashing!!!!\n");
    char buf[1];

    memcpy( buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1000 );
}


/**
 * Try reading from a registry key
 * @param fuzzing If we're not fuzzing, guarantee a crash. Otherwise, require a minimal mutation to cause a crash.
 */
int test_RegQueryValueEx(bool fuzzing) {
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
    // 0055005C003A0043
    if (fuzzing) {
        if((UINT64)crashPtr > 0x0055005C003A0043) {
            printf("*CRASH PTR: %x\n", *crashPtr);
        }
    } else {
        printf("*CRASH PTR: %x\n", *crashPtr);
    }

    return 0;
}

/*! Create a file to read from if it doesnt' already exist */
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


/**
 * Read a buffer from a file and see if we can mutate it to cause a crash
 * @param fuzzing If we're not fuzzing, guarantee a crash. Otherwise, require a minimal mutation to cause a crash.
 */
int test_ReadFile(bool fuzzing) {
    LPWSTR name = L"test_ReadFile.txt";
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
    if (fuzzing) {
        if((UINT64)crashPtr > 0x4947464544434241) {
            printf("*CRASH PTR: %x\n", *crashPtr);
        }
    } else {
        printf("*CRASH PTR: %x\n", *crashPtr);
    }

    CloseHandle(file);
    return 0;
}

/**
 * Cause an infinite loop to test timeouts
 * @param fuzzing If we're not fuzzing, guarantee a crash. Otherwise, require a minimal mutation to cause a crash.
 */
int test_ReadFile_inf_loop(bool fuzzing) {
    LPWSTR name = L"test_ReadFile.txt";
    prep_read_file_test(name);
    HANDLE file = CreateFile(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("ERROR: CreateFile (%x)\n", GetLastError());
        return 1;
    }

    BYTE buf[0x1000];
    DWORD bytes_to_read = 8;
    DWORD bytes_read;
    while(1) {
        SetFilePointer(file, 0, NULL, FILE_BEGIN);

        if (!ReadFile(file, buf, bytes_to_read, &bytes_read, NULL) || bytes_read != bytes_to_read) {
            printf("ERROR: ReadFile (ms_buf) (%x)\n", GetLastError());
            return 1;
        }

        buf[8] = 0;
        printf("BUF: %s\n", buf);

        int *crashPtr = *(int **)buf;
        printf("CRASH PTR: %p\n", crashPtr);
        if (fuzzing) {
            if((UINT64)crashPtr > 0x4947464544434241) {
                printf("*CRASH PTR: %x\n", *crashPtr);
            }
        } else {
            printf("*CRASH PTR: %x\n", *crashPtr);
        }
    }

    CloseHandle(file);
    return 0;
}

/**
 * Wraps ReadFile
 */
int readfile(LPWSTR path, uint8_t* buf=nullptr ) {

    BYTE bufStack[0x1000] = {};
    if( buf==nullptr )
        buf = (uint8_t*)bufStack;
    

    printf("Reading file %S.\n", path);
    HANDLE file = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("ERROR: CreateFile (%x)\n", GetLastError());
        return 1;
    }

    
    DWORD bytes_to_read = 8;
    DWORD bytes_read;
    if (!ReadFile(file, buf, bytes_to_read, &bytes_read, NULL) || bytes_read != bytes_to_read) {
        printf("ERROR: ReadFile (ms_buf) (%x)\n", GetLastError());
        return 1;
    }

    CloseHandle(file);
    return 0;
}

/**
 * Similar to test_Readfile, but uses fread instead
 * @param fuzzing If we're not fuzzing, guarantee a crash. Otherwise, require a minimal mutation to cause a crash.
 */
int test_fread(bool fuzzing) {
    LPWSTR name = L"test_ReadFile.txt";
    prep_read_file_test(name);
    
    BYTE buf[0x1000] = {0};
    FILE *stream;
    if(fopen_s(&stream, "test_ReadFile.txt", "r+t") == 0) {  
        fread(buf, sizeof(BYTE), 8, stream);  
        fclose( stream );  

        buf[8] = 0;
        printf("BUF: %s\n", buf);

        int *crashPtr = *(int **)buf;
        printf("CRASH PTR: %p\n", crashPtr);
        if (fuzzing) {
            if((UINT64)crashPtr > 0x4947464544434241) {
                printf("*CRASH PTR: %x\n", *crashPtr);
            }
        } else {
            printf("*CRASH PTR: %x\n", *crashPtr);
        }
    }  

    return 0;
}

/*! Used for unit tests*/
int test_argCompare(bool fuzzing) {

    readfile(L"sl2\\test\\test_argCompare_fail.txt");
    readfile(L"sl2\\test\\test_argCompare_fail.txt");
    readfile(L"sl2\\test\\test_argCompare_fail.txt");
    readfile(L"sl2\\test\\test_argCompare_win.txt");
    readfile(L"sl2\\test\\test_argCompare_fail.txt");

    return 0;
}

/*! Used for unit tests*/
int test_captureStdout(bool fuzzing) {
    readfile(L"test_argCompare_fail.txt");

    printf("XXXWWWXXX\n");
    return 0;
}


/*! Used for unit tests*/
int test_quickCrash(bool fuzzing) {
    printf("Starting quickCrash()...\n");
    char buf[1024];
    memset(buf, 0, sizeof(buf) );
    readfile(L"sl2\\test\\test_argCompare_win.txt", (uint8_t*)buf);
    printf("(%s)\n", buf);
    if( strstr( buf, "WIN!!!" ) != NULL ) {
        crash();
    } 
    return 0;
}


/*! Print list of test numbers */
int show_help(LPWSTR *argv) {
    printf("\nUSAGE: %S [TEST NUMBER] [-f]\n", argv[0]);
    printf("\nTEST NUMBERS:\n");
    printf("\t0:  test_ReadFile\n");
    printf("\t1:  test_recv\n");
    printf("\t2:  test_WinHttpReadData\n");
    printf("\t3:  test_InternetReadFile\n");
    printf("\t4:  test_RegQueryValueEx\n");
    printf("\t5:  test_WinHttpWebSocketReceive\n");
    printf("\t6:  test_fread\n");
    printf("\t7:  test_ReadFile_inf_loop\n");
    printf("\t8:  test_argCompare\n");
    printf("\t9:  test_captureStdout\n");
    printf("\t10: test_quickCrash\n");
    printf("\nf:\n"); 
    printf("\tenable fuzzing mode\n");
    printf("\the crashing condition will be guarded by a conditional\n");
    return 0;
}


/**
 * Dispatch tests based on argument
 * @return exit code
 */
int main()
{
    int argc;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    bool fuzzing = false;
    
    int opt = 100;    
    if (argc > 1) {
        opt = _wtoi(argv[1]);
    } else {
        show_help(argv);
        return 0;
    }

    if(argc > 2 && wcscmp(argv[2], L"-f") == 0) {
        fuzzing = true;
    } 

    switch(opt) {
        case 0:
            printf("Running: test_ReadFile\n");
            test_ReadFile(fuzzing);
            break;
        case 1:
            printf("Running: test_recv\n");
            test_recv(fuzzing);
            break;
        case 2:
            printf("Running: test_WinHttpReadData\n");
            test_WinHttpReadData(fuzzing);
            break;
        case 3:
            printf("Running: test_InternetReadFile\n");
            test_InternetReadFile(fuzzing);
            break;
        case 4:
            printf("Running: test_RegQueryValueEx\n");
            test_RegQueryValueEx(fuzzing);
            break;
        case 5:
            printf("Running: test_WinHttpWebSocketReceive\n");
            test_WinHttpWebSocketReceive(fuzzing);
            break;
        case 6:
            printf("Running: test_fread\n");
            test_fread(fuzzing);
            break;
        case 7:
            printf("Running: test_ReadFile_inf_loop\n");
            test_ReadFile_inf_loop(fuzzing);
            break;
        case 8:
            printf("Running: test_argCompare\n");
            test_argCompare(fuzzing);
            break;
        case 9:
            printf("Running: test_captureStdout\n");
            test_captureStdout(fuzzing);
            break;

        case 10:
            printf("Running: test_quickCrash\n");
            test_quickCrash(fuzzing);
            break;

        default:
            show_help(argv);
            break;
    }


    return 0;
}

