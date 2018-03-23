#include <stdio.h>

#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")

#include <Windows.h>

// cmake -G"Visual Studio 15 Win64" ..
// cmake --build . --config Release

/*
    ReadEventLog
    RegQueryValueEx
    WinHttpWebSocketReceive
    InternetReadFile
*/

// WinHttpReadData
int test_WinHttpReadData() {
    DWORD dwSize = 0;
  DWORD dwDownloaded = 0;
  LPSTR pszOutBuffer;
  BOOL  bResults = FALSE;
  HINTERNET  hSession = NULL, 
             hConnect = NULL,
             hRequest = NULL;

  // Use WinHttpOpen to obtain a session handle.
  hSession = WinHttpOpen( L"WinHTTP Example/1.0",  
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, 
                          WINHTTP_NO_PROXY_BYPASS, 0 );

  // Specify an HTTP server.
  if( hSession )
    hConnect = WinHttpConnect( hSession, L"neverssl.com",
                               INTERNET_DEFAULT_HTTP_PORT, 0 );

  // Create an HTTP request handle.
  if( hConnect )
    hRequest = WinHttpOpenRequest( hConnect, L"GET", NULL,
                                   NULL, WINHTTP_NO_REFERER, 
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, 
                                   NULL );

  // Send a request.
  if( hRequest )
    bResults = WinHttpSendRequest( hRequest,
                                   WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 
                                   0, 0 );


  // End the request.
  if( bResults )
    bResults = WinHttpReceiveResponse( hRequest, NULL );

  // Keep checking for data until there is nothing left.
  if( bResults )
  {
    do 
    {
      // Check for available data.
      dwSize = 0;
      if( !WinHttpQueryDataAvailable( hRequest, &dwSize ) )
        printf( "Error %u in WinHttpQueryDataAvailable.\n",
                GetLastError( ) );

      // Allocate space for the buffer.
      pszOutBuffer = new char[dwSize+1];
      if( !pszOutBuffer )
      {
        printf( "Out of memory\n" );
        dwSize=0;
      }
      else
      {
        // Read the data.
        ZeroMemory( pszOutBuffer, dwSize+1 );

        if(!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
          printf( "Error %u in WinHttpReadData.\n", GetLastError( ) );
        }
        else {
          // printf( "%s\n", pszOutBuffer );
          if(dwDownloaded >= 8) {
            int *crashPtr = *(int **)pszOutBuffer;
            printf("CRASH PTR: %p\n", crashPtr);
            printf("*CRASH PTR: %x\n", *crashPtr);
          }
        }

        // Free the memory allocated to the buffer.
        delete [] pszOutBuffer;
      }
    } while( dwSize > 0 );
  }


  // Report any errors.
  if( !bResults )
    printf( "Error %d has occurred.\n", GetLastError( ) );

  // Close any open handles.
  if( hRequest ) WinHttpCloseHandle( hRequest );
  if( hConnect ) WinHttpCloseHandle( hConnect );
  if( hSession ) WinHttpCloseHandle( hSession );

  return 0;
}

// recv
int test_recv() {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo *result = NULL,
                    *ptr = NULL,
                    hints;
    char *sendbuf = "AAAAAAAA";
    char recvbuf[8];
    int iResult;
    int recvbuflen = 8;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo("localhost", "27015", &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, 
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        printf("Is it running?\n");
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
    iResult = send( ConnectSocket, sendbuf, (int)strlen(sendbuf), 0 );
    if (iResult == SOCKET_ERROR) {
        printf("send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    printf("Bytes Sent: %ld\n", iResult);

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        printf("shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Receive until the peer closes the connection
    do {

        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if ( iResult > 0 ) {
            printf("Bytes received: %d\n", iResult);
        }
        else if ( iResult == 0 ) {
            printf("Connection closed\n");
            int *crashPtr = *(int **)recvbuf;
            printf("CRASH PTR: %p\n", crashPtr);
            printf("*CRASH PTR: %x\n", *crashPtr);
        }
        else {
            printf("recv failed with error: %d\n", WSAGetLastError());
        }

    } while( iResult > 0 );

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
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
        default:
            show_help(argv);
            break;
    }


    return 0;
}

