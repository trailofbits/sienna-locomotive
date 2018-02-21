#include <stdio.h>
#include "Windows.h"

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"

#ifdef WINDOWS
#define IF_WINDOWS_ELSE(x,y) x
#else
#define IF_WINDOWS_ELSE(x,y) y
#endif

#ifdef WINDOWS
#define DISPLAY_STRING(msg) dr_messagebox(msg)
#else
#define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
#endif

#define NULL_TERMINATE(buf) buf[(sizeof(buf)/sizeof(buf[0])) - 1] = '\0'

static void event_exit(void);
static void wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data);
static void wrap_post_ReadFile(void *wrapcxt, void *user_data);

static size_t max_ReadFile;
static void *max_lock; /* sync writes to max_ReadFile */

static BOOL mutate(HANDLE hFile, DWORD64 position, LPVOID buf, DWORD size);

extern "C" __declspec(dllexport) DWORD runId;
__declspec(dllexport) DWORD runId;
//extern "C" __declspec(dllexport) BOOL replay;
//__declspec(dllexport) BOOL replay;
extern "C" __declspec(dllexport) BOOL trace;
__declspec(dllexport) BOOL trace;
static BOOL replay;

/* from wrap.cpp sample code */
static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, "ReadFile");
    if (towrap != NULL) {
	    bool ok = drwrap_wrap(towrap, wrap_pre_ReadFile, wrap_post_ReadFile);
	    if (ok) {
		    dr_fprintf(STDERR, "<wrapped ReadFile @ 0x%p\n", towrap);
	    } else {
		    dr_fprintf(STDERR, "<FAILED to wrap ReadFile @ 0x%p: already wrapped?\n", towrap);
	    }
    }
    towrap = (app_pc) dr_get_proc_address(mod->handle, "ReadFileEx");
    if (towrap != NULL) {
	    bool ok = drwrap_wrap(towrap, wrap_pre_ReadFile, wrap_post_ReadFile);
	    if (ok) {
		    dr_fprintf(STDERR, "<wrapped ReadFileEx @ 0x%p\n", towrap);
	    } else {
		    dr_fprintf(STDERR, "<FAILED to wrap ReadFileEx @ 0x%p: already wrapped?\n", towrap);
	    }
    }
}


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("Sienna-Locomotive Fuzzer",
                       "https://github.com/trailofbits/sienna-locomotive/issues");
    dr_log(NULL, LOG_ALL, 1, "DR client 'SL Fuzzer' initializing\n");
    if (dr_is_notify_on()) {
#ifdef WINDOWS
	dr_enable_console_printing();
#endif
	dr_fprintf(STDERR, "Client SL Fuzzer is running\n");
    }

    drmgr_init();
    drwrap_init();
    
    max_ReadFile = 0;
    
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(module_load_event);
}

/* from wrap.cpp sample code */
static void
event_exit(void) {
    //char msg[256];
    //int len;
    //len = dr_snprintf(msg, sizeof(msg)/sizeof(msg[0]),
	//	    "<Largest ReadFile request: %d>\n",
	//	    max_ReadFile);
    //DR_ASSERT(len > 0);
    //NULL_TERMINATE(msg);
    //DISPLAY_STRING(msg);

    drwrap_exit();
    drmgr_exit();
}


DWORD64 position = 0;
DWORD   nNumberOfBytesToRead;
LPDWORD lpNumberOfBytesRead;
HANDLE  hFile;
/* from wrap.cpp sample code */
static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data) {
    hFile =                drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer =      drwrap_get_arg(wrapcxt, 1);
    nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    lpNumberOfBytesRead =  (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    //if (max_ReadFile < nNumberOfBytesToRead) {
    //    max_ReadFile = nNumberOfBytesToRead;
    //}
    *user_data = lpBuffer;

    LONG positionHigh = 0;

    // we may need to go lower-level than just calling windows api?
    //DWORD positionLow = SetFilePointer(hFile, 0, &positionHigh, FILE_CURRENT);
    //DWORD64 position = positionHigh;
    //position = (position << 32) | positionLow;
}

static void
wrap_post_ReadFile(void *wrapcxt, void *user_data) {
    LPVOID lpBuffer = user_data;
    DWORD nNumberOfBytesToRead;
	if (lpNumberOfBytesRead) {
        nNumberOfBytesToRead = *lpNumberOfBytesRead;
    }
    
    //dr_fprintf(STDERR, "In wrap_post_ReadFile (%d)\n", hFile);
    //dr_printf("post- lpBuffer %p: %s\n", lpBuffer, lpBuffer);
   
    if (!replay && !trace || replay) {
        //if (!mutate(hFile, position, lpBuffer, nNumberOfBytesToRead)) {
        if (!mutate(hFile, position, lpBuffer, *lpNumberOfBytesRead)) {
            // TODO: fallback mutations?
            dr_printf("failed to mutate lpBuffer\n");
        }
    }
    
    //TCHAR *new_buf = (TCHAR *)lpBuffer;
    //for(DWORD i = 0; i < nNumberOfBytesToRead; ++i) {
    //    if (isprint(new_buf[i])) {
    //        dr_printf("%c", new_buf[i]);
    //    }
    //    else {
    //        dr_printf(".");
    //    }
    //    new_buf[i] = (TCHAR)'A';
    //    dr_printf("%c", new_buf[i]);
    //}

    //dr_printf("mutated lpBuffer %p: %s", lpBuffer, lpBuffer);

    if (lpNumberOfBytesRead != NULL) {
        *lpNumberOfBytesRead = nNumberOfBytesToRead;
    }
    
    //dr_printf("lpNumberOfBytesRead = %d\n", *lpNumberOfBytesRead);

    drwrap_set_mcontext(wrapcxt);

    BOOL ok = TRUE; 
    drwrap_set_retval(wrapcxt, &ok); // FIXME
}

static DWORD mutateCount = 0;
static BOOL mutate(HANDLE hFile, DWORD64 position, LPVOID buf, DWORD size) {
	TCHAR filePath[MAX_PATH+1];
    TCHAR *new_buf = (TCHAR *)buf;
    
    for(DWORD i = 0; i < size; ++i) {
        if (isprint(new_buf[i])) {
            dr_printf("%c", new_buf[i]);
        }
        else {
            dr_printf(".");
        }
        new_buf[i] = (TCHAR)'A';
        dr_printf("%c", new_buf[i]);
    }

    /*
	DWORD pathSize = GetFinalPathNameByHandle(hFile, filePath, MAX_PATH, 0);

	if (pathSize > MAX_PATH || pathSize == 0) {
		return false;
	}

	filePath[pathSize] = 0;

	HANDLE hPipe = CreateFile(
		TEXT("\\\\.\\pipe\\fuzz_server"),
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		return false;
	}

	DWORD readMode = PIPE_READMODE_MESSAGE;
	SetNamedPipeHandleState(
		hPipe,
		&readMode,
		NULL,
		NULL);

	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;

	if (!replay) {
		BYTE eventId = 1;

		WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);
		WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL);
		WriteFile(hPipe, &mutateCount, sizeof(DWORD), &bytesWritten, NULL);

		WriteFile(hPipe, &pathSize, sizeof(DWORD), &bytesWritten, NULL);
		WriteFile(hPipe, &filePath, pathSize * sizeof(TCHAR), &bytesWritten, NULL);

		WriteFile(hPipe, &position, sizeof(DWORD64), &bytesWritten, NULL);
		WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL);
		TransactNamedPipe(hPipe, buf, size, buf, size, &bytesRead, NULL);
	}
	else {
		BYTE eventId = 2;

		WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);
		WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL);
		WriteFile(hPipe, &mutateCount, sizeof(DWORD), &bytesWritten, NULL);
		TransactNamedPipe(hPipe, &size, sizeof(DWORD), buf, size, &bytesRead, NULL);
	}
	CloseHandle(hPipe);
	
    */
    mutateCount++;

	return true;
}
