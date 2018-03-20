#include <stdio.h>

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

static bool onexception(void *drcontext, dr_exception_t *excpt);
static void event_exit(void);
static void wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data);
static void wrap_post_ReadFile(void *wrapcxt, void *user_data);

static size_t max_ReadFile;
static void *max_lock; /* sync writes to max_ReadFile */

static BOOL mutate(HANDLE hFile, DWORD64 position, LPVOID buf, DWORD size);

DWORD runId;
BOOL crashed = false;

//TODO: Fix logging 
DWORD getRunID(HANDLE hPipe, LPCTSTR targetName, LPTSTR targetArgs) {
  dr_log(NULL, LOG_ALL, ERROR, "Requesting run id");
  DWORD bytesRead = 0;
  DWORD bytesWritten = 0;

  BYTE eventId = 0;
  DWORD runId = 0;
  if (!TransactNamedPipe(hPipe, &eventId, sizeof(BYTE), &runId, sizeof(DWORD), &bytesRead, NULL)) {
    dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
    dr_exit_process(1);
  }

  DWORD size = lstrlen(targetName) * sizeof(TCHAR);
  if (!WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL)) {
    dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
    dr_exit_process(1);
  }

  if (!WriteFile(hPipe, targetName, size, &bytesWritten, NULL)) {
    dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
    dr_exit_process(1);
  }

  size = lstrlen(targetArgs) * sizeof(TCHAR);
  if (!WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL)) {
    dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
    dr_exit_process(1);
  }

  if (!WriteFile(hPipe, targetArgs, size, &bytesWritten, NULL)) {
    dr_log(NULL, LOG_ALL, ERROR, "Error getting run id (%x)", GetLastError());
    dr_exit_process(1);
  }

  dr_log(NULL, LOG_ALL, ERROR, "Run id %x", runId);

  return runId;
}

HANDLE getPipe() {
  HANDLE hPipe;
  while (1) {
    hPipe = CreateFile(
      "\\\\.\\pipe\\fuzz_server",
      GENERIC_READ | GENERIC_WRITE,
      0,
      NULL,
      OPEN_EXISTING,
      0,
      NULL);

    if (hPipe != INVALID_HANDLE_VALUE) {
      break;
    }

    DWORD err = GetLastError();
    if (err != ERROR_PIPE_BUSY) {
      dr_log(NULL, LOG_ALL, ERROR, "Could not open pipe (%x)", err);
      return hPipe;
    }

    if (!WaitNamedPipe("\\\\.\\pipe\\fuzz_server", 5000)) {
      dr_log(NULL, LOG_ALL, ERROR, "Could not connect, timeout");
      // TODO: fallback mutations?
      dr_exit_process(1);
    }
  }

  DWORD readMode = PIPE_READMODE_MESSAGE;
  SetNamedPipeHandleState(
    hPipe,
    &readMode,
    NULL,
    NULL);

  return hPipe;
}

DWORD finalize(HANDLE hPipe, DWORD runId, BOOL crashed) {
  if (crashed) {
    dr_log(NULL, LOG_ALL, ERROR, "Crash found for run id %d!", runId);
  }
  DWORD bytesWritten;
  BYTE eventId = 4;

  if (!WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL)) {
    dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
    dr_exit_process(1);
  }

  if (!WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL)) {
    dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
    dr_exit_process(1);
  }

  if (!WriteFile(hPipe, &crashed, sizeof(BOOL), &bytesWritten, NULL)) {
    dr_log(NULL, LOG_ALL, ERROR, "Error finalizing (%x)", GetLastError());
    dr_exit_process(1);
  }

  return 0;
}

/* From wrap.cpp sample code. Called on application library load and unload.
   Responsible for registering pre and post callbacks for ReadFile. */
static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded) {
    app_pc towrap = (app_pc) dr_get_proc_address(mod->handle, "ReadFile");
    if (towrap != NULL) {
	    bool ok = drwrap_wrap(towrap, wrap_pre_ReadFile, wrap_post_ReadFile);
	    if (ok) {
		    dr_log(NULL, LOG_ALL, ERROR, "<wrapped ReadFile @ 0x%p\n", towrap);
	    } else {
		    dr_log(NULL, LOG_ALL, ERROR, "<FAILED to wrap ReadFile @ 0x%p: already wrapped?\n", towrap);
	    }
    }
    towrap = (app_pc) dr_get_proc_address(mod->handle, "ReadFileEx");
    if (towrap != NULL) {
	    bool ok = drwrap_wrap(towrap, wrap_pre_ReadFile, wrap_post_ReadFile);
	    if (ok) {
		    dr_log(NULL, LOG_ALL, ERROR, "<wrapped ReadFileEx @ 0x%p\n", towrap);
	    } else {
		    dr_log(NULL, LOG_ALL, ERROR, "<FAILED to wrap ReadFileEx @ 0x%p: already wrapped?\n", towrap);
	    }
    }
}

/* Runs after process initialization. Initializes DynamoRIO and registers module load callback*/
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    dr_set_client_name("Sienna-Locomotive Fuzzer",
                       "https://github.com/trailofbits/sienna-locomotive/issues");
    dr_log(NULL, LOG_ALL, 1, "DR client 'SL Fuzzer' initializing\n");
    if (dr_is_notify_on()) {
      #ifdef WINDOWS
	      dr_enable_console_printing();
      #endif
	  dr_log(NULL, LOG_ALL, ERROR, "Client SL Fuzzer is running\n");
    }

    //TODO: support multiple passes over one binary without re-running drrun

    // TODO: get arguments to target binary
    // see: https://github.com/DynamoRIO/dynamorio/issues/2662
    // alternatively: https://wj32.org/wp/2009/01/24/howto-get-the-command-line-of-processes/
    LPTSTR targetArgs;

    HANDLE hPipe = getPipe();
    runId = getRunID(hPipe, dr_get_application_name(), targetArgs);
    CloseHandle(hPipe);

    drmgr_init();
    drwrap_init();
    
    max_ReadFile = 0;

    drmgr_register_exception_event(onexception);
    dr_register_exit_event(event_exit);
    drmgr_register_module_load_event(module_load_event);
}

static bool
onexception(void *drcontext, dr_exception_t *excpt) {
  dr_log(NULL, LOG_ALL, ERROR, "Exception occurred!\n");

  crashed = true;
  DWORD exceptionCode = excpt->record->ExceptionCode;

  switch (exceptionCode){
    case EXCEPTION_ACCESS_VIOLATION:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_ACCESS_VIOLATION");
      break;
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
      break;
    case EXCEPTION_BREAKPOINT:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_BREAKPOINT");
      crashed = false;
      //TODO: double check that this is correct
      break;
    case EXCEPTION_DATATYPE_MISALIGNMENT:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_DATATYPE_MISALIGNMENT");
      break;
    case EXCEPTION_FLT_DENORMAL_OPERAND:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_DENORMAL_OPERAND");
      break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_DIVIDE_BY_ZERO");
      break;
    case EXCEPTION_FLT_INEXACT_RESULT:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_INEXACT_RESULT");
      break;
    case EXCEPTION_FLT_INVALID_OPERATION:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_INVALID_OPERATION");
      break;
    case EXCEPTION_FLT_OVERFLOW:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_OVERFLOW");
      break;
    case EXCEPTION_FLT_STACK_CHECK:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_STACK_CHECK");
      break;
    case EXCEPTION_FLT_UNDERFLOW:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_FLT_UNDERFLOW");
      break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_ILLEGAL_INSTRUCTION");
      break;
    case EXCEPTION_IN_PAGE_ERROR:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_IN_PAGE_ERROR");
      break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_INT_DIVIDE_BY_ZERO");
      break;
    case EXCEPTION_INT_OVERFLOW:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_INT_OVERFLOW");
      break;
    case EXCEPTION_INVALID_DISPOSITION:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_INVALID_DISPOSITION");
      break;
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_NONCONTINUABLE_EXCEPTION");
      break;
    case EXCEPTION_PRIV_INSTRUCTION:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_PRIV_INSTRUCTION");
      break;
    case EXCEPTION_SINGLE_STEP:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_SINGLE_STEP");
      break;
    case EXCEPTION_STACK_OVERFLOW:
      dr_log(NULL, LOG_ALL, ERROR, "EXCEPTION_STACK_OVERFLOW");
      break;
    default:
      break;
  }

  return true;
}

/* from wrap.cpp sample code */
static void
event_exit(void) {
  HANDLE hPipe = getPipe();
  finalize(hPipe, runId, crashed);
  CloseHandle(hPipe);

  dr_log(NULL, LOG_ALL, ERROR, "Dynamorio Exiting\n");
    drwrap_exit();
    drmgr_exit();
}


DWORD64 position = 0;
DWORD   nNumberOfBytesToRead;
LPDWORD lpNumberOfBytesRead;
HANDLE  hFile;
/* from wrap.cpp sample code. Runs before ReadFile is called. Records arguments to
   ReadFile and stores them in probably thread-unsafe variables above. */
static void
wrap_pre_ReadFile(void *wrapcxt, OUT void **user_data) {
    hFile =                drwrap_get_arg(wrapcxt, 0);
    LPVOID lpBuffer =      drwrap_get_arg(wrapcxt, 1);
    nNumberOfBytesToRead = (DWORD)drwrap_get_arg(wrapcxt, 2);
    lpNumberOfBytesRead =  (LPDWORD)drwrap_get_arg(wrapcxt, 3);
    
    *user_data = lpBuffer;
    
    LONG positionHigh = 0;
    DWORD positionLow = SetFilePointer(hFile, 0, &positionHigh, FILE_CURRENT);
    DWORD64 position = positionHigh;
    position = (position << 32) | positionLow;
}

/* Called after ReadFile returns. Calls `mutate` on the bytes that ReadFile
   wrote into the program's memory. */
static void
wrap_post_ReadFile(void *wrapcxt, void *user_data) {
    LPVOID lpBuffer = user_data;
	  if (lpNumberOfBytesRead) {
        nNumberOfBytesToRead = *lpNumberOfBytesRead;
    }
    
    if (!mutate(hFile, position, lpBuffer, nNumberOfBytesToRead)) {
        // TODO: fallback mutations?
        //TCHAR *new_buf = (TCHAR *)lpBuffer;
        //for(DWORD i = 0; i < nNumberOfBytesToRead; ++i) {
        //    new_buf[i] = (TCHAR)'A';
        //}
    }

    if (lpNumberOfBytesRead != NULL) {
        *lpNumberOfBytesRead = nNumberOfBytesToRead;
    }
    
    drwrap_set_mcontext(wrapcxt); // is this necessary?

    BOOL ok = TRUE; 
    drwrap_set_retval(wrapcxt, &ok); // FIXME
}

/* Hands bytes off to the mutation server, gets mutated bytes, and writes them into memory. */
static DWORD mutateCount = 0;
static BOOL mutate(HANDLE hFile, DWORD64 position, LPVOID buf, DWORD size) {
	TCHAR filePath[MAX_PATH+1];
    TCHAR *new_buf = (TCHAR *)buf;

    if (hFile == INVALID_HANDLE_VALUE) {
		dr_log(NULL, LOG_ALL, ERROR, "The file we're trying to write to doesn't appear to be valid\n");
        return false;
    }

	DWORD pathSize = GetFinalPathNameByHandle(hFile, filePath, MAX_PATH, 0);

	if (pathSize > MAX_PATH || pathSize == 0) {
		dr_log(NULL, LOG_ALL, ERROR, "Pathsize %d is out of bounds\n", pathSize);
        return false;
	}

	filePath[pathSize] = 0;

  HANDLE hPipe = getPipe();

	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;

	BYTE eventId = 1;

	// Send state information to the fuzz server
	WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);
	WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL);
	WriteFile(hPipe, &mutateCount, sizeof(DWORD), &bytesWritten, NULL);

	WriteFile(hPipe, &pathSize, sizeof(DWORD), &bytesWritten, NULL);
	WriteFile(hPipe, &filePath, pathSize * sizeof(TCHAR), &bytesWritten, NULL);

	WriteFile(hPipe, &position, sizeof(DWORD64), &bytesWritten, NULL);
	WriteFile(hPipe, &size, sizeof(DWORD), &bytesWritten, NULL);
		
	// Send current contents of buf to the server, overwrite them with its reply
	TransactNamedPipe(hPipe, buf, size, buf, size, &bytesRead, NULL);

	CloseHandle(hPipe);
    
    mutateCount++;

	return true;
}
