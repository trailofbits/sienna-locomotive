#include <random>
#define NOMINMAX
#include <Windows.h>
#include <set>
#include <unordered_map>

#define LOGURU_IMPLEMENTATION 1
#include "loguru.hpp"

#define BUFSIZE 100000
#include <ShlObj.h>
#include <PathCch.h>
#pragma comment(lib, "Pathcch.lib")

CRITICAL_SECTION critId;
CRITICAL_SECTION critLog;

HANDLE hLog = INVALID_HANDLE_VALUE;

WCHAR FUZZ_WORKING_STAR[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_PROGRAM[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_ARGS[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_FKT[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_STAR[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_FMT[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_EXECUTION[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_MEM[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_CRASH[MAX_PATH] = L"";
WCHAR FUZZ_WORKING_FMT_JSON[MAX_PATH] = L"";
WCHAR FUZZ_LOG[MAX_PATH] = L"";

VOID initDirs() {
	PWSTR roamingPath;
	SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roamingPath);
	WCHAR workingLocalPath[MAX_PATH] = L"Trail of Bits\\fuzzkit\\working";
	WCHAR combinedPath[MAX_PATH] = L"";
	PathCchCombine(combinedPath, MAX_PATH, roamingPath, workingLocalPath);

	PathCchCombine(FUZZ_WORKING_STAR, MAX_PATH, combinedPath, L"*");
	PathCchCombine(FUZZ_WORKING_FMT, MAX_PATH, combinedPath, L"%d");
	PathCchCombine(FUZZ_WORKING_FMT_PROGRAM, MAX_PATH, FUZZ_WORKING_FMT, L"program.txt");
	PathCchCombine(FUZZ_WORKING_FMT_ARGS, MAX_PATH, FUZZ_WORKING_FMT, L"arguments.txt");
	PathCchCombine(FUZZ_WORKING_FMT_FKT, MAX_PATH, FUZZ_WORKING_FMT, L"%d.fkt");
	PathCchCombine(FUZZ_WORKING_FMT_STAR, MAX_PATH, FUZZ_WORKING_FMT, L"*");
	PathCchCombine(FUZZ_WORKING_FMT_FMT, MAX_PATH, FUZZ_WORKING_FMT, L"%s");
	PathCchCombine(FUZZ_WORKING_FMT_EXECUTION, MAX_PATH, FUZZ_WORKING_FMT, L"execution.trc");
	PathCchCombine(FUZZ_WORKING_FMT_MEM, MAX_PATH, FUZZ_WORKING_FMT, L"mem.dmp");
	PathCchCombine(FUZZ_WORKING_FMT_CRASH, MAX_PATH, FUZZ_WORKING_FMT, L"execution.csh");
    PathCchCombine(FUZZ_WORKING_FMT_JSON, MAX_PATH, FUZZ_WORKING_FMT, L"crash.json");

	SHGetKnownFolderPath(FOLDERID_RoamingAppData, NULL, NULL, &roamingPath);
	WCHAR logLocalPath[MAX_PATH] = L"Trail of Bits\\fuzzkit\\log\\server.log";
	PathCchCombine(FUZZ_LOG, MAX_PATH, roamingPath, logLocalPath);

	CoTaskMemFree(roamingPath);
}

DWORD findUnusedId() {
	HANDLE hFind;
	WIN32_FIND_DATA findData;
	std::set<UINT64> usedIds;

	EnterCriticalSection(&critId);
	
	hFind = FindFirstFile(FUZZ_WORKING_STAR, &findData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (findData.cFileName[0] >= 0x30 && findData.cFileName[0] <= 0x39) {
				UINT64 runId = wcstoul(findData.cFileName, NULL, 0);
				usedIds.insert(runId);
			}
		} while (FindNextFile(hFind, &findData));
		FindClose(hFind);
	}

	DWORD id = 0;
	for (id = 0; id <= UINT64_MAX; id++) {
		if (usedIds.find(id) == usedIds.end()) {
			LOG_F(INFO, "Found run id %x", id);
			break;
		}
	}

	WCHAR targetDir[MAX_PATH];
	wsprintf(targetDir, FUZZ_WORKING_FMT, id);
	if(!CreateDirectory(targetDir, NULL)) {
		LOG_F(ERROR, "FindUnusedId (0x%x)", GetLastError());
		exit(1);
	}

	LeaveCriticalSection(&critId);

	return id;
}

DWORD generateRunId(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	LOG_F(INFO, "Run id requested");
	DWORD runId = findUnusedId();

	BOOL success = WriteFile(hPipe, &runId, sizeof(DWORD), &dwBytesWritten, NULL);

	// get program name
	TCHAR commandLine[8192] = { 0 };
	DWORD size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	if (size > 8191) {
		LOG_F(ERROR, "Invalid size for command name");
		return 1;
	}
	
	if(!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	wsprintf(targetFile, FUZZ_WORKING_FMT_PROGRAM, runId);
	HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}
	
	ZeroMemory(commandLine, 8192 * sizeof(TCHAR));

	// get program arguments
	size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	if (size > 8191) {
		LOG_F(ERROR, "Invalid size for command name");
		return 1;
	}
	
	if(!ReadFile(hPipe, commandLine, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	ZeroMemory(targetFile, (MAX_PATH + 1)*sizeof(WCHAR));
	wsprintf(targetFile, FUZZ_WORKING_FMT_ARGS, runId);
	hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hFile, commandLine, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "GenerateRunId (0x%x)", GetLastError());
		exit(1);
	}

	return 0;
}

VOID strategyAAAA(BYTE *buf, DWORD size) {
	for (DWORD i = 0; i < size; i++) {
		buf[i] = 'A';
	}
}

VOID strategyRandByte(BYTE *buf, DWORD size) {
	std::random_device rd;
	srand(rd());
	DWORD random = rand();
	random <<= 15;
	random |= rand();

	DWORD pos = random % size;
	BYTE mut = rand() % 256;

	buf[pos] = mut;
}

DWORD mutate(BYTE *buf, DWORD size) {
	strategyRandByte(buf, size);
	return 0;
}

DWORD writeFKT(HANDLE hFile, DWORD type, DWORD pathSize, TCHAR *filePath, DWORD64 position, DWORD size, BYTE* buf) {
	DWORD dwBytesWritten = 0;

	if (!WriteFile(hFile, "FKT\0", 4, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	// only one type for right now, files
	if (!WriteFile(hFile, &type, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, &pathSize, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, filePath, pathSize * sizeof(TCHAR), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, &position, sizeof(DWORD64), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, &size, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	if (!WriteFile(hFile, buf, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	if (!CloseHandle(hFile)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD handleMutation(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	DWORD type = 0;
	if(!ReadFile(hPipe, &type, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	DWORD mutateCount = 0;
	if(!ReadFile(hPipe, &mutateCount, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	DWORD pathSize = 0;
	if (!ReadFile(hPipe, &pathSize, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	if (pathSize > MAX_PATH) {
		LOG_F(ERROR, "HandleMutation MAX_PATH", GetLastError());
		exit(1);
	}

	TCHAR filePath[MAX_PATH + 1];
	if (!ReadFile(hPipe, &filePath, pathSize * sizeof(TCHAR), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	filePath[pathSize] = 0;

	DWORD64 position = 0;
	if (!ReadFile(hPipe, &position, sizeof(DWORD64), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	DWORD size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}
	
	HANDLE hHeap = GetProcessHeap();
	if(hHeap == NULL) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));
	
	if(buf == NULL) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}
	
	if(!ReadFile(hPipe, buf, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	if (dwBytesRead != size) {
		size = dwBytesRead;
	}

	mutate(buf, size);
	
	if(!WriteFile(hPipe, buf, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	WCHAR targetFile[MAX_PATH+1];
	wsprintf(targetFile, FUZZ_WORKING_FMT_FKT, runId, mutateCount);
	HANDLE hFile = CreateFile(targetFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	writeFKT(hFile, type, pathSize, filePath, position, size, buf);

	if(!HeapFree(hHeap, NULL, buf)) {
		LOG_F(ERROR, "HandleMutation (0x%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD getBytesFKT(HANDLE hFile, BYTE *buf, DWORD size) {
	DWORD dwBytesRead = 0;

	SetFilePointer(hFile, -(LONG)size, NULL, FILE_END);

	if (!ReadFile(hFile, buf, size, &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD handleReplay(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	DWORD mutateCount = 0;
	
	if(!ReadFile(hPipe, &mutateCount, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	// TODO: validate size matches file size
	DWORD size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	HANDLE hHeap = GetProcessHeap();

	if(hHeap == NULL) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	BYTE* buf = (BYTE*)HeapAlloc(hHeap, 0, size * sizeof(BYTE));
	
	if(buf == NULL) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	WCHAR targetFile[MAX_PATH + 1];
	wsprintf(targetFile, FUZZ_WORKING_FMT_FKT, runId, mutateCount);
	// TODO: validate file exists
	HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	getBytesFKT(hFile, buf, size);
	
	if(!WriteFile(hPipe, buf, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}
	
	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	if(!HeapFree(hHeap, NULL, buf)) {
		LOG_F(ERROR, "HandleReplay (0x%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD serveRunInfo(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	TCHAR commandLine[8192] = { 0 };
	WCHAR targetFile[MAX_PATH + 1] = { 0 };

	wsprintf(targetFile, FUZZ_WORKING_FMT_PROGRAM, runId);
	HANDLE hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}
	
	if(!ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}
	
	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	ZeroMemory(commandLine, 8192 * sizeof(TCHAR));
	ZeroMemory(targetFile, (MAX_PATH + 1) * sizeof(WCHAR));
	wsprintf(targetFile, FUZZ_WORKING_FMT_ARGS, runId);
	
	hFile = CreateFile(targetFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

	if(hFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	if(!ReadFile(hFile, commandLine, 8191 * sizeof(TCHAR), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hFile)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &dwBytesRead, sizeof(DWORD), &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, commandLine, dwBytesRead, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "serveRunInfo (0x%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD finalizeRun(HANDLE hPipe) {
	DWORD dwBytesRead = 0;

	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "FinalizeRun (0x%x)", GetLastError());
		exit(1);
	}

	BOOL crash = false;
	if(!ReadFile(hPipe, &crash, sizeof(BOOL), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "FinalizeRun (0x%x)", GetLastError());
		exit(1);
	}
	LOG_F(INFO, "Finalizing run %x", runId);

	if (!crash) {
		LOG_F(INFO, "No crash removing run %x", runId);
		EnterCriticalSection(&critId);
		WIN32_FIND_DATA findData;
		WCHAR targetFile[MAX_PATH + 1] = { 0 };
		wsprintf(targetFile, FUZZ_WORKING_FMT_STAR, runId);

		// empty directory
		HANDLE hFind = FindFirstFile(targetFile, &findData);
		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				// TODO: this will fail on directories, but we don't have any directories yet
				wsprintf(targetFile, FUZZ_WORKING_FMT_FMT, runId, findData.cFileName);
				DeleteFile(targetFile);
			} while (FindNextFile(hFind, &findData));
			FindClose(hFind);
		}

		wsprintf(targetFile, FUZZ_WORKING_FMT, runId);
		if(!RemoveDirectory(targetFile)) {
			LOG_F(ERROR, "FinalizeRun (0x%x)", GetLastError());
			exit(1);
		}

		LeaveCriticalSection(&critId);
	}
	else {
		LOG_F(INFO, "Crash found for run %x", runId);
	}

	return 0;
}

DWORD crashPath(HANDLE hPipe) {
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	
	DWORD runId = 0;
	if(!ReadFile(hPipe, &runId, sizeof(DWORD), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "crashPath (0x%x)", GetLastError());
		exit(1);
	}

	WCHAR targetFile[MAX_PATH + 1] = { 0 };
	int len = wsprintf(targetFile, FUZZ_WORKING_FMT_JSON, runId);
	DWORD size = (wcslen(targetFile) + 1) * sizeof(WCHAR);

	if(!WriteFile(hPipe, &targetFile, size, &dwBytesWritten, NULL)) {
		LOG_F(ERROR, "crashPath (0x%x)", GetLastError());
		exit(1);
	}

	return 0;
}

// TODO: check then delete all the tracing stuff
enum Event {
	EVT_RUN_ID,				// 0
	EVT_MUTATION,			// 1
	EVT_REPLAY,				// 2
	EVT_RUN_INFO,			// 3
	EVT_RUN_COMPLETE,		// 4
	EVT_CRASH_PATH,			// 5
};

DWORD WINAPI threadHandler(LPVOID lpvPipe) {
	HANDLE hPipe = (HANDLE)lpvPipe;

	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;

	BYTE eventId = 255;
	if(!ReadFile(hPipe, &eventId, sizeof(BYTE), &dwBytesRead, NULL)) {
		LOG_F(ERROR, "ThreadHandler (0x%x)", GetLastError());
		exit(1);
	}

	switch (eventId) {
		case EVT_RUN_ID:
			generateRunId(hPipe);
			break;
		case EVT_MUTATION:
			handleMutation(hPipe);
			break;
		case EVT_REPLAY:
			handleReplay(hPipe);
			break;
		case EVT_RUN_INFO:
			serveRunInfo(hPipe);
			break;
		case EVT_RUN_COMPLETE:
			finalizeRun(hPipe);
			break;
		case EVT_CRASH_PATH:
			crashPath(hPipe);
			break;
		default:
			LOG_F(ERROR, "Unknown or invalid event id %x", eventId);
			break;
	}

	if(!FlushFileBuffers(hPipe)) {
		LOG_F(ERROR, "ThreadHandler (0x%x)", GetLastError());
		exit(1);
	}

	if(!DisconnectNamedPipe(hPipe)) {
		LOG_F(ERROR, "ThreadHandler (0x%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hPipe)) {
		LOG_F(ERROR, "ThreadHandler (0x%x)", GetLastError());
		exit(1);
	}

	return 0;
}

HANDLE hProcessMutex = INVALID_HANDLE_VALUE;

void lockProcess() {
	hProcessMutex = CreateMutex(NULL, FALSE, L"fuzz_server_mutex");
	if(!hProcessMutex || hProcessMutex == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "Could not get process lock (handle)");
		exit(1);
	}

	DWORD result = WaitForSingleObject(hProcessMutex, 0);
	if(result != WAIT_OBJECT_0) {
		LOG_F(ERROR, "Could not get process lock (lock)");
		exit(1);
	}
}

int main(int mArgc, char **mArgv)
{
	initDirs();
	
	loguru::init(mArgc, mArgv);
	CHAR logLocalPathA[MAX_PATH];
	wcstombs(logLocalPathA, FUZZ_LOG, MAX_PATH);
	loguru::add_file(logLocalPathA, loguru::Append, loguru::Verbosity_MAX);
	
	LOG_F(INFO, "Server started!");

	lockProcess();

	InitializeCriticalSection(&critId);
	InitializeCriticalSection(&critLog);

	while (1) {
		DWORD outSize = BUFSIZE;
		DWORD inSize = BUFSIZE;
		HANDLE hPipe = CreateNamedPipe(
			L"\\\\.\\pipe\\fuzz_server",
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
			PIPE_UNLIMITED_INSTANCES,
			outSize,
			inSize,
			0,
			NULL
		);

		if (hPipe == INVALID_HANDLE_VALUE) {
			LOG_F(ERROR, "Could not create pipe");
			return 1;
		}

		BOOL connected = ConnectNamedPipe(hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (connected) {
			DWORD threadID;
			HANDLE hThread = CreateThread(
				NULL,
				0,
				threadHandler,
				(LPVOID)hPipe,
				0,
				&threadID);

			if (hThread == NULL)
			{
				LOG_F(ERROR, "CreateThread (0x%x)\n", GetLastError());
				return -1;
			}
			else {
				CloseHandle(hThread);
			}
		}
		else {
			LOG_F(ERROR, "Could not connect to hPipe");
			CloseHandle(hPipe);
		}
	}

	// TODO: stop gracefully?
	ReleaseMutex(hProcessMutex);
	CloseHandle(hProcessMutex);
	DeleteCriticalSection(&critId);
	DeleteCriticalSection(&critLog);
    return 0;
}

