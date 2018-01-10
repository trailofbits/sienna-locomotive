// injectable.cpp : Defines the exported functions for the DLL application.
//

#include <stdio.h>
#include <Windows.h>

extern "C" __declspec(dllexport) DWORD runId;
__declspec(dllexport) DWORD runId;

extern "C" __declspec(dllexport) BOOL replay;
__declspec(dllexport) BOOL replay;

extern "C" __declspec(dllexport) BOOL trace;
__declspec(dllexport) BOOL trace;

extern "C" __declspec(dllexport) VOID asm_trace();
__declspec(dllexport) VOID asm_trace();

DWORD mutateCount = 0;

BOOL mutate(HANDLE hFile, DWORD64 position, LPVOID buf, DWORD size) {
	TCHAR filePath[MAX_PATH+1];

	DWORD pathSize = GetFinalPathNameByHandle(hFile, filePath, MAX_PATH, 0);

	if (pathSize > MAX_PATH || pathSize == 0) {
		return false;
	}

	filePath[pathSize] = 0;

	HANDLE hPipe = CreateFile(
		L"\\\\.\\pipe\\fuzz_server",
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
	mutateCount++;

	return true;
}

VOID taint(LPVOID buf, DWORD size) {
	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;

	HANDLE hPipe = CreateFile(
		L"\\\\.\\pipe\\fuzz_server",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hPipe == INVALID_HANDLE_VALUE) {
		// TODO: fallback mutations?
		return;
	}

	DWORD readMode = PIPE_READMODE_MESSAGE;
	SetNamedPipeHandleState(
		hPipe,
		&readMode,
		NULL,
		NULL);

	BYTE eventId = 7;
	UINT64 taintAddr = (UINT64)buf;
	UINT64 taintSize = (UINT64)size;

	WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);
	WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL);
	WriteFile(hPipe, &taintAddr, sizeof(UINT64), &bytesWritten, NULL);

	BYTE nullByte = 0;
	TransactNamedPipe(hPipe, &taintSize, sizeof(UINT64), &nullByte, sizeof(BYTE), &bytesRead, NULL);
	CloseHandle(hPipe);
}

extern "C" __declspec(dllexport) VOID traceSelf(UINT64 returnAddr) {
	return;
}

extern "C" __declspec(dllexport) BOOL WINAPI ReadFileHook(
	HANDLE       hFile,
	LPVOID       lpBuffer,
	DWORD        nNumberOfBytesToRead,
	LPDWORD      lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) 
{
	LONG positionHigh = 0;
	DWORD positionLow = SetFilePointer(hFile, 0, &positionHigh, FILE_CURRENT);
	DWORD64 position = positionHigh;
	position = (position << 32) | positionLow;

	ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);

	// mutate or replay
	if (!replay && !trace || replay) {
		if (!mutate(hFile, position, lpBuffer, nNumberOfBytesToRead)) {
			// TODO: fallback mutations?
		}
	}

	if (trace) {
		taint(lpBuffer, nNumberOfBytesToRead);
	}

	if (lpNumberOfBytesRead != NULL) {
		*lpNumberOfBytesRead = nNumberOfBytesToRead;
	}

	return true;
}