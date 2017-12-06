#include "stdafx.h"
#include "Tracer.h"

/*
                .yNss/-.                                                                             
                 .hMMMNddh+.`                                                                       
                   -yMMMMMMMMmyys---                                                                
                     -hMMMMMMMMMMMMNdddh+++/```````````                                             
                       -ydMMMMMMMMMMMMMMMMMMNNNNNNNNNNmyyyy/:-                                      
                         `/dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNdd++-`                                
                           `+MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNy+:                             
                            `NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNd+:                          
                             -hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNhs.                       
 .`                           `+mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNs.                     
.hhs:.                          .sMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmo.                   
 `+mMmdh++-..`                   `+dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmo.  //             
   .dMMMMMNNNhyyy/:::::::-``````   `+mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmo`mN/            
    `/dMMMMMMMMMMMMMMMMMMNdddddd++:...+mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMyNMN/           
      `dNMMMMMMMMMMMMMMMMMMMMMMMMMNNNdydMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN:          
       `/hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm`         
         `/NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy`        
           :hNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMo        
             :hNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-       
               :omNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm`      
                  `/shNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMh      
  ```                 ./oNNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN+     
  oMNyyyy+:::::::::::::oyydMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm-    
   oNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy.   
    -mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN+  
     `+NMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNy.
       `+mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-
         `.sNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMo 
            .:hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm: 
               `/omNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMs  
                  `.shMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMm   
                      `:odNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMo   
                         `.::hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMN`   
                             `oNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmmMMMMMMMM+    
                              -mMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMmy+`/MMMMMMMy`    
                             :dMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMdhy/.  -NMMMMMN+     
                           `yNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNNNNhysoNdmNNmh/.hMMMMMh      
                         `/hMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNddddddo+++++-...-ymNMMMMMMMMyMMMMMM.      
                         oMMMMMMMMMMMMMMMMMMMMMMMMMMm::::-``````       `-sNMMMMMNNNMMMMMMMMMh       
                       .oMMMMMMMMMMMMMMMMmd+++dmMMMMNs-`             `+dNMMMMmo/..-yMMMMMMMM-       
                      .hMMMMMMMMMMMMMNMMh.     .omMMMMMm+:``     ``/hmMMMMNyo.     +MMMMMMMs`       
                     `hMMMMMMMMMMMMMMsdMm-       .+yNMMMMMmyssssymmMMMMMNy-        +MMMMMMN/        
                    `hMMMMMMMMNhhMMMMohMM+          -yNNMMMMMMMMMMMMMNhs-          oMMMMMMs         
                   `yMMMNNmmo/. .NMMMosMM+            .:+dmmNNNNNmmo+:`           .NMMMMMm`         
                  `sNyy+:-       +MMN: NMm.                 -:::-                 -MMMMNM:          
                   ..            +Mms  oMM/                `.---.`                yMMMmmm`          
                                 +M.   .NMM`            `.ohNMMMNho.`            :MMMN+N:           
                                 /N.    /NMh.        `:smNMMMMMMMMMNm+-`       `+NMNNd `            
                                  .      sMMmo/   //ydMMMMMMyyyyyMMMMMMdy/.   /mMMN/.               
                                          /mMMMNNNMMMMMMm+:`     -+hmMMMMMMNNNMMMm/                 
                                           `+mMMMMMMMyo-`           `-oyMMMMMMMm+`.cpp          
*/

DWORD Tracer::singleStep(HANDLE hThread) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_CONTROL;
	SuspendThread(hThread);
	GetThreadContext(hThread, &context);
	context.EFlags = context.EFlags | (1 << 8);

	if (!SetThreadContext(hThread, &context)) {
		printf("ERROR: SetThreadContext (%x)\n", GetLastError());
		return 1;
	}

	ResumeThread(hThread);
	return 0;
}

DWORD Tracer::setBreak(HANDLE hProcess, UINT64 address) {
	BYTE breakByte = 0xCC;
	BYTE startByte;
	ReadProcessMemory(hProcess, (LPVOID)address, &startByte, sizeof(BYTE), NULL);
	WriteProcessMemory(hProcess, (LPVOID)address, &breakByte, sizeof(BYTE), NULL);
	restoreBytes[(LPVOID)address] = startByte;
	//printf("INFO: setBreak at %x\n", address);
	return 0;
}

BOOL Tracer::restoreBreak(HANDLE hProcess, HANDLE hThread) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	GetThreadContext(hThread, &context);
	//printf("RIP: %x\n", context.Rip);
	
	context.Rip -= 1;

	if (restoreBytes.find((LPVOID)context.Rip) == restoreBytes.end()) {
		printf("ERROR: restoreBytes miss at %x\n", context.Rip);
		return false;
	}
		
	SetThreadContext(hThread, &context);
	WriteProcessMemory(hProcess, (LPVOID)context.Rip, &restoreBytes[(LPVOID)context.Rip], sizeof(BYTE), NULL);
	
	return true;
}

BOOL Tracer::isTerminator(xed_decoded_inst_t xedd) {
	xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass(&xedd);

	switch (iclass) {
		case XED_ICLASS_RET_NEAR:
		case XED_ICLASS_RET_FAR:
		case XED_ICLASS_SYSCALL:
		case XED_ICLASS_SYSCALL_AMD:
		case XED_ICLASS_SYSENTER:
		case XED_ICLASS_SYSRET:
		case XED_ICLASS_SYSRET_AMD:
		case XED_ICLASS_SYSEXIT:
		case XED_ICLASS_INT:
		case XED_ICLASS_INT1:
		case XED_ICLASS_INT3:
		case XED_ICLASS_INTO:
		case XED_ICLASS_BOUND:
		case XED_ICLASS_CALL_NEAR:
		case XED_ICLASS_CALL_FAR:
		case XED_ICLASS_JMP:
		case XED_ICLASS_JMP_FAR:
		case XED_ICLASS_XEND:
		case XED_ICLASS_XABORT:
		case XED_ICLASS_HLT:
		case XED_ICLASS_UD2:
		case XED_ICLASS_INVALID:
			return true;
		default:
			break;
	}

	if (XED_ICLASS_IRET <= iclass && XED_ICLASS_IRETQ >= iclass) {
		return true;
	}

	xed_category_enum_t cat = xed_decoded_inst_get_category(&xedd);
	if (XED_CATEGORY_COND_BR == cat ||
		XED_CATEGORY_NOP == cat ||
		XED_CATEGORY_WIDENOP == cat) 
	{
		return true;
	}

	return false;
}

HANDLE Tracer::tracerGetPipe() {
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
		printf("ERROR: trc could not connect to server\n");
		exit(1);
	}

	DWORD readMode = PIPE_READMODE_MESSAGE;
	SetNamedPipeHandleState(
		hPipe,
		&readMode,
		NULL,
		NULL);

	return hPipe;
}

DWORD Tracer::traceInit(DWORD runId, HANDLE hProc, DWORD procId) {
	printf("in init\n");
	DWORD bytesRead;
	DWORD bytesWritten;
	HANDLE hPipe = tracerGetPipe();
	
	BYTE eventId = 5;
	WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);

	WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL);

	DWORD size = 0;
	ReadFile(hPipe, &size, sizeof(DWORD), &bytesRead, NULL);
	
	// get minidump path
	HANDLE hHeap = GetProcessHeap();
	WCHAR *minidumpPath = (WCHAR *)HeapAlloc(hHeap, NULL, size);
	ReadFile(hPipe, minidumpPath, size, &bytesRead, NULL);

	// open file
	HANDLE minidumpFile = CreateFile(minidumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	// write minidump
	DWORD type = MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo;
	MiniDumpWriteDump(hProc, procId, minidumpFile, (MINIDUMP_TYPE)type, NULL, NULL, NULL);

	HeapFree(hHeap, NULL, minidumpPath);
	CloseHandle(hPipe);
	return 0;
}

HANDLE Tracer::tracerGetPipeInsn(DWORD runId) {
	if (hPipeInsn == INVALID_HANDLE_VALUE) {
		printf("NEW INSN PIPE\n");
		hPipeInsn = CreateFile(
			L"\\\\.\\pipe\\fuzz_server",
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (hPipeInsn == INVALID_HANDLE_VALUE) {
			DWORD err = GetLastError();
			printf("ERROR: insn trc could not connect to server (%x)\n", err);
			exit(1);
		}

		DWORD readMode = PIPE_READMODE_MESSAGE;
		SetNamedPipeHandleState(
			hPipeInsn,
			&readMode,
			NULL,
			NULL);

		BYTE eventId = 6;
		DWORD bytesWritten;
		WriteFile(hPipeInsn, &eventId, sizeof(BYTE), &bytesWritten, NULL);

		WriteFile(hPipeInsn, &runId, sizeof(DWORD), &bytesWritten, NULL);
	}

	return hPipeInsn;
}

DWORD Tracer::traceInsn(DWORD runId, UINT64 addr, UINT64 traceSize, BYTE *trace) {
	DWORD bytesRead;
	DWORD bytesWritten;
	HANDLE hPipe = tracerGetPipeInsn(runId);

	// send head address to server
	WriteFile(hPipe, &addr, sizeof(UINT64), &bytesWritten, NULL);

	// send trace size to server
	WriteFile(hPipe, &traceSize, sizeof(UINT64), &bytesWritten, NULL);

	//printf("%x, %x, %x\t", runId, addr, traceSize);
	//for (int i = 0; i < traceSize; i++) {
	//	printf("%x ", trace[i]);
	//}
	//printf("\n");

	// send trace to server
	BYTE nullByte = 0;
	TransactNamedPipe(hPipe, trace, traceSize, &nullByte, sizeof(BYTE), &bytesRead, NULL);

	return 0;
}

DWORD Tracer::traceCrash(DWORD runId, UINT64 exceptionAddr, DWORD exceptionCode) {
	printf("in crash\n");
	DWORD bytesRead;
	DWORD bytesWritten;

	HANDLE hInsnPipe = tracerGetPipeInsn(runId);
	UINT64 zero = 0;
	WriteFile(hInsnPipe, &zero, sizeof(UINT64), &bytesWritten, NULL);
	WriteFile(hInsnPipe, &zero, sizeof(UINT64), &bytesWritten, NULL);

	HANDLE hPipe = tracerGetPipe();

	BYTE eventId = 8;
	WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL);

	WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL);

	// send crash addr to server
	WriteFile(hPipe, &exceptionAddr, sizeof(UINT64), &bytesWritten, NULL);

	// send crash type to server
	BYTE nullByte = 0;
	TransactNamedPipe(hPipe, &exceptionCode, sizeof(DWORD), &nullByte, sizeof(BYTE), &bytesRead, NULL);
	CloseHandle(hPipe);

	return 0;
}

UINT64 Tracer::trace(HANDLE hProcess, PVOID address, DWORD runId) {
	/* 
	trace format
		in tracer::trace:
			bb head addr
			insn size, insn
		in injectable:
			taint size, buf addr
		in fuzzkit (on crash):
			crash addr
			crash type
	*/

	// check cache
	//If have address:
	//	Set break on end of bb
	//	Record trace (bb)
	struct BasicBlock bb;
	std::list<struct Instruction> insnList;
	if (cache.HasBB((UINT64)address)) {
		//printf("HIT: found bb at %x\n", address);
		bb = cache.FetchBB((UINT64)address);
	}
	else {
		//printf("MISS: new bb at %x\n", address);
		bb.head = (UINT64)address;
		
		xed_decoded_inst_t xedd;
		xedd._decoded_length = 0;
		UINT64 currAddr = (UINT64)address;
		DWORD traceSize = 0;

		do {
			currAddr += xedd._decoded_length;
			struct Instruction insn;
			xed_error_enum_t xed_err;
			ReadProcessMemory(hProcess, (LPVOID)currAddr, insn.bytes, 15, NULL);

			xed_decoded_inst_zero(&xedd);
			xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
			xed_err = xed_decode(&xedd, insn.bytes, 15);
			insn.length = xedd._decoded_length;
			insnList.push_back(insn);
			
			traceSize += 1;
			traceSize += insn.length;

			//CHAR outBuf[1024];
			//xed_decoded_inst_dump(&xedd, outBuf, 1024);
			//xed_format_context(XED_SYNTAX_INTEL, &xedd, outBuf, 1024, 0, 0, 0);
			//printf("%s\n", outBuf);
		} while (!isTerminator(xedd));
		
		bb.bbTrace = (BYTE *)HeapAlloc(hHeap, NULL, traceSize);
		bb.traceSize = traceSize;
		DWORD pos = 0;
		std::list<struct Instruction>::iterator insnIt;
		for (insnIt = insnList.begin(); insnIt != insnList.end(); insnIt++) {
			bb.bbTrace[pos] = insnIt->length;
			pos += 1;
			memcpy(bb.bbTrace + pos, insnIt->bytes, insnIt->length);
			pos += insnIt->length;
		}

		bb.tail = currAddr;
		cache.AddBB(bb);
	}
	//Don't have address:
	//	Walk forward through memory until control flow insn
	//	Set break on end of bb
	//	Store bb by address
	//	Record trace (bb)

	//DWORD bytesWritten;
	//WriteFile(hTraceFile, bb.bbTrace, bb.traceSize, &bytesWritten, NULL);
	traceInsn(runId, bb.head, bb.traceSize, bb.bbTrace);
	HeapFree(hHeap, NULL, bb.bbTrace);
	return bb.tail;
}

// TODO: deduplicate this from fuzzkit
DWORD traceHandleInjection(CREATE_PROCESS_DEBUG_INFO cpdi, DWORD runId) {
	std::map<std::string, std::string> hookMap;
	hookMap["ReadFileHook"] = "ReadFile";
	Injector injector(cpdi.hProcess, cpdi.lpBaseOfImage, "injectable.dll", hookMap);
	injector.Inject(runId);

	// TODO: 
	// while have missing
	// get map<base, missing modules>
	// search for dlls
	// load each
	// add child missing to map
	// fixup
	// ALT: recursion?

	return 0;
}

DWORD Tracer::TraceMainLoop(DWORD runId) {
	DWORD dwContinueStatus = DBG_CONTINUE;
	CREATE_PROCESS_DEBUG_INFO cpdi;
	xed_tables_init();
	for (;;)
	{
		DEBUG_EVENT dbgev;
		WaitForDebugEvent(&dbgev, INFINITE);
		UINT64 tail;
		
		BOOL crashed = false;
		PVOID address = 0;
		DWORD code;

		//printf("DEBUG EVENT: %d\n", dbgev.dwDebugEventCode);

		switch (dbgev.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			crashed = true;
			address = dbgev.u.Exception.ExceptionRecord.ExceptionAddress;
			code = dbgev.u.Exception.ExceptionRecord.ExceptionCode;
			switch (code)
			{
			case EXCEPTION_ACCESS_VIOLATION:
				printf("SEGGY AT %x\n", address);
				break;
			case EXCEPTION_BREAKPOINT:
				crashed = false;
				//printf("BREAK AT %x\n", address);
				if (address == cpdi.lpStartAddress) {
					crashed = false;
					printf("!!! AT START: %x\n", address);
					restoreBreak(cpdi.hProcess, threadMap[dbgev.dwThreadId]);

					traceHandleInjection(cpdi, runId);
					traceInit(runId, cpdi.hProcess, dbgev.dwProcessId);

					tail = trace(cpdi.hProcess, address, runId);
					if (tail == (UINT64)address) {
						singleStep(threadMap[dbgev.dwThreadId]);
					}
					else {
						setBreak(cpdi.hProcess, tail);
					}
				}
				else {
					if (restoreBreak(cpdi.hProcess, threadMap[dbgev.dwThreadId])) {
						crashed = false;
						singleStep(threadMap[dbgev.dwThreadId]);
					}
				}
				break;
			case EXCEPTION_DATATYPE_MISALIGNMENT:
				break;
			case EXCEPTION_SINGLE_STEP:
				crashed = false;
				tail = trace(cpdi.hProcess, address, runId);
				if (tail == (UINT64)address) {
					singleStep(threadMap[dbgev.dwThreadId]);
				}
				else {
					setBreak(cpdi.hProcess, tail);
				}
				break;
			case DBG_CONTROL_C:
				break;
			default:
				break;
			}

			if (crashed) {
				traceCrash(runId, (UINT64)address, code);
				return 0;
			}
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			threadMap[dbgev.dwThreadId] = dbgev.u.CreateThread.hThread;
			//trap_card(threadMap);
			printf("CREATE THREAD\n");
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			printf("CREATE PROC\n");
			cpdi = dbgev.u.CreateProcessInfo;
			setBreak(cpdi.hProcess, (UINT64)cpdi.lpStartAddress);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			printf("EXIT THREAD\n");
			threadMap.erase(dbgev.dwThreadId);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			printf("EXIT PROC\n");
			EXIT_PROCESS_DEBUG_INFO epdi = dbgev.u.ExitProcess;
			return 0;
			break;
		case LOAD_DLL_DEBUG_EVENT:
			break;
		case UNLOAD_DLL_DEBUG_EVENT:
			break;
		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		case RIP_EVENT:
			break;
		}

		ContinueDebugEvent(dbgev.dwProcessId,
			dbgev.dwThreadId,
			dwContinueStatus);
	}
	return 0;
}

DWORD Tracer::addThread(DWORD dwThreadId, HANDLE hThread) {
	threadMap[dwThreadId] = hThread;
	return 0;
}

Tracer::Tracer(LPCTSTR traceName) {
	hHeap = GetProcessHeap();
	hPipeInsn = INVALID_HANDLE_VALUE;
	/*hTraceFile = CreateFile(traceName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTraceFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: CreateFile (%x)\n", GetLastError());
		exit(1);
	}*/
}
