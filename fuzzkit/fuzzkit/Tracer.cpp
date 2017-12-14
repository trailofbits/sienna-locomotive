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
	if (SuspendThread(hThread) == -1) {
		LOG_F(ERROR, "SingleStep (%x)", GetLastError());
		exit(1);
	}

	if(!GetThreadContext(hThread, &context)) {
		LOG_F(ERROR, "SingleStep (%x)", GetLastError());
		exit(1);
	}

	context.EFlags = context.EFlags | (1 << 8);

	if (!SetThreadContext(hThread, &context)) {
		LOG_F(ERROR, "SingleStep (%x)", GetLastError());
		exit(1);
	}

	if (ResumeThread(hThread) == -1) {
		LOG_F(ERROR, "SingleStep (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD Tracer::setBreak(HANDLE hProcess, UINT64 address) {
	BYTE breakByte = 0xCC;
	BYTE startByte;
	
	if(!ReadProcessMemory(hProcess, (LPVOID)address, &startByte, sizeof(BYTE), NULL)) {
		LOG_F(ERROR, "SetBreak (%x)", GetLastError());
		exit(1);
	}

	if(!WriteProcessMemory(hProcess, (LPVOID)address, &breakByte, sizeof(BYTE), NULL)) {
		LOG_F(ERROR, "SetBreak (%x)", GetLastError());
		exit(1);
	}

	if (restoreBytes.find((LPVOID)address) == restoreBytes.end()) {
		restoreBytes[(LPVOID)address] = startByte;
	}
	return 0;
}

BOOL Tracer::restoreBreak(HANDLE hProcess, HANDLE hThread) {
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(hThread, &context)) {
		LOG_F(ERROR, "RestoreBreak (%x)", GetLastError());
		exit(1);
	}
	
	context.Rip -= 1;

	if (restoreBytes.find((LPVOID)context.Rip) == restoreBytes.end()) {
		LOG_F(WARNING, "restoreBytes miss at %llx", context.Rip);
		return false;
	}
		
	if(!SetThreadContext(hThread, &context)) {
		LOG_F(ERROR, "RestoreBreak (%x)", GetLastError());
		exit(1);
	}

	if(!WriteProcessMemory(hProcess, (LPVOID)context.Rip, &restoreBytes[(LPVOID)context.Rip], sizeof(BYTE), NULL)) {
		LOG_F(ERROR, "RestoreBreak (%x)", GetLastError());
		exit(1);
	}
	
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
		LOG_F(ERROR, "Could not connect to server");
		exit(1);
	}

	DWORD readMode = PIPE_READMODE_MESSAGE;
	if (!SetNamedPipeHandleState(hPipe, &readMode, NULL, NULL)) {
		LOG_F(ERROR, "Could not connect to server");
		exit(1);
	}

	return hPipe;
}

DWORD Tracer::traceInit(DWORD runId, HANDLE hProc, DWORD procId) {
	DWORD bytesRead;
	DWORD bytesWritten;
	HANDLE hPipe = tracerGetPipe();
	
	BYTE eventId = 5;
	if(!WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	DWORD size = 0;
	if(!ReadFile(hPipe, &size, sizeof(DWORD), &bytesRead, NULL)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}
	
	// get minidump path
	HANDLE hHeap = GetProcessHeap();
	WCHAR *minidumpPath = (WCHAR *)HeapAlloc(hHeap, NULL, size);
	if(!ReadFile(hPipe, minidumpPath, size, &bytesRead, NULL)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	// open file
	HANDLE minidumpFile = CreateFile(minidumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

	if (minidumpFile == INVALID_HANDLE_VALUE) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	// write minidump
	DWORD type = MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo;
	if(!MiniDumpWriteDump(hProc, procId, minidumpFile, (MINIDUMP_TYPE)type, NULL, NULL, NULL)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	if(!HeapFree(hHeap, NULL, minidumpPath)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hPipe)) {
		LOG_F(ERROR, "TraceInit (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

HANDLE Tracer::tracerGetPipeInsn(DWORD runId) {
	if (hPipeInsn == INVALID_HANDLE_VALUE) {
		LOG_F(INFO, "Creating new pipe for insn tracing");
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
			LOG_F(ERROR, "Could not connect to server (instruction) (%x)", err);
			exit(1);
		}

		DWORD readMode = PIPE_READMODE_MESSAGE;
		if(!SetNamedPipeHandleState(hPipeInsn, &readMode, NULL, NULL)) {
			LOG_F(ERROR, "TracerGetPipeInsn (%x)", GetLastError());
			exit(1);
		}

		BYTE eventId = 6;
		DWORD bytesWritten;
		if(!WriteFile(hPipeInsn, &eventId, sizeof(BYTE), &bytesWritten, NULL)) {
			LOG_F(ERROR, "TracerGetPipeInsn (%x)", GetLastError());
			exit(1);
		}

		if(!WriteFile(hPipeInsn, &runId, sizeof(DWORD), &bytesWritten, NULL)) {
			LOG_F(ERROR, "TracerGetPipeInsn (%x)", GetLastError());
			exit(1);
		}
	}

	return hPipeInsn;
}

DWORD Tracer::traceInsn(DWORD runId, UINT64 addr, DWORD traceSize, BYTE *trace) {
	DWORD bytesRead;
	DWORD bytesWritten;
	HANDLE hPipe = tracerGetPipeInsn(runId);

	// send head address to server
	if(!WriteFile(hPipe, &addr, sizeof(UINT64), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	// send trace size to server
	if(!WriteFile(hPipe, &traceSize, sizeof(DWORD), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	//printf("%x, %x, %x\t", runId, addr, traceSize);
	//for (int i = 0; i < traceSize; i++) {
	//	printf("%x ", trace[i]);
	//}
	//printf("\n");

	// send trace to server
	BYTE nullByte = 0;
	if(!TransactNamedPipe(hPipe, trace, traceSize, &nullByte, sizeof(BYTE), &bytesRead, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

DWORD Tracer::traceCrash(DWORD runId, UINT64 exceptionAddr, DWORD exceptionCode) {
	DWORD bytesRead;
	DWORD bytesWritten;

	HANDLE hInsnPipe = tracerGetPipeInsn(runId);
	UINT64 zero = 0;
	if(!WriteFile(hInsnPipe, &zero, sizeof(UINT64), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hInsnPipe, &zero, sizeof(UINT64), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	HANDLE hPipe = tracerGetPipe();

	BYTE eventId = 8;
	if(!WriteFile(hPipe, &eventId, sizeof(BYTE), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	if(!WriteFile(hPipe, &runId, sizeof(DWORD), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	// send crash addr to server
	if(!WriteFile(hPipe, &exceptionAddr, sizeof(UINT64), &bytesWritten, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	// send crash type to server
	BYTE nullByte = 0;
	if(!TransactNamedPipe(hPipe, &exceptionCode, sizeof(DWORD), &nullByte, sizeof(BYTE), &bytesRead, NULL)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	if(!CloseHandle(hPipe)) {
		LOG_F(ERROR, "TraceInsn (%x)", GetLastError());
		exit(1);
	}

	return 0;
}

UINT64 Tracer::trace(HANDLE hProcess, PVOID address, DWORD runId) {
	struct BasicBlock bb;
	std::list<struct Instruction> insnList;
	if (cache.HasBB((UINT64)address)) {
		bb = cache.FetchBB((UINT64)address);
	}
	else {
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

			if (xed_err != XED_ERROR_NONE) {
				LOG_F(ERROR, "Trace xed_err (%x)", xed_err);
				exit(1);
			}

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

	traceInsn(runId, bb.head, bb.traceSize, bb.bbTrace);
	return bb.tail;
}

// TODO: deduplicate this from fuzzkit
UINT64 traceHandleInjection(CREATE_PROCESS_DEBUG_INFO cpdi, DWORD runId) {
	std::map<std::string, std::string> hookMap;
	hookMap["ReadFileHook"] = "ReadFile";
	Injector *origInjector = new Injector(cpdi.hProcess, cpdi.lpBaseOfImage, "C:\\Users\\dgoddard\\Documents\\GitHub\\sienna-locomotive\\fuzzkit\\x64\\Release\\injectable.dll", hookMap);
	Injector *injector = origInjector;
	injector->Inject(runId);

	std::set<std::string> missingModules = injector->MissingModules();
	/*if (injector->MissingModules().size() == 0) {
	return 0;
	}
	*/
	std::map<std::string, LPVOID> loadedModules;
	std::set<Injector *> injectors;
	injectors.insert(injector);

	std::set<std::string> missingMaster;

	missingMaster.insert(missingModules.begin(), missingModules.end());
	std::map<std::string, std::string> emptyMap;
	while (missingMaster.size() > 0) {
		// TODO: add more intelligent search, maybe a dependencies folder
		// open C:\Windows\System32\file.dll
		std::string missing = *(missingMaster.begin());
		std::string path = "C:\\Windows\\System32\\" + missing;

		// inject
		//printf("INJECTING EXTRA: %s\n", missing.c_str());
		injector = new Injector(cpdi.hProcess, cpdi.lpBaseOfImage, path, emptyMap);
		injector->Inject();

		// add injector to list
		injectors.insert(injector);

		// have missing?
		missingModules = injector->MissingModules();
		if (missingModules.size() > 0) {
			// add missing to missing master
			missingMaster.insert(missingModules.begin(), missingModules.end());
		}

		loadedModules[missing] = injector->BaseOfInjected();
		std::set<Injector *>::iterator injectorIt;
		// for injector in injectors
		for (injectorIt = injectors.begin(); injectorIt != injectors.end(); injectorIt++) {
			// missing newly injected?
			missingModules = (*injectorIt)->MissingModules();
			if (missingModules.size() == 0) {
				continue;
			}
			(*injectorIt)->ResolveImports(loadedModules);
		}

		missingMaster.erase(missing);
	}

	return origInjector->hookAddrMap["ReadFileHook"];
}

DWORD Tracer::TraceMainLoop(DWORD runId) {
	DWORD dwContinueStatus = DBG_CONTINUE;
	CREATE_PROCESS_DEBUG_INFO cpdi;
	xed_tables_init();
	UINT64 taintAddr = 0;

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
				case EXCEPTION_BREAKPOINT:
					crashed = false;
					// printf("[B] BREAK AT %x\n", address);
					if (address == cpdi.lpStartAddress) {
						crashed = false;
						LOG_F(INFO, "At start address %llx", address);
						LOG_F(INFO, "In thread %x", dbgev.dwThreadId);
						restoreBreak(cpdi.hProcess, threadMap[dbgev.dwThreadId]);

						taintAddr = traceHandleInjection(cpdi, runId);
						LOG_F(INFO, "Setting taint break on %llx", taintAddr);
						setBreak(cpdi.hProcess, taintAddr);
					}
					else if ((UINT64)address == taintAddr) {
						LOG_F(INFO, "Taint break point %llx", address);
						crashed = false;
						restoreBreak(cpdi.hProcess, threadMap[dbgev.dwThreadId]);
						LOG_F(INFO, "Beginning trace");

						traceInit(runId, cpdi.hProcess, dbgev.dwProcessId);

						tail = trace(cpdi.hProcess, address, runId);
						if (tail == (UINT64)address) {
							// printf("[.] SINGLE STEPPING\n");
							singleStep(threadMap[dbgev.dwThreadId]);
						}
						else {
							// printf("[.] BREAK SET %x\n", tail);
							setBreak(cpdi.hProcess, tail);
						}
					}
					else {
						if (restoreBreak(cpdi.hProcess, threadMap[dbgev.dwThreadId])) {
							// printf("[B] TAIL HIT %x\n", address);
							// printf("[B] SINGLE STEPPING\n");
							crashed = false;
							singleStep(threadMap[dbgev.dwThreadId]);
						}
					}
					break;
				case EXCEPTION_SINGLE_STEP:
					crashed = false;
					tail = trace(cpdi.hProcess, address, runId);
					if (tail == (UINT64)address) {
						// printf("[S] HEAD / TAIL HIT %x\n", address);
						// printf("[S] SINGLE STEPPING\n");
						singleStep(threadMap[dbgev.dwThreadId]);
					}
					else {
						// printf("[S] HEAD HIT %x\n", address);
						// printf("[S] BREAK SET %x\n", tail);
						setBreak(cpdi.hProcess, tail);
					}
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
			LOG_F(INFO, "Thread started with id %x", dbgev.dwThreadId);
			threadMap[dbgev.dwThreadId] = dbgev.u.CreateThread.hThread;
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			LOG_F(INFO, "Process started with id %x", dbgev.dwProcessId);
			cpdi = dbgev.u.CreateProcessInfo;
			setBreak(cpdi.hProcess, (UINT64)cpdi.lpStartAddress);
			break;
		case EXIT_THREAD_DEBUG_EVENT:
			LOG_F(INFO, "Thread exited with id %x", dbgev.dwThreadId);
			threadMap.erase(dbgev.dwThreadId);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			LOG_F(INFO, "Process exited with id %x", dbgev.dwProcessId);
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

Tracer::Tracer() {
	hHeap = GetProcessHeap();
	hPipeInsn = INVALID_HANDLE_VALUE;
}
