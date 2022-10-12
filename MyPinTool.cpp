#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <list>
#include <sstream>
#include <cstdio>

#include "libdft/libdft_api.h"
#include "libdft/libdft_core.h"
#include "libdft/tagmap.h"
#include "libdft/taint_map.h"
#include "libdft/client.h"
#include "ads.hpp"
namespace WINDOWS {
#include <fileapi.h>
}


//#include "libdft/client.h"

using std::string;
using std::endl;
using std::cerr;
using std::vector;
using std::list;

vector<string> f_source;
vector<string> f_leak;
vector<string> f_sp;

static FILE* sink = fopen("sink.txt", "w");
static FILE* source = fopen("source.txt", "w");
map<UINT32, UINT32> taint_map;
bool leak = true;
map<ADDRINT, char*> handles;

extern int client_send(const char* text);

string to_string(int n)
{
	std::ostringstream stm;
	stm << n;
	return stm.str();
}


void init() {
	string fsource[] = { "ReadFile" };
	string fsp[] = { "CreateFile" ,"CreateFileW" };
	string fleak[] = { "WriteFile" };
	f_source =
		vector<string>(fsource, fsource + sizeof(fsource) / sizeof(fsource[0]));
	f_sp = vector<string>(fsp, fsp + sizeof(fsp) / sizeof(fsp[0]));
	f_leak = vector<string>(fleak, fleak + sizeof(fleak) / sizeof(fleak[0]));
}

VOID* tmpLpBuffer;
VOID* tmpLpNumberOfBytes;
ADDRINT tmpHFile = -1;
VOID getReadAndWrite(std::vector<string>::iterator name, ADDRINT hFile, VOID* lpBuffer, int32_t nNumberOfBytes, VOID* lpNumberOfBytes, VOID* lpOverlapped)
{
	// Print the input argument of each function
	/*
	BOOL WriteFile(
		HANDLE       hFile,
		LPCVOID      lpBuffer,
		DWORD        nNumberOfBytesToWrite,
		LPDWORD      lpNumberOfBytesWritten,
		LPOVERLAPPED lpOverlapped
	);
	*/
	std::cout << std::hex << *name << "( 0x" << hFile << ", 0x" << (ADDRINT)lpBuffer << ", 0x" << nNumberOfBytes << ", 0x" << (ADDRINT)lpNumberOfBytes << ", 0x" << (ADDRINT)lpOverlapped << ")" << endl;
	tmpHFile = hFile;
	tmpLpBuffer = lpBuffer;
	tmpLpNumberOfBytes = lpNumberOfBytes;
}

VOID getReadRet() {
	if (tmpLpNumberOfBytes && tmpLpBuffer && tmpHFile != -1)
	{
		char* name = handles[tmpHFile];
		wchar_t* m_wchar;
		int len = WINDOWS::MultiByteToWideChar(CP_ACP, 0, name, -1, NULL, 0);
		m_wchar = new wchar_t[len + 1];
		WINDOWS::MultiByteToWideChar(CP_ACP, 0, name, -1, m_wchar, len);
		m_wchar[len] = '\0';
		printf("%ls\n", m_wchar);
		tmpHFile = -1;
		std::vector<ADS_ENTRY> entries;
		ADS_get_entries(m_wchar, entries);
		printf("%d\n", entries.size());
		int tag = -1;

		for (size_t i = 0; i < entries.size(); ++i)
		{
			std::string data;
			ADS_get_data(m_wchar, entries[i], data);
			std::string str;
			int nLen = (int)entries[i].name.length();
			str.resize(nLen, ' ');
			WINDOWS::WideCharToMultiByte(CP_ACP, 0, (WINDOWS::LPCWSTR)entries[i].name.c_str(), nLen, (WINDOWS::LPSTR)str.c_str(), nLen, NULL, NULL);
			printf("%s\n", str);
			if (str == ":taint:$DATA" && int(data.c_str()))
			{
				char newName[MAX_PATH + 4] = "\nI:";
				strcat(newName, name);
				strcat(newName, "|");
				client_send(newName);
				leak = false;
				tag = int(data.c_str());
				//tag = 1;
				for (size_t i = 0; i < *(UINT32*)tmpLpNumberOfBytes; i++)
					tagmap_setb_with_tag((UINT32)tmpLpBuffer + i, tag);
				std::cout << "\x1b[34m[TAINT]\tbytes tainted from " << std::hex << "0x"
					<< (UINT32)tmpLpBuffer << " to 0x" << (UINT32)tmpLpBuffer + *(UINT32*)tmpLpNumberOfBytes
					<< " (via ReadFile )\x1b[0m" << std::endl;
				string msg = "";
				for (int t = 0; t < *(UINT32*)tmpLpNumberOfBytes; t++)
				{
					auto tmp = get_taint((UINT32)tmpLpBuffer + t);
					msg += decstr(tmp.first) + "," + decstr(tmp.second) + "," + hexstr(*((char*)tmpLpBuffer + t)) + "\n";
				}
				fwrite(msg.c_str(), 1, msg.length(), source);
				break;
			}
		}

		tmpLpNumberOfBytes = NULL;
		tmpLpBuffer = NULL;
	}
}

VOID getWriteRet()
{
	if (tmpLpNumberOfBytes && tmpLpBuffer && tmpHFile != -1)
	{
		std::cout << "  Write content: " << endl;
		for (UINT32 i = 0; i < *(UINT32*)tmpLpNumberOfBytes; i++)
		{
			std::cout << *((char*)tmpLpBuffer + i);
		}
		std::cout << std::endl;
		bool leak = false;
		for (UINT32 i = 0; i < *(UINT32*)tmpLpNumberOfBytes; i++)
		{
			if (tagmap_getb((UINT32)tmpLpBuffer + i))
			{
				if (handles.find(tmpHFile) != handles.end())
				{
					leak = true;
					std::cout << "\x1b[31mLeaked information from address " << (UINT32)tmpLpBuffer + i
						<< "\x1b[0m" << std::endl;
					auto l = "=========================LEAK " + hexstr((UINT32)tmpLpBuffer + i) + "=========================\n";
					LOG(l);
					leak = true;
					string msg = "";
					auto tmp = get_taint((UINT32)tmpLpBuffer + i);
					msg += decstr(tmp.first) + "," + decstr(tmp.second) + "," + hexstr(*((char*)tmpLpBuffer + i)) + "\n";
					fwrite(msg.c_str(), 1, msg.length(), sink);
				}
			}
		}
		if (leak) {
			char* name = handles[tmpHFile];
			char newName[MAX_PATH + 3] = "O:";
			strcat(newName, name);
			strcat(newName, ";");
			client_send(newName);
			wchar_t* m_wchar;
			int len = WINDOWS::MultiByteToWideChar(CP_ACP, 0, name, -1, NULL, 0);
			m_wchar = new wchar_t[len + 1];
			WINDOWS::MultiByteToWideChar(CP_ACP, 0, name, -1, m_wchar, len);
			m_wchar[len] = '\0';
			ADS_ENTRY entry;
			entry.name = L":taint";
			std::wstring value = L"1";
			tmpHFile = -1;
			char buf[256];
			WINDOWS::WideCharToMultiByte(CP_ACP, 0, (WINDOWS::LPCWCH)value.c_str(), -1, buf, 256, NULL, NULL);
			ADS_put_data(m_wchar, entry, buf);
		}
		tmpLpNumberOfBytes = NULL;
		tmpLpBuffer = NULL;
	}
}

WINDOWS::LPCWSTR tmpLpFileName = NULL;

VOID getFileName(std::vector<string>::iterator name, WINDOWS::LPCWSTR lpFileName)
{
	printf("%s: %ls\n", name->c_str(), lpFileName);
	tmpLpFileName = lpFileName;
}

VOID getRetHandle(ADDRINT handle)
{
	if (tmpLpFileName)
	{
		char* tmpfileName = new char[MAX_PATH + 1];
		int fileNameResult = WINDOWS::GetFinalPathNameByHandleA((WINDOWS::HANDLE)handle, tmpfileName, MAX_PATH, 0);
		char* fileName = new char[MAX_PATH + 1];
		strcpy(fileName, tmpfileName + 4);
		delete tmpfileName;
		//printf("%s\n", fileName);
		handles[handle] = fileName;
	}
	tmpLpFileName = NULL;
}


std::list<string> names;
VOID getName(CHAR* name) { printf("\x1b[31m%s\x1b[0m\n", name); }

bool in(string s, vector<string> array) {
	std::vector<string>::iterator pos = std::find(array.begin(), array.end(), s);
	if (pos == array.end())
		return false;
	else
		return true;
}

//static bool once_leak = 1;
//static bool once_source = 1;

VOID Routine(RTN rtn, VOID* v) {
	// Allocate a counter for this routine
	string name = RTN_Name(rtn);
	//LOG(name);
	//names.push_back(name);
	RTN_Open(rtn);

	if (in(name, f_leak)) {

		std::vector<string>::iterator pos =
			std::find(f_leak.begin(), f_leak.end(), name);
		//std::cout << name << std::endl;

		RTN_InsertCall(
			rtn,
			IPOINT_BEFORE, (AFUNPTR)getReadAndWrite,
			IARG_ADDRINT, pos,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getWriteRet, IARG_END);
	}
	if (in(name, f_source)) {
		std::vector<string>::iterator pos =
			std::find(f_source.begin(), f_source.end(), name);

		RTN_InsertCall(
			rtn,
			IPOINT_BEFORE, (AFUNPTR)getReadAndWrite,
			IARG_ADDRINT, pos,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getReadRet, IARG_END);
	}
	if (in(name, f_sp)) {

		std::vector<string>::iterator pos =
			std::find(f_sp.begin(), f_sp.end(), name);
		//std::cout << name << std::endl;

		RTN_InsertCall(
			rtn,
			IPOINT_BEFORE, (AFUNPTR)getFileName,
			IARG_ADDRINT, pos,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getRetHandle, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
	}
	RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID* v) {
	//OutFile.close();
	//fclose(f);
	fclose(source);
	fclose(sink);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
	cerr << "This Pintool counts the number of times a routine is executed"
		<< endl;
	cerr << "and the number of instructions executed in a routine" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}


void test_ads()
{
	ADS_ENTRY entry;
	entry.name = L":taint";


	std::wstring value = L"1";

	char buf[256];
	WINDOWS::WideCharToMultiByte(CP_ACP, 0, (WINDOWS::LPCWCH)value.c_str(), -1, buf, 256, NULL, NULL);
	ADS_put_data(TEXT(L"./test.txt"), entry, buf);

	/*std::vector<ADS_ENTRY> entries;
	ADS_get_entries(TEXT(L"file.txt"), entries);
	for (size_t i = 0; i < entries.size(); ++i)
	{
		std::string data;
		ADS_get_data(TEXT(L"file.txt"), entries[i], data);
		printf("%ls\n", entries[i].name.c_str());
	}*/

	//ADS_delete_all(TEXT(L"file.txt"));
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[]) {
	// Initialize symbol table code, needed for rtn instrumentation
	init();

	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv))
		return Usage();

	if (libdft_init())
		return Usage();

	//test_ads();

	PIN_SetSyntaxIntel();
	//IMG_AddInstrumentFunction(Image, 0);
	RTN_AddInstrumentFunction(Routine, 0);
	//INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();

	return 0;
}