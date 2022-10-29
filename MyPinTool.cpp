#include "pin.H"
#include <iostream>
#include <vector>
#include <list>
#include <sstream>
#include <cstdio>

#include "libdft/libdft_api.h"
#include "libdft/libdft_core.h"
#include "libdft/tagmap.h"

using std::string;
using std::endl;
using std::cerr;
using std::vector;
using std::list;


void init() {
}


VOID Routine(RTN rtn, VOID *v) {
    string name = RTN_Name(rtn);
    RTN_Open(rtn);

//		RTN_InsertCall(
//			rtn,
//			IPOINT_BEFORE, (AFUNPTR)getReadAndWrite,
//			IARG_ADDRINT, pos,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
//			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
//			IARG_END);
//		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getWriteRet, IARG_END);

    RTN_Close(rtn);
}

// This function is called when the application exits
// It prints the name and count for each procedure
VOID Fini(INT32 code, VOID *v) {

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
/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
    // Initialize symbol table code, needed for rtn instrumentation
    init();

    PIN_InitSymbols();

    // Initialize pin
    if (PIN_Init(argc, argv))
        return Usage();

    if (libdft_init())
        return Usage();

    PIN_SetSyntaxIntel();
    //IMG_AddInstrumentFunction(Image, 0);
    RTN_AddInstrumentFunction(Routine, 0);
    //INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();

    return 0;
}