// Test1.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <stdio.h>
#include "PEHandler.h"
#include "../Test/Lib/TTDLL.h"
#pragma comment(lib,"../Test/Lib/TestDLL.lib")	


void __declspec(naked) pl12us(int x, int y, int z)
{
	__asm
	{

	}
}


int main(int argc, char* argv[])
{

	//TestFiletoMemoryToFile();
	//TestAddCodeInCodeSec();
	//sAlign(100,200);
	//printf("%d\n",Align(610,600));
	//printf("%d\n",Plus(5,2));
	//TestPrintExportDir();
	//TestMergeSection();
	//TestGetFunctionAddrByName();
	//TestGetFunctionAddrByOrdinals();
	//TestPrintRelocationDir();
	//TestMoveNtAndSectionToDosStub();
	//TestAddSection();
	//TestMoveExportDir();
	return 0;
}


