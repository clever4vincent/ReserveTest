// PEHandler.h: interface for the PEHandler class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PEHANDLER_H__F917A88B_E890_4B42_8219_55678F58A18D__INCLUDED_)
#define AFX_PEHANDLER_H__F917A88B_E890_4B42_8219_55678F58A18D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//函数声明								
//**************************************************************************								
//ReadPEFile:将文件读取到缓冲区								
//参数说明：								
//lpszFile 文件路径								
//pFileBuffer 缓冲区指针								
//返回值说明：								
//读取失败返回0  否则返回实际读取的大小								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);
//**************************************************************************								
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer								
//参数说明：								
//pFileBuffer  FileBuffer指针								
//pImageBuffer ImageBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);
//**************************************************************************								
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区								
//参数说明：								
//pImageBuffer ImageBuffer指针								
//pNewBuffer NewBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);
//**************************************************************************								
//MemeryTOFile:将内存中的数据复制到文件								
//参数说明：								
//pMemBuffer 内存中数据的指针								
//size 要复制的大小								
//lpszFile 要存储的文件路径								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
BOOL MemeryTOFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);
//**************************************************************************								
//RvaToFileOffset:将内存偏移转换为文件偏移								
//参数说明：								
//pFileBuffer FileBuffer指针								
//dwRva RVA的值								
//返回值说明：								
//返回转换后的FOA的值  如果失败返回0								
//**************************************************************************								
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva);
//AddSectionToImageBuffer:将ImageBuffer中的数据复制到新的缓冲区并加入新的节和数据								
//参数说明：								
//pImageBuffer ImageBuffer指针	
//pDataSize 数据大小						
//pNewSectionBuffer NewSectionBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
DWORD AddSectionToImageBuffer(IN LPVOID pImageBuffer, IN DWORD pDataSize, OUT LPVOID* pNewSectionBuffer);
//**************************************************************************	
//ExpandLastSection:将ImageBuffer中的数据复制到新的缓冲区并拉伸最后一个节后写入数据							
//参数说明：								
//pImageBuffer ImageBuffer指针	
//pDataSize 数据大小
//pData 数据指针							
//pExpandSectionBuffer ExpandSectionBuffer								
//返回值说明：								
//读取失败返回0  否则返回复制的大小	
//**************************************************************************	
DWORD ExpandLastSection(IN LPVOID pImageBuffer, IN DWORD pDataSize, IN LPVOID pData, OUT LPVOID* pExpandSectionBuffer);
//**************************************************************************	
//MergeSection:将所有节合并到一个节上							
//参数说明：								
//pImageBuffer ImageBuffer指针								
//pMergeSectionBuffer MergeSectionBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小	
//**************************************************************************	
DWORD MergeSection(IN LPVOID pImageBuffer, OUT LPVOID* pMergeSectionBuffer);
//**************************************************************************								
//Align:将内存偏移转换为文件偏移								
//参数说明：								
//pData 要对齐的数据								
//pAlignSize 对齐大小								
//返回值说明：								
//返回对齐后的值							
//**************************************************************************	
DWORD Align(DWORD pData, DWORD pAlignSize);
//**************************************************************************								
//GetFunctionAddrByOrdinals:通过函数名指针获取函数地址								
//参数说明：								
//pFileBuffer FileBuffer指针									
//Ordinals 函数名导出序号								
//返回值说明：								
//返回函数地址		出错返回0						
//**************************************************************************	
LPVOID GetFunctionAddrByOrdinals(IN LPVOID pFileBuffer, IN DWORD Ordinals);
//**************************************************************************								
//GetFunctionAddrByName:通过函数名指针获取函数地址								
//参数说明：								
//pFileBuffer FileBuffer指针									
//pName 函数名指针								
//返回值说明：								
//返回函数地址		出错返回0						
//**************************************************************************	
LPVOID GetFunctionAddrByName(IN LPVOID pFileBuffer, IN LPVOID pName);
//**************************************************************************								
//MoveNtAndSectionToDosStub:移动PE头和节表至DOS头后面								
//参数说明：								
//pFileBuffer FileBuffer指针																
//返回值说明：								
//返回 TRUE FALSE								
//**************************************************************************	
BOOL MoveNtAndSectionToDosStub(IN LPVOID pFileBuffer);

VOID TestFiletoMemoryToFile();
VOID TestAddCodeInCodeSec();
VOID TestAddSection();
VOID TestExpandLastSection();
VOID TestMergeSection();
VOID TestPrintExportDir();
VOID TestGetFunctionAddrByName();
VOID TestGetFunctionAddrByOrdinals();
VOID TestPrintRelocationDir();
VOID TestMoveExportDir();
VOID TestMoveNtAndSectionToDosStub();
#endif // !defined(AFX_PEHANDLER_H__F917A88B_E890_4B42_8219_55678F58A18D__INCLUDED_)
