// PEHandler.h: interface for the PEHandler class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PEHANDLER_H__F917A88B_E890_4B42_8219_55678F58A18D__INCLUDED_)
#define AFX_PEHANDLER_H__F917A88B_E890_4B42_8219_55678F58A18D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//��������								
//**************************************************************************								
//ReadPEFile:���ļ���ȡ��������								
//����˵����								
//lpszFile �ļ�·��								
//pFileBuffer ������ָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer);
//**************************************************************************								
//CopyFileBufferToImageBuffer:���ļ���FileBuffer���Ƶ�ImageBuffer								
//����˵����								
//pFileBuffer  FileBufferָ��								
//pImageBuffer ImageBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);
//**************************************************************************								
//CopyImageBufferToNewBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ�����								
//����˵����								
//pImageBuffer ImageBufferָ��								
//pNewBuffer NewBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);
//**************************************************************************								
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�								
//����˵����								
//pMemBuffer �ڴ������ݵ�ָ��								
//size Ҫ���ƵĴ�С								
//lpszFile Ҫ�洢���ļ�·��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
BOOL MemeryTOFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile);
//**************************************************************************								
//RvaToFileOffset:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��								
//����˵����								
//pFileBuffer FileBufferָ��								
//dwRva RVA��ֵ								
//����ֵ˵����								
//����ת�����FOA��ֵ  ���ʧ�ܷ���0								
//**************************************************************************								
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva);
//AddSectionToImageBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ������������µĽں�����								
//����˵����								
//pImageBuffer ImageBufferָ��	
//pDataSize ���ݴ�С						
//pNewSectionBuffer NewSectionBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD AddSectionToImageBuffer(IN LPVOID pImageBuffer, IN DWORD pDataSize, OUT LPVOID* pNewSectionBuffer);
//**************************************************************************	
//ExpandLastSection:��ImageBuffer�е����ݸ��Ƶ��µĻ��������������һ���ں�д������							
//����˵����								
//pImageBuffer ImageBufferָ��	
//pDataSize ���ݴ�С
//pData ����ָ��							
//pExpandSectionBuffer ExpandSectionBuffer								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С	
//**************************************************************************	
DWORD ExpandLastSection(IN LPVOID pImageBuffer, IN DWORD pDataSize, IN LPVOID pData, OUT LPVOID* pExpandSectionBuffer);
//**************************************************************************	
//MergeSection:�����нںϲ���һ������							
//����˵����								
//pImageBuffer ImageBufferָ��								
//pMergeSectionBuffer MergeSectionBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С	
//**************************************************************************	
DWORD MergeSection(IN LPVOID pImageBuffer, OUT LPVOID* pMergeSectionBuffer);
//**************************************************************************								
//Align:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��								
//����˵����								
//pData Ҫ���������								
//pAlignSize �����С								
//����ֵ˵����								
//���ض�����ֵ							
//**************************************************************************	
DWORD Align(DWORD pData, DWORD pAlignSize);
//**************************************************************************								
//GetFunctionAddrByOrdinals:ͨ��������ָ���ȡ������ַ								
//����˵����								
//pFileBuffer FileBufferָ��									
//Ordinals �������������								
//����ֵ˵����								
//���غ�����ַ		������0						
//**************************************************************************	
LPVOID GetFunctionAddrByOrdinals(IN LPVOID pFileBuffer, IN DWORD Ordinals);
//**************************************************************************								
//GetFunctionAddrByName:ͨ��������ָ���ȡ������ַ								
//����˵����								
//pFileBuffer FileBufferָ��									
//pName ������ָ��								
//����ֵ˵����								
//���غ�����ַ		������0						
//**************************************************************************	
LPVOID GetFunctionAddrByName(IN LPVOID pFileBuffer, IN LPVOID pName);
//**************************************************************************								
//MoveNtAndSectionToDosStub:�ƶ�PEͷ�ͽڱ���DOSͷ����								
//����˵����								
//pFileBuffer FileBufferָ��																
//����ֵ˵����								
//���� TRUE FALSE								
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
