// PEHandler.cpp: implementation of the PEHandler class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "PEHandler.h"
#include <stdio.h>
#include <stdlib.h>

#define FILEPATH_IN "C:/test/TestDLL.dll"
#define FILEPATH_OUT "C:/test/TestDLL_new.dll"
#define SHELLCODELENGTH 0x12
#define MESSAGEBOXADDR 0x76B4EE90

BYTE shellCode[] =
{
	0x6A,00,0x6A,00,0x6A,00,0x6A,00,
	0xE8,00,00,00,00,
	0xE9,00,00,00,00
};
//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////
//��������								
//**************************************************************************								
//ReadPEFile:���ļ���ȡ��������								
//����˵����								
//lpszFile �ļ�·��								
//pFileBuffer ������ָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻�ʵ�ʶ�ȡ�Ĵ�С								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{
	FILE* fp;
	LPVOID ptr;
	DWORD fileSize;
	//�ж��ļ��Ƿ��ʧ��
	if ((fp = fopen(lpszFile, "rb")) == NULL) {
		printf("Fail to open file!");
		return 0;
	}
	// ��ȡ�ļ�ĩ��ַ
	fseek(fp, 0L, SEEK_END);
	// �����ļ���С
	fileSize = ftell(fp);
	// �ص��ļ��׵�ַ
	rewind(fp);
	// ��̬�����ڴ�
	ptr = malloc(fileSize);
	if (ptr == NULL)
	{
		printf("Fail to malloc!");
		fclose(fp);
		return 0;
	}
	//memset(ptr,0,fileSize);
	// ��λ���ļ���ͷ
	size_t n = fread(ptr, fileSize, 1, fp);
	if (!n)
	{
		printf(" ��ȡ����ʧ��! ");
		free(ptr);
		fclose(fp);
		return 0;
	}
	*pFileBuffer = ptr;
	pFileBuffer = NULL;
	fclose(fp);
	return fileSize;
}
//**************************************************************************								
//CopyFileBufferToImageBuffer:���ļ���FileBuffer���Ƶ�ImageBuffer								
//����˵����								
//pFileBuffer  FileBufferָ��								
//pImageBuffer ImageBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID mImageBuffer = NULL;


	if (pFileBuffer == NULL)
	{
		printf("������ָ����Ч\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return 0;
	}

	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return 0;
	}

	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// ��Ŀ¼
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	mImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (mImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}

	// ��ʼ��������
	memset(mImageBuffer, 0, pOptionHeader->SizeOfImage);
	// COPYͷ
	memcpy(mImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
	int sectionSize = 0;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
		if (pSectionHeader[i].SizeOfRawData == 0) {
			sectionSize = pOptionHeader->SectionAlignment; // ��С�ڴ�Seciton��λΪ SectionAlignment�Ĵ�С
		}
		else
		{
			sectionSize = pSectionHeader[i].SizeOfRawData;
		}
		if (sectionSize > 0) {
			LPVOID dest = (LPVOID)((DWORD)mImageBuffer + pSectionHeader[i].VirtualAddress);
			LPVOID src = (LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].PointerToRawData);
			memcpy(dest, src, sectionSize);
		}
	}
	*pImageBuffer = mImageBuffer;
	pImageBuffer = NULL;
	return pOptionHeader->SizeOfImage;
}
//**************************************************************************								
//CopyImageBufferToNewBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ�����								
//����˵����								
//pImageBuffer ImageBufferָ��								
//pNewBuffer NewBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
DWORD CopyImageBufferToNewBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pNewBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID mImageBuffer = NULL;
	DWORD pBufferSize;
	if (!pFileBuffer)
	{
		printf("�ļ���ȡʧ��\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return 0;
	}
	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return 0;
	}

	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	int lastNum = pPEHeader->NumberOfSections - 1;
	// ����EXEӲ�̸�ʽ��С= �ڱ����һ�������ļ���ƫ��+�ļ��ж����ĳߴ�
	pBufferSize = pSectionHeader[lastNum].PointerToRawData + pSectionHeader[lastNum].SizeOfRawData;
	mImageBuffer = malloc(pBufferSize);
	if (mImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}
	// ��ʼ��������
	memset(mImageBuffer, 0, pBufferSize);
	// copy PE header 
	memcpy(mImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);

	CHAR szSecName[9] = { 0 };
	int sectionSize = 0;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
		memset(szSecName, 0, 9);
		memcpy(szSecName, pSectionHeader[i].Name, IMAGE_SIZEOF_SHORT_NAME);
		printf("********************��%d�ڱ�ͷ********************\n", i + 1);
		printf("section name: %s\n", szSecName);
		if (pSectionHeader[i].SizeOfRawData == 0) {
			sectionSize = pOptionHeader->FileAlignment; // ��С�ڴ�Seciton��λΪ SectionAlignment�Ĵ�С
		}
		else
		{
			sectionSize = pSectionHeader[i].SizeOfRawData;
		}
		if (sectionSize > 0) {
			//IN pFileBuffer
			LPVOID dest = (LPVOID)((DWORD)mImageBuffer + pSectionHeader[i].PointerToRawData);
			LPVOID src = (LPVOID)((DWORD)pFileBuffer + pSectionHeader[i].VirtualAddress);
			memcpy(dest, src, sectionSize);
		}
	}
	*pNewBuffer = mImageBuffer;
	pNewBuffer = NULL;
	return pBufferSize;
}
//**************************************************************************	
//AddSectionToImageBuffer:��ImageBuffer�е����ݸ��Ƶ��µĻ������������µĽں�����								
//����˵����								
//pImageBuffer ImageBufferָ��	
//pDataSize ���ݴ�С							
//pNewSectionBuffer NewSectionBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С	
//**************************************************************************	
DWORD AddSectionToImageBuffer(IN LPVOID pImageBuffer, IN DWORD pDataSize, OUT LPVOID* pNewSectionBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pTmepImageBuffer = NULL;
	DWORD size = 0;

	if (pImageBuffer == NULL)
	{
		printf("������ָ����Ч\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return 0;
	}

	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return 0;
	}

	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// ��Ŀ¼
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//�ж�ͷ���Ƿ��пռ�������
	if ((PUCHAR)pImageBuffer + pOptionHeader->SizeOfHeaders - (PUCHAR)(&pSectionHeader[pPEHeader->NumberOfSections + 1]) < IMAGE_SIZEOF_SECTION_HEADER)
	{
		//Ĩ��DOS_STUB���ݲ���NT,SECTION���������ƶ�
		BOOL bRet = MoveNtAndSectionToDosStub(pImageBuffer);
		if (!bRet)
		{
			printf("AddNewSection MoveNtAndSectionToDosStub Fail \r\n");
			free(pImageBuffer);
			return 0;
		}

		pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
		pNTHeader = (PIMAGE_NT_HEADERS)((PUCHAR)pImageBuffer + pDosHeader->e_lfanew);
		pPEHeader = (PIMAGE_FILE_HEADER)((PUCHAR)pNTHeader + 4);
		pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((PUCHAR)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
		pSectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	}


	// ���������ڴ�Ĵ�С 
	DWORD addSectionMisc = Align(pDataSize, pOptionHeader->SectionAlignment);
	size = (pOptionHeader->SizeOfImage) + addSectionMisc;

	pTmepImageBuffer = malloc(size);
	if (pTmepImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}
	// ��ʼ��������
	memset(pTmepImageBuffer, 0, size);

	// �޸�����һ ��װ�����ڵ���Ϣ���������Ľ���ӵ��ڱ���
	DWORD sectionSize = pPEHeader->NumberOfSections;
	IMAGE_SECTION_HEADER lastSectionHeader = pSectionHeader[sectionSize - 1];
	// ��װ�����ڵ���Ϣ
	DWORD addSectionVirtualAddress = 0;
	if (lastSectionHeader.SizeOfRawData > lastSectionHeader.Misc.VirtualSize)
	{
		addSectionVirtualAddress = (lastSectionHeader.VirtualAddress) + Align(lastSectionHeader.SizeOfRawData, pOptionHeader->SectionAlignment);
	}
	else
	{
		addSectionVirtualAddress = (lastSectionHeader.VirtualAddress) + Align(lastSectionHeader.Misc.VirtualSize, pOptionHeader->SectionAlignment);
	}
	DWORD addSectionPointerToRawData = lastSectionHeader.PointerToRawData + lastSectionHeader.SizeOfRawData;
	IMAGE_SECTION_HEADER addSectionHeader = {
		 ".tttt",
		addSectionMisc,
		addSectionVirtualAddress,
		addSectionMisc,
		addSectionPointerToRawData,
		0,
		0,
		0,
		0,
		pSectionHeader->Characteristics
	};
	IMAGE_SECTION_HEADER zeroSectionHeader = { 0,0,0,0,0,0,0,0,0,0 };
	// �������Ľ���ӵ��ڱ���
	pSectionHeader[sectionSize] = addSectionHeader;
	// �������ڵ�֮��һ���ڱ��0
	pSectionHeader[sectionSize + 1] = zeroSectionHeader;
	// �޸����̶� �޸�PEͷ�нڵ���Ŀ
	pPEHeader->NumberOfSections = (pPEHeader->NumberOfSections) + 1;
	// �޸������� �޸�PEͷ��SizeOfImage
	DWORD OriSizeOfImage = pOptionHeader->SizeOfImage;
	pOptionHeader->SizeOfImage = OriSizeOfImage + addSectionMisc;
	// ��֮ǰ������ȫ��COPY
	memcpy(pTmepImageBuffer, pImageBuffer, OriSizeOfImage);
	*pNewSectionBuffer = pTmepImageBuffer;
	pNewSectionBuffer = NULL;
	return size;
}
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
DWORD ExpandLastSection(IN LPVOID pImageBuffer, IN DWORD pDataSize, IN LPVOID pData, OUT LPVOID* pExpandSectionBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pTmepImageBuffer = NULL;
	DWORD size = 0;

	if (pImageBuffer == NULL)
	{
		printf("������ָ����Ч\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return 0;
	}

	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return 0;
	}

	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// ��Ŀ¼
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// ���������ڴ�Ĵ�С 
	DWORD addSectionMisc = Align(pDataSize, pOptionHeader->SectionAlignment);
	size = (pOptionHeader->SizeOfImage) + addSectionMisc;

	pTmepImageBuffer = malloc(size);
	if (pTmepImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}
	// ��ʼ��������
	memset(pTmepImageBuffer, 0, size);
	// �޸�����һ �޸Ľڱ������һ���ڵ�����
	DWORD sectionSize = pPEHeader->NumberOfSections;
	IMAGE_SECTION_HEADER lastSectionHeader = pSectionHeader[sectionSize - 1];
	// ����ڵ��ļ���С
	DWORD oriLastSectionSize = 0;
	if (lastSectionHeader.SizeOfRawData > lastSectionHeader.Misc.VirtualSize)
	{
		oriLastSectionSize = Align(lastSectionHeader.SizeOfRawData, pOptionHeader->SectionAlignment);
	}
	else
	{
		oriLastSectionSize = Align(lastSectionHeader.Misc.VirtualSize, pOptionHeader->SectionAlignment);
	}
	DWORD destLastSectionSize = oriLastSectionSize + addSectionMisc;
	// �޸����ڵ�����
	lastSectionHeader.Misc.VirtualSize = destLastSectionSize;
	lastSectionHeader.SizeOfRawData = destLastSectionSize;
	lastSectionHeader.Characteristics = pSectionHeader->Characteristics;
	// �����ڽ��и�ֵ
	pSectionHeader[sectionSize - 1] = lastSectionHeader;
	// �޸������� �޸�PEͷ��SizeOfImage
	DWORD OriSizeOfImage = pOptionHeader->SizeOfImage;
	pOptionHeader->SizeOfImage = OriSizeOfImage + addSectionMisc;
	// ��֮ǰ������ȫ��COPY
	memcpy(pTmepImageBuffer, pImageBuffer, OriSizeOfImage);
	// �޸������� �����ݼ��뵽���һ�ڵ��·�
	// ��ָ�붨λ��ԭ�Ȼ����������
	LPVOID pDataStart = LPVOID((DWORD)pTmepImageBuffer + OriSizeOfImage);
	// �����ݼ��뵽���һ��
	memcpy(pDataStart, pData, pDataSize);
	*pExpandSectionBuffer = pTmepImageBuffer;
	pExpandSectionBuffer = NULL;
	return size;
}
//**************************************************************************	
//MergeSection:�����нںϲ���һ������							
//����˵����								
//pImageBuffer ImageBufferָ��								
//pMergeSectionBuffer MergeSectionBufferָ��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С	
//**************************************************************************	
DWORD MergeSection(IN LPVOID pImageBuffer, OUT LPVOID* pMergeSectionBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID pTmepImageBuffer = NULL;
	DWORD size = 0;

	if (pImageBuffer == NULL)
	{
		printf("������ָ����Ч\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return 0;
	}

	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return 0;
	}
	// �ϲ��ڱ�Ĺ��̣� 1 �޸ĵ�һ���ڵ���Ϣ 2 �޸�NumberOfSections
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// ��Ŀ¼
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// ���������ڴ�Ĵ�С 
	size = (pOptionHeader->SizeOfImage);

	pTmepImageBuffer = malloc(size);
	if (pTmepImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}
	// ��ʼ��������
	memset(pTmepImageBuffer, 0, size);

	// �޸�����һ �޸ĵ�һ���ڵ���Ϣ
	IMAGE_SECTION_HEADER firstSectionHeader = pSectionHeader[0];
	// ����ڵ��ļ���С
	DWORD firstSectionSize = size - firstSectionHeader.VirtualAddress;
	// ����Characteristics��ֵ
	DWORD characteristics = 0;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		characteristics |= pSectionHeader[i].Characteristics;
	}
	firstSectionHeader.Misc.VirtualSize = firstSectionSize;
	firstSectionHeader.SizeOfRawData = firstSectionSize;
	firstSectionHeader.Characteristics = characteristics;
	// �Ե�һ���ڽ��и�ֵ
	pSectionHeader[0] = firstSectionHeader;

	// �޸����̶� �޸�NumberOfSections
	pPEHeader->NumberOfSections = 1;

	// ��֮ǰ������ȫ��COPY
	memcpy(pTmepImageBuffer, pImageBuffer, size);
	*pMergeSectionBuffer = pTmepImageBuffer;
	pMergeSectionBuffer = NULL;
	return size;
}
//**************************************************************************								
//MemeryTOFile:���ڴ��е����ݸ��Ƶ��ļ�								
//����˵����								
//pMemBuffer �ڴ������ݵ�ָ��								
//size Ҫ���ƵĴ�С								
//lpszFile Ҫ�洢���ļ�·��								
//����ֵ˵����								
//��ȡʧ�ܷ���0  ���򷵻ظ��ƵĴ�С								
//**************************************************************************								
BOOL MemeryTOFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile)
{
	FILE* fp;
	//�ж��ļ��Ƿ��ʧ��
	if ((fp = fopen(lpszFile, "wb")) == NULL) {
		printf("Fail to open file!");
		return 0;
	}
	size_t count = fwrite(pMemBuffer, size, 1, fp);
	fclose(fp);
	return count;
}
//**************************************************************************								
//RvaToFileOffset:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��								
//����˵����								
//pFileBuffer FileBufferָ��								
//dwRva RVA��ֵ								
//����ֵ˵����								
//����ת�����FOA��ֵ  ���ʧ�ܷ���0								
//**************************************************************************								
DWORD RvaToFileOffset(IN LPVOID pFileBuffer, IN DWORD dwRva)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID mImageBuffer = NULL;


	if (pFileBuffer == NULL)
	{
		printf("������ָ����Ч\n");
		return 0;
	}

	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return 0;
	}

	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return 0;
	}

	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// ��Ŀ¼
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// ��ôת�� ���жϵ�ַ���ĸ�����
	//��ǰ��ַ �����SizeOfHeaders֮�ڵľͷ��ص�ǰ��ַ-imageBase
	// ��ǰ��ַ ����ȵ�һ�ڴ�
	//dwRva pOptionHeader->SizeOfHeaders
	//DWORD offsetAddress = dwRva  - (DWORD)(pOptionHeader->ImageBase);
	DWORD offsetAddress = dwRva;
	if (offsetAddress <= pOptionHeader->SizeOfHeaders)
	{
		return offsetAddress;
	}
	for (int i = (pPEHeader->NumberOfSections - 1); i >= 0; i--)
	{
		if (offsetAddress >= pSectionHeader[i].VirtualAddress)
		{
			return (DWORD)(pSectionHeader[i].PointerToRawData) + offsetAddress - (DWORD)(pSectionHeader[i].VirtualAddress);
		}
	}
	printf("������������ݣ��ļ���ԭ��û��!\n");
	return 0;
}
//**************************************************************************								
//Align:���ڴ�ƫ��ת��Ϊ�ļ�ƫ��								
//����˵����								
//pData Ҫ���������								
//pAlignSize �����С								
//����ֵ˵����								
//���ض�����ֵ	������0						
//**************************************************************************							
DWORD Align(DWORD pData, DWORD pAlignSize)
{
	DWORD x = pData / pAlignSize;
	DWORD y = pData % pAlignSize;
	return (x * pAlignSize) + (y > 0 ? pAlignSize : 0);
}
//**************************************************************************								
//GetFunctionAddrByName:ͨ��������ָ���ȡ������ַ								
//����˵����								
//pFileBuffer FileBufferָ��									
//pName ������ָ��								
//����ֵ˵����								
//���غ�����ַ		������0						
//**************************************************************************	
LPVOID GetFunctionAddrByName(IN LPVOID pFileBuffer, IN LPVOID pName)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	LPVOID mImageBuffer = NULL;

	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return 0;
	}
	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return 0;
	}
	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return 0;
	}
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;
	//�жϸ�PE�ļ��Ƿ��е�����
	if (!exportVirtualAddress)
	{
		printf("��PE�ļ������ڵ����� \r\n");
		return 0;
	}
	DWORD exportRawAddress = RvaToFileOffset(pFileBuffer, exportVirtualAddress);
	// ���������ļ��еĵ�ַ
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportRawAddress);
	// ��ַ��
	DWORD rawAdrFuns = RvaToFileOffset(pFileBuffer, pExportDir->AddressOfFunctions);
	DWORD* rawAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + rawAdrFuns);
	// ���Ʊ�+��ű�
	DWORD rawAdrNamesTemp = RvaToFileOffset(pFileBuffer, pExportDir->AddressOfNames);
	DWORD* rawAddressOfNames = (DWORD*)((DWORD)pFileBuffer + rawAdrNamesTemp);
	DWORD rawAdrNameOrdinalsTemp = RvaToFileOffset(pFileBuffer, pExportDir->AddressOfNameOrdinals);
	WORD* rawAddressOfNameOrdinals = (WORD*)((DWORD)pFileBuffer + rawAdrNameOrdinalsTemp);
	for (size_t i = 0; i < pExportDir->NumberOfNames; i++)
	{
		LPVOID rawAddressOfName = (LPVOID)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, rawAddressOfNames[i]));
		printf("rawAddressOfName  -> [%s] \r\n", rawAddressOfName);
		if (strcmp((PCSTR)pName, (PCSTR)rawAddressOfName) == 0)
		{
			WORD index = rawAddressOfNameOrdinals[i];
			printf("index  -> [0x%08x] \r\n", index);
			return (LPVOID)rawAddressOfFunctions[index];
		}
	}
	return 0;
}
//**************************************************************************								
//GetFunctionAddrByName:ͨ��������ָ���ȡ������ַ								
//����˵����								
//pFileBuffer FileBufferָ��									
//Ordinals �������������								
//����ֵ˵����								
//���غ�����ַ		������0						
//**************************************************************************	
LPVOID GetFunctionAddrByOrdinals(IN LPVOID pFileBuffer, IN DWORD Ordinals)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	LPVOID mImageBuffer = NULL;

	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return 0;
	}
	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return 0;
	}
	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return 0;
	}
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;
	//�жϸ�PE�ļ��Ƿ��е�����
	if (!exportVirtualAddress)
	{
		printf("��PE�ļ������ڵ����� \r\n");
		return 0;
	}
	DWORD exportRawAddress = RvaToFileOffset(pFileBuffer, exportVirtualAddress);
	// ���������ļ��еĵ�ַ
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportRawAddress);
	// ��ַ��
	DWORD* rawAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->AddressOfFunctions));
	WORD index = Ordinals - pExportDir->Base;
	if (index > pExportDir->NumberOfFunctions)
	{
		return 0;
	}
	return (LPVOID)rawAddressOfFunctions[index];
}
//**************************************************************************								
//MoveNtAndSectionToDosStub:�ƶ�PEͷ�ͽڱ���DOSͷ����								
//����˵����								
//pFileBuffer FileBufferָ��																
//����ֵ˵����								
//���� TRUE FALSE								
//**************************************************************************	
BOOL MoveNtAndSectionToDosStub(IN LPVOID pFileBuffer)
{
	//��λ�ṹ
	PIMAGE_DOS_HEADER         pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS         pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER        pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32  pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER     pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);



	//���DOS_STUB����
	memset((LPVOID)((DWORD)pFileBuffer + sizeof(IMAGE_DOS_HEADER)), 0, pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER));

	//�ƶ����ݴ�С
	DWORD dwMoveSize = sizeof(IMAGE_NT_HEADERS) + pPEHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;

	//��������
	LPVOID pTemp = (LPVOID)malloc(dwMoveSize);
	if (!pTemp)
	{
		return FALSE;
	}
	memset(pTemp, 0, dwMoveSize);
	memcpy(pTemp, (LPVOID)((DWORD)pFileBuffer + pDosHeader->e_lfanew), dwMoveSize);

	//���Ĭ������
	memset((LPVOID)((DWORD)pFileBuffer + pDosHeader->e_lfanew), 0, dwMoveSize);

	//�ƶ�����
	memcpy((LPVOID)((DWORD)pFileBuffer + sizeof(IMAGE_DOS_HEADER)), pTemp, dwMoveSize);

	//����e_lfanewָ��
	pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	free(pTemp);

	return TRUE;
}
VOID TestMoveNtAndSectionToDosStub()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	LPVOID mImageBuffer = NULL;

	int size = ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;
	}
	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return;
	}
	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return;
	}
	if (!MoveNtAndSectionToDosStub(pFileBuffer))
	{
		printf("�ƶ�ʧ��\n");
		free(pFileBuffer);
		return;
	}
	int success = MemeryTOFile(pFileBuffer, size, (LPSTR)FILEPATH_OUT);
	if (success)
	{
		printf("�浽Ӳ��!\n");
	}

}

VOID TestMoveExportDir()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pNewSectionBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	LPVOID mImageBuffer = NULL;

	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;
	}
	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;
	//�жϸ�PE�ļ��Ƿ��е�����
	if (!exportVirtualAddress)
	{
		printf("��PE�ļ������ڵ����� \r\n");
		return;
	}
	// ���������ļ��еĵ�ַ
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, exportVirtualAddress));
	// ��һ�� ���㵼�����С
	DWORD size = pExportDir->NumberOfFunctions * 4 + pExportDir->NumberOfNames * 6;
	// ��ַ��
	DWORD* rawAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->AddressOfFunctions));
	// ��ű�
	DWORD* rawAddressOfNameOrdinals = (DWORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->AddressOfNameOrdinals));
	// ���Ʊ�
	DWORD* rawAddressOfNames = (DWORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->AddressOfNames));
	for (size_t i = 0; i < pExportDir->NumberOfNames; i++)
	{
		LPVOID rawAddressOfName = (LPVOID)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, rawAddressOfNames[i]));
		size += strlen((char*)rawAddressOfName);
	}
	// �ڶ����������������½�
	DWORD bufferSize = AddSectionToImageBuffer(pFileBuffer, size, &pNewSectionBuffer);
	if (!pNewSectionBuffer)
	{
		printf("�����ʧ��!\n");
		free(pFileBuffer);
		return;
	}
	// ��������ͷ�ĵ�ַ
	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pNewSectionBuffer;
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pNewSectionBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;

	// ���������ļ��еĵ�ַ
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pNewSectionBuffer + RvaToFileOffset(pNewSectionBuffer, exportVirtualAddress));
	// ԭ���ĵ��������
	IMAGE_EXPORT_DIRECTORY oldExportDir = pExportDir[0];
	// ��ַ��
	rawAddressOfFunctions = (DWORD*)((DWORD)pNewSectionBuffer + RvaToFileOffset(pNewSectionBuffer, pExportDir->AddressOfFunctions));
	// ��ű�
	rawAddressOfNameOrdinals = (DWORD*)((DWORD)pNewSectionBuffer + RvaToFileOffset(pNewSectionBuffer, pExportDir->AddressOfNameOrdinals));
	// ���Ʊ�
	rawAddressOfNames = (DWORD*)((DWORD)pNewSectionBuffer + RvaToFileOffset(pNewSectionBuffer, pExportDir->AddressOfNames));
	// �½���ʼ��ַ
	DWORD* pRvaStartAddress = (DWORD*)(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress);
	DWORD* pFoaStartAddress = (DWORD*)((DWORD)pNewSectionBuffer + pSectionHeader[pPEHeader->NumberOfSections - 1].PointerToRawData);
	// ����ַ��д���µĽ���
	memcpy(pFoaStartAddress, rawAddressOfFunctions, pExportDir->NumberOfFunctions * 4);
	// ���µ���ű��ַ��ֵ
	DWORD* newRawAddressOfNameOrdinals = (DWORD*)((DWORD)pFoaStartAddress + pExportDir->NumberOfFunctions * 4);
	// ��ű�����д�뵽�µ���ű��ַ
	memcpy(newRawAddressOfNameOrdinals, rawAddressOfNameOrdinals, pExportDir->NumberOfNames * 2);
	// ���µ����Ʊ��ַ��ֵ
	DWORD* newRawAddressOfNames = (DWORD*)((DWORD)newRawAddressOfNameOrdinals + pExportDir->NumberOfNames * 2);
	// ���Ʊ�����д�뵽�µ����Ʊ��ַ
	memcpy(newRawAddressOfNames, rawAddressOfNames, pExportDir->NumberOfNames * 4);
	// ���µĺ�������ʼ��ַ��ֵ
	DWORD* newRawNamesStart = (DWORD*)((DWORD)newRawAddressOfNames + pExportDir->NumberOfNames * 4);
	// ���ɵĵ��������ֵ
	oldExportDir.AddressOfFunctions = (DWORD)pRvaStartAddress + 0;
	oldExportDir.AddressOfNameOrdinals = (DWORD)pRvaStartAddress + pExportDir->NumberOfFunctions * 4;
	oldExportDir.AddressOfNames = (DWORD)pRvaStartAddress + pExportDir->NumberOfFunctions * 4 + pExportDir->NumberOfNames * 2;
	// ѭ��д�뺯����
	for (size_t i = 0; i < pExportDir->NumberOfNames; i++)
	{
		LPVOID rawAddressOfName = (LPVOID)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, rawAddressOfNames[i]));
		int nameSize = strlen((char*)rawAddressOfName);
		// ���Ʊ�����д�뵽�µ����Ʊ��ַ
		memcpy(newRawNamesStart, rawAddressOfName, nameSize);
		// �޸��µ����Ʊ�ĵ�ַ����
		newRawAddressOfNames[i] = (DWORD)newRawNamesStart;
		// �ַ���ĩβ��0�������
		newRawNamesStart = (DWORD*)((DWORD)newRawNamesStart + nameSize + 1);
	}
	// ��������Ŀ¼д��
	memcpy(newRawNamesStart, &oldExportDir, sizeof(IMAGE_EXPORT_DIRECTORY));
	// ��OPͷ�еĵ�����ĵ�ַ����
	exportVirtualAddress = (DWORD)newRawNamesStart;

	int success = MemeryTOFile(pNewSectionBuffer, bufferSize, (LPSTR)FILEPATH_OUT);
	if (success)
	{
		printf("�浽Ӳ��!\n");
	}
}
VOID TestPrintRelocationDir()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	LPVOID mImageBuffer = NULL;

	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;
	}
	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return;
	}
	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return;
	}
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	DWORD relocationVirtualAddress = pOptionHeader->DataDirectory[5].VirtualAddress;
	//�жϸ�PE�ļ��Ƿ����ض����
	if (!relocationVirtualAddress)
	{
		printf("��PE�ļ��������ض���� \r\n");
		return;
	}
	// �ض�������ļ��еĵ�ַ
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, relocationVirtualAddress));
	IMAGE_BASE_RELOCATION baseRelocation = pBaseRelocation[0];
	// ��һ����ӡ�����ض������ݵĿ�ͷ
	PIMAGE_BASE_RELOCATION tempRelocation = pBaseRelocation;
	int blockItemCount = 0;
	while (tempRelocation->VirtualAddress != 0 && tempRelocation->SizeOfBlock != 0)
	{

		printf("[%d] IMAGE_BASE_RELOCATION.VirtualAddress  -> [0x%08x] \r\n", blockItemCount, tempRelocation->VirtualAddress);
		printf("[%d] IMAGE_BASE_RELOCATION.SizeOfBlock  -> [0x%08x] \r\n", blockItemCount, tempRelocation->SizeOfBlock);
		// �ڶ�����ӡǰ4λΪ0011����������
		PWORD tempDataRelocation = (PWORD)((DWORD)tempRelocation + 8);
		PIMAGE_BASE_RELOCATION nextRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)tempRelocation + tempRelocation->SizeOfBlock);
		int blockCount = 0;
		while ((DWORD)tempDataRelocation < (DWORD)nextRelocation)
		{
			/*
			�ض�λ��λ��SizeOfBlock�����СΪ2�ֽ�,ͨ���ж����4λ��ֵ�������Ƿ���Ҫ�޸�(x86Ϊ0x3,x64Ϊ0xA)
			IMAGE_REL_BASED_ABSOLUTE	0	������,����������
			IMAGE_REL_BASED_HIGH	1	˫����,����16λ������
			IMAGE_REL_BASED_LOW	2	˫����,����16λ������
			IMAGE_REL_BASED_HIGHLOW	3	˫��32λ����Ҫ����
			IMAGE_REL_BASED_HIGHADJ	4	���л���ַ�ض�λʱ����ֵ�ĸ�16λ�ӵ�ָ��ƫ�ƴ���һ��16λ����.
			IMAGE_REL_BASED_MIPS_JMPADDR	5	��MIPSƽ̨����תָ����л���ַ�ض�λ
			IMAGE_REL_BASED_MIPS_JMPADDR16	9	��MIPS16ƽ̨����תָ����л���ַ�ض�λ
			IMAGE_REL_BASED_DIR64	10	���л���ַ�ض�λʱ����ֵ�ӵ�ָ��ƫ�ƴ���һ��64λ����

			 /�жϸ�4λ
			//32λ��4λ0011
			//64λ��4λ1010
			*/
			if (((*tempDataRelocation) & 0x3000) == 0x3000)
			{
				blockCount++;
				printf("IMAGE_BASE_RELOCATION.Block  -> [0x%08x] \r\n", ((*tempDataRelocation) & 0x0FFF) + tempRelocation->VirtualAddress);
			}

			tempDataRelocation++;
		}
		printf("IMAGE_BASE_RELOCATION.BlockCount  -> [%d] \r\n", blockCount);
		tempRelocation = nextRelocation;
		blockItemCount++;
	}
	free(pFileBuffer);
	pFileBuffer = NULL;
}

VOID TestGetFunctionAddrByOrdinals()
{
	LPVOID pFileBuffer = NULL;

	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;

	}
	printf("FunctionAddr  -> [0x%08x] \r\n", (DWORD)GetFunctionAddrByOrdinals(pFileBuffer, 3));
	free(pFileBuffer);
	pFileBuffer = NULL;
}
VOID TestGetFunctionAddrByName()
{
	LPVOID pFileBuffer = NULL;

	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;

	}
	printf("FunctionAddr  -> [0x%08x] \r\n", (DWORD)GetFunctionAddrByName(pFileBuffer, (LPVOID)"_Sub@8"));
	free(pFileBuffer);
	pFileBuffer = NULL;
}
VOID TestPrintExportDir()
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	LPVOID mImageBuffer = NULL;

	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;
	}
	//�ж��Ƿ�����Ч��MZ��־	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("������Ч��MZ��־\n");
		return;
	}
	// Dosͷ
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//�ж��Ƿ�����Ч��PE��־	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("������Ч��PE��־\n");
		return;
	}
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;
	//�жϸ�PE�ļ��Ƿ��е�����
	if (!exportVirtualAddress)
	{
		printf("��PE�ļ������ڵ����� \r\n");
		return;
	}
	DWORD exportRawAddress = RvaToFileOffset(pFileBuffer, exportVirtualAddress);
	// ���������ļ��еĵ�ַ
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportRawAddress);

	printf("IMAGE_EXPORT_DIRECTORY.Characteristics  -> [0x%08x] \r\n", pExportDir->Characteristics);
	printf("IMAGE_EXPORT_DIRECTORY.TimeDateStamp  -> [0x%08x] \r\n", pExportDir->TimeDateStamp);
	printf("IMAGE_EXPORT_DIRECTORY.MajorVersion  -> [0x%04x] \r\n", pExportDir->MajorVersion);
	printf("IMAGE_EXPORT_DIRECTORY.MinorVersion  -> [0x%04x] \r\n", pExportDir->MinorVersion);
	printf("IMAGE_EXPORT_DIRECTORY.Name -> [%s] \r\n", (char*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->Name)));
	printf("IMAGE_EXPORT_DIRECTORY.Base  -> [0x%08x] \r\n", pExportDir->Base);
	printf("IMAGE_EXPORT_DIRECTORY.NumberOfFunctions  -> [0x%08x] \r\n", pExportDir->NumberOfFunctions);
	printf("IMAGE_EXPORT_DIRECTORY.NumberOfNames  -> [0x%08x] \r\n", pExportDir->NumberOfNames);
	// ��ַ��
	DWORD rawAdrFuns = RvaToFileOffset(pFileBuffer, pExportDir->AddressOfFunctions);
	DWORD* rawAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + rawAdrFuns);
	for (size_t i = 0; i < pExportDir->NumberOfFunctions; i++)
	{
		printf("IMAGE_EXPORT_DIRECTORY.AddressOfFunctions[%d]  -> [0x%08x] \r\n", i, rawAddressOfFunctions[i]);
	}
	// ���Ʊ�+��ű�
	DWORD rawAdrNamesTemp = RvaToFileOffset(pFileBuffer, pExportDir->AddressOfNames);
	DWORD* rawAddressOfNames = (DWORD*)((DWORD)pFileBuffer + rawAdrNamesTemp);
	DWORD rawAdrNameOrdinalsTemp = RvaToFileOffset(pFileBuffer, pExportDir->AddressOfNameOrdinals);
	WORD* rawAddressOfNameOrdinals = (WORD*)((DWORD)pFileBuffer + rawAdrNameOrdinalsTemp);
	for (size_t i = 0; i < pExportDir->NumberOfNames; i++)
	{
		LPVOID rawAddressOfName = (LPVOID)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, rawAddressOfNames[i]));
		printf("IMAGE_EXPORT_DIRECTORY.AddressOfNames[%d]  -> [%s] \r\n", i, rawAddressOfName);

		printf("IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals[%d]  -> [0x%04x] \r\n", i, rawAddressOfNameOrdinals[i] + pExportDir->Base);
	}
	free(pFileBuffer);
	pFileBuffer = NULL;
}
VOID TestFiletoMemoryToFile()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewImageBuffer = NULL;
	int size = ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (size == 0)
	{
		printf("error!\n");
		exit(0);
	}
	size = CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (size == 0)
	{
		printf("error!\n");
		exit(0);
	}
	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewImageBuffer);
	if (size == 0)
	{
		printf("error!\n");
		exit(0);
	}
	int success = MemeryTOFile(pNewImageBuffer, size, (LPSTR)FILEPATH_OUT);
	if (success)
	{
		printf("�浽Ӳ��!\n");
	}
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewImageBuffer);
	pFileBuffer = NULL;
	pImageBuffer = NULL;
	pNewImageBuffer = NULL;
}
VOID TestAddCodeInCodeSec()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewImageBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PBYTE codeBegin = NULL;
	BOOL isOK = FALSE;
	DWORD size = 0;
	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;
	}
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer)
	{
		printf("buffer -> image buffer fail!\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD sizeOfRawData = pSectionHeader->SizeOfRawData;

	if (((pSectionHeader->SizeOfRawData) - (pSectionHeader->Misc.VirtualSize)) < SHELLCODELENGTH)
	{
		printf("�ռ䲻��!");
		free(pFileBuffer);
		return;
	}
	codeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
	memcpy(codeBegin, shellCode, SHELLCODELENGTH);
	// fix E8
	DWORD callAddr = (MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)pImageBuffer)));
	*(PDWORD)(codeBegin + 9) = callAddr;
	// fix E9
	DWORD jmpAddr = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)codeBegin + SHELLCODELENGTH - (DWORD)pImageBuffer)));
	*(PDWORD)(codeBegin + 0xE) = jmpAddr;
	// fix OEP
	pOptionHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;

	size = CopyImageBufferToNewBuffer(pImageBuffer, &pNewImageBuffer);
	if (size == 0 || !pNewImageBuffer)
	{
		printf("imageBuffer -> NewBuffer fail!");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	isOK = MemeryTOFile(pNewImageBuffer, size, (LPSTR)FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ�1!");
		return;
	}
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewImageBuffer);
	pFileBuffer = NULL;
	pImageBuffer = NULL;
	pNewImageBuffer = NULL;
}
VOID TestAddSection()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewImageBuffer = NULL;
	LPVOID pNewSectionBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PBYTE codeBegin = NULL;
	BOOL isOK = FALSE;
	DWORD size = 0;
	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;
	}
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer)
	{
		printf("buffer -> image buffer fail!\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	size = AddSectionToImageBuffer(pImageBuffer, 0xB, &pNewSectionBuffer);
	if (size == 0 || !pNewSectionBuffer)
	{
		printf("imageBuffer -> NewSectionBuffer fail!");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	size = CopyImageBufferToNewBuffer(pNewSectionBuffer, &pNewImageBuffer);
	if (size == 0 || !pNewImageBuffer)
	{
		printf("imageBuffer -> NewBuffer fail!");
		free(pFileBuffer);
		free(pImageBuffer);
		free(pNewSectionBuffer);
		return;
	}
	isOK = MemeryTOFile(pNewImageBuffer, size, (LPSTR)FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ�!");
		return;
	}
	free(pFileBuffer);
	free(pImageBuffer);
	free(pNewSectionBuffer);
	free(pNewImageBuffer);
	pFileBuffer = NULL;
	pImageBuffer = NULL;
	pNewSectionBuffer = NULL;
	pNewImageBuffer = NULL;
}
VOID TestExpandLastSection()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewImageBuffer = NULL;
	LPVOID pExpandSectionBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PBYTE codeBegin = NULL;
	BOOL isOK = FALSE;
	DWORD size = 0;
	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;
	}
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer)
	{
		printf("buffer -> image buffer fail!\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// ���ж������ڱ������С������
	DWORD remainingSize = pSectionHeader->VirtualAddress - pOptionHeader->SizeOfHeaders;
	if (remainingSize < 80)
	{
		printf("û���㹻�ռ�Žڱ�����");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	size = ExpandLastSection(pImageBuffer, 0xB, (LPVOID)"china NO.123", &pExpandSectionBuffer);
	if (size == 0 || !pExpandSectionBuffer)
	{
		printf("imageBuffer -> ExpandSectionBuffer fail!");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	size = CopyImageBufferToNewBuffer(pExpandSectionBuffer, &pNewImageBuffer);
	if (size == 0 || !pNewImageBuffer)
	{
		printf("imageBuffer -> NewBuffer fail!");
		free(pFileBuffer);
		free(pImageBuffer);
		free(pExpandSectionBuffer);
		return;
	}
	isOK = MemeryTOFile(pNewImageBuffer, size, (LPSTR)FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ�!");
		return;
	}
	free(pFileBuffer);
	free(pImageBuffer);
	free(pExpandSectionBuffer);
	free(pNewImageBuffer);
	pFileBuffer = NULL;
	pImageBuffer = NULL;
	pExpandSectionBuffer = NULL;
	pNewImageBuffer = NULL;
}
VOID TestMergeSection()
{
	LPVOID pFileBuffer = NULL;
	LPVOID pImageBuffer = NULL;
	LPVOID pNewImageBuffer = NULL;
	LPVOID pMergeSectionBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PBYTE codeBegin = NULL;
	BOOL isOK = FALSE;
	DWORD size = 0;
	ReadPEFile((LPSTR)FILEPATH_IN, &pFileBuffer);
	if (!pFileBuffer)
	{
		printf("file -> buffer fail!\n");
		return;
	}
	CopyFileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
	if (!pImageBuffer)
	{
		printf("buffer -> image buffer fail!\n");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	// NTͷ
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PEͷ
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//��ѡPEͷ	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// �ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	size = MergeSection(pImageBuffer, &pMergeSectionBuffer);
	if (size == 0 || !pMergeSectionBuffer)
	{
		printf("imageBuffer -> MergeSectionBuffer fail!");
		free(pFileBuffer);
		free(pImageBuffer);
		return;
	}
	size = CopyImageBufferToNewBuffer(pMergeSectionBuffer, &pNewImageBuffer);
	if (size == 0 || !pNewImageBuffer)
	{
		printf("imageBuffer -> NewBuffer fail!");
		free(pFileBuffer);
		free(pImageBuffer);
		free(pMergeSectionBuffer);
		return;
	}
	isOK = MemeryTOFile(pNewImageBuffer, size, (LPSTR)FILEPATH_OUT);
	if (isOK)
	{
		printf("���̳ɹ�!");
		return;
	}
	free(pFileBuffer);
	free(pImageBuffer);
	free(pMergeSectionBuffer);
	free(pNewImageBuffer);
	pFileBuffer = NULL;
	pImageBuffer = NULL;
	pMergeSectionBuffer = NULL;
	pNewImageBuffer = NULL;
}