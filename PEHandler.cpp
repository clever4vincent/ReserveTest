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
//函数声明								
//**************************************************************************								
//ReadPEFile:将文件读取到缓冲区								
//参数说明：								
//lpszFile 文件路径								
//pFileBuffer 缓冲区指针								
//返回值说明：								
//读取失败返回0  否则返回实际读取的大小								
//**************************************************************************								
DWORD ReadPEFile(IN LPSTR lpszFile, OUT LPVOID* pFileBuffer)
{
	FILE* fp;
	LPVOID ptr;
	DWORD fileSize;
	//判断文件是否打开失败
	if ((fp = fopen(lpszFile, "rb")) == NULL) {
		printf("Fail to open file!");
		return 0;
	}
	// 获取文件末地址
	fseek(fp, 0L, SEEK_END);
	// 计算文件大小
	fileSize = ftell(fp);
	// 回到文件首地址
	rewind(fp);
	// 动态分配内存
	ptr = malloc(fileSize);
	if (ptr == NULL)
	{
		printf("Fail to malloc!");
		fclose(fp);
		return 0;
	}
	//memset(ptr,0,fileSize);
	// 定位到文件开头
	size_t n = fread(ptr, fileSize, 1, fp);
	if (!n)
	{
		printf(" 读取数据失败! ");
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
//CopyFileBufferToImageBuffer:将文件从FileBuffer复制到ImageBuffer								
//参数说明：								
//pFileBuffer  FileBuffer指针								
//pImageBuffer ImageBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
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
		printf("缓冲区指针无效\n");
		return 0;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return 0;
	}

	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}

	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节目录
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	mImageBuffer = malloc(pOptionHeader->SizeOfImage);
	if (mImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}

	// 初始化缓冲区
	memset(mImageBuffer, 0, pOptionHeader->SizeOfImage);
	// COPY头
	memcpy(mImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);
	int sectionSize = 0;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
		if (pSectionHeader[i].SizeOfRawData == 0) {
			sectionSize = pOptionHeader->SectionAlignment; // 最小内存Seciton单位为 SectionAlignment的大小
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
//CopyImageBufferToNewBuffer:将ImageBuffer中的数据复制到新的缓冲区								
//参数说明：								
//pImageBuffer ImageBuffer指针								
//pNewBuffer NewBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
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
		printf("文件读取失败\n");
		return 0;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return 0;
	}
	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}

	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	int lastNum = pPEHeader->NumberOfSections - 1;
	// 计算EXE硬盘格式大小= 节表最后一个区的文件中偏移+文件中对齐后的尺寸
	pBufferSize = pSectionHeader[lastNum].PointerToRawData + pSectionHeader[lastNum].SizeOfRawData;
	mImageBuffer = malloc(pBufferSize);
	if (mImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}
	// 初始化缓冲区
	memset(mImageBuffer, 0, pBufferSize);
	// copy PE header 
	memcpy(mImageBuffer, pFileBuffer, pOptionHeader->SizeOfHeaders);

	CHAR szSecName[9] = { 0 };
	int sectionSize = 0;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++) {
		memset(szSecName, 0, 9);
		memcpy(szSecName, pSectionHeader[i].Name, IMAGE_SIZEOF_SHORT_NAME);
		printf("********************第%d节表头********************\n", i + 1);
		printf("section name: %s\n", szSecName);
		if (pSectionHeader[i].SizeOfRawData == 0) {
			sectionSize = pOptionHeader->FileAlignment; // 最小内存Seciton单位为 SectionAlignment的大小
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
//AddSectionToImageBuffer:将ImageBuffer中的数据复制到新的缓冲区并加入新的节和数据								
//参数说明：								
//pImageBuffer ImageBuffer指针	
//pDataSize 数据大小							
//pNewSectionBuffer NewSectionBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小	
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
		printf("缓冲区指针无效\n");
		return 0;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return 0;
	}

	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;

	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}

	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节目录
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);


	//判断头部是否有空间新增节
	if ((PUCHAR)pImageBuffer + pOptionHeader->SizeOfHeaders - (PUCHAR)(&pSectionHeader[pPEHeader->NumberOfSections + 1]) < IMAGE_SIZEOF_SECTION_HEADER)
	{
		//抹除DOS_STUB数据并将NT,SECTION整理向上移动
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


	// 计算申请内存的大小 
	DWORD addSectionMisc = Align(pDataSize, pOptionHeader->SectionAlignment);
	size = (pOptionHeader->SizeOfImage) + addSectionMisc;

	pTmepImageBuffer = malloc(size);
	if (pTmepImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}
	// 初始化缓冲区
	memset(pTmepImageBuffer, 0, size);

	// 修改流程一 组装新增节的信息，将新增的节添加到节表中
	DWORD sectionSize = pPEHeader->NumberOfSections;
	IMAGE_SECTION_HEADER lastSectionHeader = pSectionHeader[sectionSize - 1];
	// 组装新增节的信息
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
	// 将新增的节添加到节表中
	pSectionHeader[sectionSize] = addSectionHeader;
	// 在新增节点之后补一个节表的0
	pSectionHeader[sectionSize + 1] = zeroSectionHeader;
	// 修改流程二 修改PE头中节的数目
	pPEHeader->NumberOfSections = (pPEHeader->NumberOfSections) + 1;
	// 修改流程三 修改PE头中SizeOfImage
	DWORD OriSizeOfImage = pOptionHeader->SizeOfImage;
	pOptionHeader->SizeOfImage = OriSizeOfImage + addSectionMisc;
	// 将之前的内容全数COPY
	memcpy(pTmepImageBuffer, pImageBuffer, OriSizeOfImage);
	*pNewSectionBuffer = pTmepImageBuffer;
	pNewSectionBuffer = NULL;
	return size;
}
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
		printf("缓冲区指针无效\n");
		return 0;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return 0;
	}

	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;

	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}

	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节目录
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// 计算申请内存的大小 
	DWORD addSectionMisc = Align(pDataSize, pOptionHeader->SectionAlignment);
	size = (pOptionHeader->SizeOfImage) + addSectionMisc;

	pTmepImageBuffer = malloc(size);
	if (pTmepImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}
	// 初始化缓冲区
	memset(pTmepImageBuffer, 0, size);
	// 修改流程一 修改节表中最后一个节的数据
	DWORD sectionSize = pPEHeader->NumberOfSections;
	IMAGE_SECTION_HEADER lastSectionHeader = pSectionHeader[sectionSize - 1];
	// 计算节的文件大小
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
	// 修改最后节的数据
	lastSectionHeader.Misc.VirtualSize = destLastSectionSize;
	lastSectionHeader.SizeOfRawData = destLastSectionSize;
	lastSectionHeader.Characteristics = pSectionHeader->Characteristics;
	// 对最后节进行赋值
	pSectionHeader[sectionSize - 1] = lastSectionHeader;
	// 修改流程三 修改PE头中SizeOfImage
	DWORD OriSizeOfImage = pOptionHeader->SizeOfImage;
	pOptionHeader->SizeOfImage = OriSizeOfImage + addSectionMisc;
	// 将之前的内容全数COPY
	memcpy(pTmepImageBuffer, pImageBuffer, OriSizeOfImage);
	// 修改流程四 将数据加入到最后一节的下方
	// 将指针定位到原先缓存区的最后
	LPVOID pDataStart = LPVOID((DWORD)pTmepImageBuffer + OriSizeOfImage);
	// 将数据加入到最后一节
	memcpy(pDataStart, pData, pDataSize);
	*pExpandSectionBuffer = pTmepImageBuffer;
	pExpandSectionBuffer = NULL;
	return size;
}
//**************************************************************************	
//MergeSection:将所有节合并到一个节上							
//参数说明：								
//pImageBuffer ImageBuffer指针								
//pMergeSectionBuffer MergeSectionBuffer指针								
//返回值说明：								
//读取失败返回0  否则返回复制的大小	
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
		printf("缓冲区指针无效\n");
		return 0;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pImageBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return 0;
	}

	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;

	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pImageBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}
	// 合并节表的过程： 1 修改第一个节的信息 2 修改NumberOfSections
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节目录
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// 计算申请内存的大小 
	size = (pOptionHeader->SizeOfImage);

	pTmepImageBuffer = malloc(size);
	if (pTmepImageBuffer == NULL)
	{
		printf("Fail to malloc!");
		return 0;
	}
	// 初始化缓冲区
	memset(pTmepImageBuffer, 0, size);

	// 修改流程一 修改第一个节的信息
	IMAGE_SECTION_HEADER firstSectionHeader = pSectionHeader[0];
	// 计算节的文件大小
	DWORD firstSectionSize = size - firstSectionHeader.VirtualAddress;
	// 计算Characteristics的值
	DWORD characteristics = 0;
	for (int i = 0; i < pPEHeader->NumberOfSections; i++)
	{
		characteristics |= pSectionHeader[i].Characteristics;
	}
	firstSectionHeader.Misc.VirtualSize = firstSectionSize;
	firstSectionHeader.SizeOfRawData = firstSectionSize;
	firstSectionHeader.Characteristics = characteristics;
	// 对第一个节进行赋值
	pSectionHeader[0] = firstSectionHeader;

	// 修改流程二 修改NumberOfSections
	pPEHeader->NumberOfSections = 1;

	// 将之前的内容全数COPY
	memcpy(pTmepImageBuffer, pImageBuffer, size);
	*pMergeSectionBuffer = pTmepImageBuffer;
	pMergeSectionBuffer = NULL;
	return size;
}
//**************************************************************************								
//MemeryTOFile:将内存中的数据复制到文件								
//参数说明：								
//pMemBuffer 内存中数据的指针								
//size 要复制的大小								
//lpszFile 要存储的文件路径								
//返回值说明：								
//读取失败返回0  否则返回复制的大小								
//**************************************************************************								
BOOL MemeryTOFile(IN LPVOID pMemBuffer, IN size_t size, OUT LPSTR lpszFile)
{
	FILE* fp;
	//判断文件是否打开失败
	if ((fp = fopen(lpszFile, "wb")) == NULL) {
		printf("Fail to open file!");
		return 0;
	}
	size_t count = fwrite(pMemBuffer, size, 1, fp);
	fclose(fp);
	return count;
}
//**************************************************************************								
//RvaToFileOffset:将内存偏移转换为文件偏移								
//参数说明：								
//pFileBuffer FileBuffer指针								
//dwRva RVA的值								
//返回值说明：								
//返回转换后的FOA的值  如果失败返回0								
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
		printf("缓冲区指针无效\n");
		return 0;
	}

	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return 0;
	}

	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}

	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节目录
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// 怎么转化 先判断地址在哪个区间
	//当前地址 如果在SizeOfHeaders之内的就返回当前地址-imageBase
	// 当前地址 如果比第一节大
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
	printf("拉伸后填充的数据，文件里原本没有!\n");
	return 0;
}
//**************************************************************************								
//Align:将内存偏移转换为文件偏移								
//参数说明：								
//pData 要对齐的数据								
//pAlignSize 对齐大小								
//返回值说明：								
//返回对齐后的值	出错返回0						
//**************************************************************************							
DWORD Align(DWORD pData, DWORD pAlignSize)
{
	DWORD x = pData / pAlignSize;
	DWORD y = pData % pAlignSize;
	return (x * pAlignSize) + (y > 0 ? pAlignSize : 0);
}
//**************************************************************************								
//GetFunctionAddrByName:通过函数名指针获取函数地址								
//参数说明：								
//pFileBuffer FileBuffer指针									
//pName 函数名指针								
//返回值说明：								
//返回函数地址		出错返回0						
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
	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return 0;
	}
	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;
	//判断该PE文件是否有导出表
	if (!exportVirtualAddress)
	{
		printf("该PE文件不存在导出表 \r\n");
		return 0;
	}
	DWORD exportRawAddress = RvaToFileOffset(pFileBuffer, exportVirtualAddress);
	// 导出表在文件中的地址
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportRawAddress);
	// 地址表
	DWORD rawAdrFuns = RvaToFileOffset(pFileBuffer, pExportDir->AddressOfFunctions);
	DWORD* rawAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + rawAdrFuns);
	// 名称表+序号表
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
//GetFunctionAddrByName:通过函数名指针获取函数地址								
//参数说明：								
//pFileBuffer FileBuffer指针									
//Ordinals 函数名导出序号								
//返回值说明：								
//返回函数地址		出错返回0						
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
	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return 0;
	}
	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return 0;
	}
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;
	//判断该PE文件是否有导出表
	if (!exportVirtualAddress)
	{
		printf("该PE文件不存在导出表 \r\n");
		return 0;
	}
	DWORD exportRawAddress = RvaToFileOffset(pFileBuffer, exportVirtualAddress);
	// 导出表在文件中的地址
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportRawAddress);
	// 地址表
	DWORD* rawAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->AddressOfFunctions));
	WORD index = Ordinals - pExportDir->Base;
	if (index > pExportDir->NumberOfFunctions)
	{
		return 0;
	}
	return (LPVOID)rawAddressOfFunctions[index];
}
//**************************************************************************								
//MoveNtAndSectionToDosStub:移动PE头和节表至DOS头后面								
//参数说明：								
//pFileBuffer FileBuffer指针																
//返回值说明：								
//返回 TRUE FALSE								
//**************************************************************************	
BOOL MoveNtAndSectionToDosStub(IN LPVOID pFileBuffer)
{
	//定位结构
	PIMAGE_DOS_HEADER         pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS         pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER        pPEHeader = (PIMAGE_FILE_HEADER)((DWORD)pNTHeader + 4);
	PIMAGE_OPTIONAL_HEADER32  pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER     pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);



	//清空DOS_STUB数据
	memset((LPVOID)((DWORD)pFileBuffer + sizeof(IMAGE_DOS_HEADER)), 0, pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER));

	//移动数据大小
	DWORD dwMoveSize = sizeof(IMAGE_NT_HEADERS) + pPEHeader->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;

	//备份数据
	LPVOID pTemp = (LPVOID)malloc(dwMoveSize);
	if (!pTemp)
	{
		return FALSE;
	}
	memset(pTemp, 0, dwMoveSize);
	memcpy(pTemp, (LPVOID)((DWORD)pFileBuffer + pDosHeader->e_lfanew), dwMoveSize);

	//清空默认数据
	memset((LPVOID)((DWORD)pFileBuffer + pDosHeader->e_lfanew), 0, dwMoveSize);

	//移动数据
	memcpy((LPVOID)((DWORD)pFileBuffer + sizeof(IMAGE_DOS_HEADER)), pTemp, dwMoveSize);

	//修正e_lfanew指向
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
	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return;
	}
	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return;
	}
	if (!MoveNtAndSectionToDosStub(pFileBuffer))
	{
		printf("移动失败\n");
		free(pFileBuffer);
		return;
	}
	int success = MemeryTOFile(pFileBuffer, size, (LPSTR)FILEPATH_OUT);
	if (success)
	{
		printf("存到硬盘!\n");
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
	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;
	//判断该PE文件是否有导出表
	if (!exportVirtualAddress)
	{
		printf("该PE文件不存在导出表 \r\n");
		return;
	}
	// 导出表在文件中的地址
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, exportVirtualAddress));
	// 第一步 计算导出表大小
	DWORD size = pExportDir->NumberOfFunctions * 4 + pExportDir->NumberOfNames * 6;
	// 地址表
	DWORD* rawAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->AddressOfFunctions));
	// 序号表
	DWORD* rawAddressOfNameOrdinals = (DWORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->AddressOfNameOrdinals));
	// 名称表
	DWORD* rawAddressOfNames = (DWORD*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->AddressOfNames));
	for (size_t i = 0; i < pExportDir->NumberOfNames; i++)
	{
		LPVOID rawAddressOfName = (LPVOID)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, rawAddressOfNames[i]));
		size += strlen((char*)rawAddressOfName);
	}
	// 第二步往缓存区加入新节
	DWORD bufferSize = AddSectionToImageBuffer(pFileBuffer, size, &pNewSectionBuffer);
	if (!pNewSectionBuffer)
	{
		printf("加入节失败!\n");
		free(pFileBuffer);
		return;
	}
	// 更新所有头的地址
	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pNewSectionBuffer;
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pNewSectionBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;

	// 导出表在文件中的地址
	pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pNewSectionBuffer + RvaToFileOffset(pNewSectionBuffer, exportVirtualAddress));
	// 原来的导出表对象
	IMAGE_EXPORT_DIRECTORY oldExportDir = pExportDir[0];
	// 地址表
	rawAddressOfFunctions = (DWORD*)((DWORD)pNewSectionBuffer + RvaToFileOffset(pNewSectionBuffer, pExportDir->AddressOfFunctions));
	// 序号表
	rawAddressOfNameOrdinals = (DWORD*)((DWORD)pNewSectionBuffer + RvaToFileOffset(pNewSectionBuffer, pExportDir->AddressOfNameOrdinals));
	// 名称表
	rawAddressOfNames = (DWORD*)((DWORD)pNewSectionBuffer + RvaToFileOffset(pNewSectionBuffer, pExportDir->AddressOfNames));
	// 新节起始地址
	DWORD* pRvaStartAddress = (DWORD*)(pSectionHeader[pPEHeader->NumberOfSections - 1].VirtualAddress);
	DWORD* pFoaStartAddress = (DWORD*)((DWORD)pNewSectionBuffer + pSectionHeader[pPEHeader->NumberOfSections - 1].PointerToRawData);
	// 将地址表写到新的节中
	memcpy(pFoaStartAddress, rawAddressOfFunctions, pExportDir->NumberOfFunctions * 4);
	// 给新的序号表地址赋值
	DWORD* newRawAddressOfNameOrdinals = (DWORD*)((DWORD)pFoaStartAddress + pExportDir->NumberOfFunctions * 4);
	// 序号表数据写入到新的序号表地址
	memcpy(newRawAddressOfNameOrdinals, rawAddressOfNameOrdinals, pExportDir->NumberOfNames * 2);
	// 给新的名称表地址赋值
	DWORD* newRawAddressOfNames = (DWORD*)((DWORD)newRawAddressOfNameOrdinals + pExportDir->NumberOfNames * 2);
	// 名称表数据写入到新的名称表地址
	memcpy(newRawAddressOfNames, rawAddressOfNames, pExportDir->NumberOfNames * 4);
	// 给新的函数名起始地址赋值
	DWORD* newRawNamesStart = (DWORD*)((DWORD)newRawAddressOfNames + pExportDir->NumberOfNames * 4);
	// 给旧的导出表对象赋值
	oldExportDir.AddressOfFunctions = (DWORD)pRvaStartAddress + 0;
	oldExportDir.AddressOfNameOrdinals = (DWORD)pRvaStartAddress + pExportDir->NumberOfFunctions * 4;
	oldExportDir.AddressOfNames = (DWORD)pRvaStartAddress + pExportDir->NumberOfFunctions * 4 + pExportDir->NumberOfNames * 2;
	// 循环写入函数名
	for (size_t i = 0; i < pExportDir->NumberOfNames; i++)
	{
		LPVOID rawAddressOfName = (LPVOID)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, rawAddressOfNames[i]));
		int nameSize = strlen((char*)rawAddressOfName);
		// 名称表数据写入到新的名称表地址
		memcpy(newRawNamesStart, rawAddressOfName, nameSize);
		// 修复新的名称表的地址数据
		newRawAddressOfNames[i] = (DWORD)newRawNamesStart;
		// 字符串末尾补0代表结束
		newRawNamesStart = (DWORD*)((DWORD)newRawNamesStart + nameSize + 1);
	}
	// 将导出表目录写入
	memcpy(newRawNamesStart, &oldExportDir, sizeof(IMAGE_EXPORT_DIRECTORY));
	// 将OP头中的导出表的地址修正
	exportVirtualAddress = (DWORD)newRawNamesStart;

	int success = MemeryTOFile(pNewSectionBuffer, bufferSize, (LPSTR)FILEPATH_OUT);
	if (success)
	{
		printf("存到硬盘!\n");
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
	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return;
	}
	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return;
	}
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	DWORD relocationVirtualAddress = pOptionHeader->DataDirectory[5].VirtualAddress;
	//判断该PE文件是否有重定向表
	if (!relocationVirtualAddress)
	{
		printf("该PE文件不存在重定向表 \r\n");
		return;
	}
	// 重定向表在文件中的地址
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, relocationVirtualAddress));
	IMAGE_BASE_RELOCATION baseRelocation = pBaseRelocation[0];
	// 第一步打印所有重定向数据的块头
	PIMAGE_BASE_RELOCATION tempRelocation = pBaseRelocation;
	int blockItemCount = 0;
	while (tempRelocation->VirtualAddress != 0 && tempRelocation->SizeOfBlock != 0)
	{

		printf("[%d] IMAGE_BASE_RELOCATION.VirtualAddress  -> [0x%08x] \r\n", blockItemCount, tempRelocation->VirtualAddress);
		printf("[%d] IMAGE_BASE_RELOCATION.SizeOfBlock  -> [0x%08x] \r\n", blockItemCount, tempRelocation->SizeOfBlock);
		// 第二步打印前4位为0011的有用数据
		PWORD tempDataRelocation = (PWORD)((DWORD)tempRelocation + 8);
		PIMAGE_BASE_RELOCATION nextRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)tempRelocation + tempRelocation->SizeOfBlock);
		int blockCount = 0;
		while ((DWORD)tempDataRelocation < (DWORD)nextRelocation)
		{
			/*
			重定位项位于SizeOfBlock后其大小为2字节,通过判断其高4位的值来决定是否需要修复(x86为0x3,x64为0xA)
			IMAGE_REL_BASED_ABSOLUTE	0	无意义,仅作对齐用
			IMAGE_REL_BASED_HIGH	1	双字中,仅高16位被修正
			IMAGE_REL_BASED_LOW	2	双字中,仅低16位被修正
			IMAGE_REL_BASED_HIGHLOW	3	双字32位都需要修正
			IMAGE_REL_BASED_HIGHADJ	4	进行基地址重定位时将差值的高16位加到指定偏移处的一个16位域上.
			IMAGE_REL_BASED_MIPS_JMPADDR	5	对MIPS平台的跳转指令进行基地址重定位
			IMAGE_REL_BASED_MIPS_JMPADDR16	9	对MIPS16平台的跳转指令进行基地址重定位
			IMAGE_REL_BASED_DIR64	10	进行基地址重定位时将差值加到指定偏移处的一个64位域上

			 /判断高4位
			//32位高4位0011
			//64位高4位1010
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
	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		return;
	}
	// Dos头
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		return;
	}
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	DWORD exportVirtualAddress = pOptionHeader->DataDirectory[0].VirtualAddress;
	//判断该PE文件是否有导出表
	if (!exportVirtualAddress)
	{
		printf("该PE文件不存在导出表 \r\n");
		return;
	}
	DWORD exportRawAddress = RvaToFileOffset(pFileBuffer, exportVirtualAddress);
	// 导出表在文件中的地址
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pFileBuffer + exportRawAddress);

	printf("IMAGE_EXPORT_DIRECTORY.Characteristics  -> [0x%08x] \r\n", pExportDir->Characteristics);
	printf("IMAGE_EXPORT_DIRECTORY.TimeDateStamp  -> [0x%08x] \r\n", pExportDir->TimeDateStamp);
	printf("IMAGE_EXPORT_DIRECTORY.MajorVersion  -> [0x%04x] \r\n", pExportDir->MajorVersion);
	printf("IMAGE_EXPORT_DIRECTORY.MinorVersion  -> [0x%04x] \r\n", pExportDir->MinorVersion);
	printf("IMAGE_EXPORT_DIRECTORY.Name -> [%s] \r\n", (char*)((DWORD)pFileBuffer + RvaToFileOffset(pFileBuffer, pExportDir->Name)));
	printf("IMAGE_EXPORT_DIRECTORY.Base  -> [0x%08x] \r\n", pExportDir->Base);
	printf("IMAGE_EXPORT_DIRECTORY.NumberOfFunctions  -> [0x%08x] \r\n", pExportDir->NumberOfFunctions);
	printf("IMAGE_EXPORT_DIRECTORY.NumberOfNames  -> [0x%08x] \r\n", pExportDir->NumberOfNames);
	// 地址表
	DWORD rawAdrFuns = RvaToFileOffset(pFileBuffer, pExportDir->AddressOfFunctions);
	DWORD* rawAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + rawAdrFuns);
	for (size_t i = 0; i < pExportDir->NumberOfFunctions; i++)
	{
		printf("IMAGE_EXPORT_DIRECTORY.AddressOfFunctions[%d]  -> [0x%08x] \r\n", i, rawAddressOfFunctions[i]);
	}
	// 名称表+序号表
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
		printf("存到硬盘!\n");
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
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

	DWORD sizeOfRawData = pSectionHeader->SizeOfRawData;

	if (((pSectionHeader->SizeOfRawData) - (pSectionHeader->Misc.VirtualSize)) < SHELLCODELENGTH)
	{
		printf("空间不够!");
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
		printf("存盘成功1!");
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
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节表
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
		printf("存盘成功!");
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
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	// 先判断新增节表后续大小够不够
	DWORD remainingSize = pSectionHeader->VirtualAddress - pOptionHeader->SizeOfHeaders;
	if (remainingSize < 80)
	{
		printf("没有足够空间放节表数据");
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
		printf("存盘成功!");
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
	// NT头
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
	// PE头
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	//可选PE头	
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	// 节表
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
		printf("存盘成功!");
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