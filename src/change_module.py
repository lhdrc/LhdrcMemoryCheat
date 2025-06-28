import ctypes
from ctypes import wintypes
import struct

# 定义 WinAPI 函数
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# 常量
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

# 函数定义
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

def modify_memory_value(pid, address, new_value):
    """
    修改指定进程的内存值
    :param pid: 目标进程ID
    :param address: 要修改的内存地址（十进制或十六进制）
    :param new_value: 要写入的新值（整数）
    """
    # 打开进程（需要写入权限）
    h_process = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, False, pid)
    if not h_process:
        print(f"❌ 无法打开进程 (PID: {pid}), 错误代码: {ctypes.get_last_error()}")
        return False
    
    try:
        # 将新值转换为字节（4字节小端序）
        new_value_bytes = struct.pack('<I', new_value)
        bytes_written = ctypes.c_size_t()
        
        # 写入内存
        success = WriteProcessMemory(
            h_process,
            address,
            new_value_bytes,
            len(new_value_bytes),
            ctypes.byref(bytes_written)
        )
        
        if success:
            print(f"✅ 成功修改 PID {pid} 的内存地址 0x{address:X} 为 {new_value}")
            return True
        else:
            print(f"❌ 写入失败, 错误代码: {ctypes.get_last_error()}")
            return False
    
    finally:
        CloseHandle(h_process)

def gua_api(pid,addresses,new_value):
    
    for address in addresses:
        modify_memory_value(pid, address, new_value)
    

if __name__ == "__main__":
    print("测试 gua_api 函数是否存在...")
    print("gua_api 函数:", gua_api)
# 示例：修改进程 PID=1234 的地址 0x00000000 的值为 9400
'''
if __name__ == "__main__":
    target_pid =  25100 # 替换为目标进程 PID
    #target_address = 0x00000000  # 替换为找到的内存地址
    new_value = 999999
    target_addresses = [0x81F6EC,0x81F6F0,0x16ECE3C4]
    for address in target_addresses:
        modify_memory_value(target_pid, address, new_value)
'''
