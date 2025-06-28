import ctypes
from ctypes import wintypes
import struct
import time
import psutil
import tkinter as tk
from tkinter import ttk, messagebox
import threading
from change_module import gua_api

# 定义 WinAPI 函数和常量
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)

# 常量
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PAGE_READWRITE = 0x04

# 结构体
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

# 正确定义所有需要的 WinAPI 函数
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = wintypes.HANDLE

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wintypes.BOOL

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

class MemoryMonitor:
    def __init__(self):
        self.monitoring = False
        self.monitor_thread = None
        self.found_addresses = []
        self.changed_addresses = []
    
    def get_process_id(self, process_name):
        """获取进程 PID（例如 'a.exe'）"""
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                return proc.info['pid']
        return None
    
    def scan_process_memory(self, pid, initial_value):
        """扫描进程内存，找到所有 initial_value 的地址"""
        self.found_addresses = []
        initial_bytes = struct.pack('<I', initial_value)  # 小端序 4 字节
        h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_process:
            print(f"❌ 无法打开进程 (PID: {pid}), 错误代码: {ctypes.get_last_error()}")
            return self.found_addresses
        
        try:
            mbi = MEMORY_BASIC_INFORMATION()
            address = 0
            
            while True:
                if not VirtualQueryEx(h_process, address, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                    break
                
                # 仅扫描可读写内存（PAGE_READWRITE）
                if (mbi.State == 0x1000) and (mbi.Protect == PAGE_READWRITE):
                    try:
                        buffer = (ctypes.c_byte * mbi.RegionSize)()
                        bytes_read = ctypes.c_size_t()
                        
                        if ReadProcessMemory(h_process, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                            data = bytes(buffer)
                            offset = 0
                            
                            while True:
                                offset = data.find(initial_bytes, offset)
                                if offset == -1:
                                    break
                                
                                found_address = mbi.BaseAddress + offset
                                self.found_addresses.append(found_address)
                                offset += 4
                    
                    except Exception as e:
                        pass
                
                address += mbi.RegionSize
        
        finally:
            CloseHandle(h_process)
        
        return self.found_addresses
    
    def monitor_changes(self, pid, addresses, target_value, callback=None):
        """监控内存变化"""
        target_bytes = struct.pack('<I', target_value)
        self.changed_addresses = []
        
        while self.monitoring:
            for addr in addresses[:]:
                if not isinstance(addr, int):
                    continue
                
                h_process = OpenProcess(PROCESS_VM_READ, False, pid)
                if not h_process:
                    addresses.remove(addr)
                    continue
                
                try:
                    buffer = (ctypes.c_byte * 4)()
                    bytes_read = ctypes.c_size_t()
                    
                    addr_ptr = ctypes.c_void_p(addr)
                    
                    if ReadProcessMemory(
                        h_process,
                        addr_ptr,
                        buffer,
                        4,
                        ctypes.byref(bytes_read)
                    ):
                        current_value = struct.unpack('<I', bytes(buffer))[0]
                        
                        if current_value == target_value:
                            message = f"🚨 地址 0x{addr:X} 的值变为 {target_value}！"
                            print(message)
                            if callback:
                                callback(message)
                            addresses.remove(addr)
                            self.changed_addresses.append(addr)
                
                finally:
                    CloseHandle(h_process)
            
            time.sleep(1)
        
        print("监控结束")
        result = "\n".join([f"0x{addr:X}," for addr in self.changed_addresses])
        if callback:
            callback(f"监控结束\n找到的地址:\n{result}")
        print(result)

class GUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Lhdrc")
        self.master.geometry("600x400")
        
        self.monitor = MemoryMonitor()
        
        self.create_widgets()
    
    def create_widgets(self):
        # 输入框架
        input_frame = ttk.LabelFrame(self.master, text="监控参数", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # 进程名
        ttk.Label(input_frame, text="目标进程名:").grid(row=0, column=0, sticky=tk.W)
        self.target_process = ttk.Entry(input_frame)
        self.target_process.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # 初始值
        ttk.Label(input_frame, text="初始值:").grid(row=1, column=0, sticky=tk.W)
        self.ini_value_entry = ttk.Entry(input_frame)
        self.ini_value_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # 目标值
        ttk.Label(input_frame, text="目标值:").grid(row=2, column=0, sticky=tk.W)
        self.tar_value_entry = ttk.Entry(input_frame)
        self.tar_value_entry.grid(row=2, column=1, sticky=tk.EW, padx=5, pady=2)

        #要更改到的值
        ttk.Label(input_frame, text="你想要的数值:").grid(row=2, column=3, sticky=tk.W)
        self.change_value_entry = ttk.Entry(input_frame)
        self.change_value_entry.grid(row=2, column=4, sticky=tk.EW, padx=5, pady=2)
        
        # 按钮框架
        button_frame = ttk.Frame(self.master)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.start_button = ttk.Button(button_frame, text="开始监控", command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="停止监控", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.change_button = ttk.Button(button_frame, text="修改值", command=self.change_value)
        self.change_button.pack(side=tk.LEFT,padx=5)
        
        # 输出框
        output_frame = ttk.LabelFrame(self.master, text="监控结果", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.output_text = tk.Text(output_frame, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_text.config(yscrollcommand=scrollbar.set)
    
    def log_message(self, message):
        """向输出框添加消息"""
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
    
    def start_monitoring(self):
        """开始监控"""
        process_name = self.target_process.get().strip()
        if not process_name:
            messagebox.showerror("错误", "请输入目标进程名！")
            return
        
        try:
            initial_value = int(self.ini_value_entry.get())
            target_value = int(self.tar_value_entry.get())
        except ValueError:
            messagebox.showerror("错误", "初始值和目标值必须是整数！")
            return
        
        pid = self.monitor.get_process_id(process_name)
        if not pid:
            messagebox.showerror("错误", f"未找到进程: {process_name}")
            return
        
        self.log_message(f"开始监控进程 {process_name} (PID: {pid})")
        
        # 扫描内存
        self.monitor.found_addresses = self.monitor.scan_process_memory(pid, initial_value)
        if not self.monitor.found_addresses:
            self.log_message("未找到匹配的内存地址")
            return
        
        self.log_message(f"找到 {len(self.monitor.found_addresses)} 个可能的内存地址")
        
        # 启动监控线程
        self.monitor.monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.monitor_thread = threading.Thread(
            target=self.monitor.monitor_changes,
            args=(pid, self.monitor.found_addresses, target_value, self.log_message),
            daemon=True
        )
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """停止监控"""
        self.monitor.monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_message("正在停止监控...")
    
    def change_value(self):
        pid = self.monitor.get_process_id(self.target_process.get())
        if(not pid):
            messagebox.showerror("错误", "请输入目标进程名！")
            return
        new_value = int(self.change_value_entry.get())
        if(not new_value):
            messagebox.showerror("错误", "请输入要修改的值！")
            return
        gua_api(pid,self.monitor.changed_addresses,new_value)
        for address in self.monitor.changed_addresses:
            self.log_message(f"修改地址0x{address:X} 的值为 {new_value}!")

if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()