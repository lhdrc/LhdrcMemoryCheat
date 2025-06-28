# Memory Editor Tool

🔧 Windows平台内存修改工具 | 🛡️ 需管理员权限 | 🐍 Python 3.9+

## 🚀 功能特性
- 实时扫描进程内存
- 监控特定值的变化
- 批量修改内存数据
- 自动请求管理员权限

## ⚙️ 运行环境
- Python 3.9+
- Windows 11

## 依赖安装（可以创建虚拟环境）
pip install pywin32 psutil ctypes

## 构建.exe(请先安装依赖，然后在该文件夹下打开cmd)
pyinstaller --onefile --windowed \
            --manifest manifest.xml \
            ----uac-admin \
            --icon resources/app.ico \
            --name MemoryEditor \
            src/main.py
            
## 构建后的exe默认在dist文件夹中！
