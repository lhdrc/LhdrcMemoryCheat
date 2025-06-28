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
pyinstaller --onefile --windowed --manifest resources/manifest.xml --uac-admin --icon=resources/app.ico --name LhdrcMemoryCheat src/Main.py
            
## 构建后的exe默认在dist文件夹中！

## 使用方法
- 1.先输入你要监控的进程
- 2.输入你想更改的东西的现在的值
- 3.输入目标值（比如说你的初始值为0，你现在在游戏中进行操作可以让他变为100，那么请先在目标值处输入100，开始监控，再进行游戏中的操作）
- 4.点击开始监控
- 5.游戏中进行操作
- 6.查看监控结果，如果找到了即为成功
- 7.“在你想要的数值”中填入你想要让他变成多少
- 8.点击修改值，如果提示修改成功即为成功
