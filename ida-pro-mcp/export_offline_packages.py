# Author: yszhang
# Description: 用于在有网络的电脑上导出 ida-pro-mcp 及其所有依赖的离线安装包

import os
import subprocess
import sys
from pathlib import Path

def main():
    print("开始准备离线安装包...")
    
    # 当前项目目录
    project_dir = Path(__file__).parent.absolute()
    
    # 离线包保存目录
    output_dir = project_dir / "offline_packages"
    output_dir.mkdir(exist_ok=True)
    
    print(f"依赖包将下载至: {output_dir}")
    
    # 使用 pip download 下载当前项目及其依赖
    # 注意：为了确保跨平台或针对目标平台（如果目标机器是 Windows）
    # 这里默认下载适用于 Windows 的预编译包（如果可能）
    try:
        # 使用 pip wheel 导出当前项目及其所有依赖到指定目录
        cmd = [
            sys.executable, "-m", "pip", "wheel", 
            str(project_dir), 
            "-w", str(output_dir)
        ]
        
        print(f"执行命令: {' '.join(cmd)}")
        subprocess.check_call(cmd)
        
        print("\n打包完成！")
        print(f"请将 '{output_dir}' 整个文件夹复制到离线电脑上。")
        print("在离线电脑上执行以下命令进行安装（注意替换路径）：")
        print(f"pip install --no-index --find-links=\"<离线包所在路径>\" ida-pro-mcp")
        print("\n安装完成后，记得在离线电脑上运行：")
        print("ida-pro-mcp --install")
        
    except subprocess.CalledProcessError as e:
        print(f"下载过程中出现错误: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
