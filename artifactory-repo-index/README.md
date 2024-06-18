# Artifactory Repository Scanner

## 概述

该项目是一个Python脚本，用于对JFrog Xray的 Indexed Resources 的数据进行解释；
支持并发API调用，结果可以保存为CSV、JSON或表格格式。

## 安装

1. 克隆项目到本地：
    ```sh
    git clone https://github.com/jfrogchina/MaintainenceTools.git
    ```

2. 进入项目目录：
    ```sh
    cd MaintainenceTools/artifactory-repo-index
    ```

3. 准备python3环境及依赖包：
    ```sh
    python3 -m venv repoindex
    source repoindex/bin/activate
    python3 -m pip install argparse requests tqdm wcwidth tabulate
    ```

## 使用方法

### 命令行参数

- `reponame`: 仓库的名称 (必需)
- `--base_url`: Artifactory实例的基本URL (默认: `http://localhost:8082`)
- `--pkg_support`: 包支持规则文件 (默认: `Xray_pkg_support.json`)
- `--username`: Artifactory用户名 (默认: `admin`)
- `--password`: Artifactory密码 (默认: `password`)
- `--scan_result_save`: 保存扫描结果的文件 (默认: `scan_details.file`)
- `--print_lines`: 在控制台打印的行数 (默认: `10`)
- `--format`: 数据格式: `table` | `json` | `csv` (默认: `table`)
- `--clear_log`: 是否清空日志 (默认: `True`)
- `--threads`: 并发API调用的线程数 (默认: `50`)

### 运行示例

1. 运行脚本：
    ```python
    python3 indexer.py my-repo --base_url=https://demo.jfrogchina.com --username myuser --password mypass --scan_result_save results.csv --format csv
    ```

2. 参数说明：
    - `my-repo`: 要扫描的仓库名称
    - `--base_url`: JFrog 平台地址
    - `--username`: JFrog 用户名
    - `--password`: JFrog 密码
    - `--scan_result_save`: 保存扫描结果的文件，格式为CSV
    - `--format`: 结果格式，支持`table`、`json`和`csv`

### 日志记录

日志记录保存在`scan_details.file`（默认）文件中，可以根据需要使用 --scan_result_save 参数更改文件名。

## 项目结构

- `scanner.py`: 主脚本文件
- `Xray_pkg_support.json`: 文件类型的支持规则

## 贡献

欢迎贡献！请 fork 本仓库并提交 PR。

## 许可证


