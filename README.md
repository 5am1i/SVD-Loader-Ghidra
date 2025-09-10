# SVD-Loader for Ghidra Extensions

[来源](https://github.com/leveldown-security/SVD-Loader-Ghidra)

由于原作者已经很久没有更新，且原来的博客也关闭了，这里简单更新一下。

## 更新内容

本版本对原始SVD-Loader进行了以下更新：

### 功能增强
- **智能清理功能**：在加载新SVD文件时自动清理原有的memory map
- **多重清理策略**：使用多种方法确保彻底清理冲突数据
- **详细错误处理**：提供清晰的错误信息和操作反馈
- **内存验证**：检查地址范围有效性，避免无效操作
- **创建前清理**：在创建数据结构前进行针对性清理

## 安装

### 方法一：直接安装（推荐）
1. 在Ghidra的项目管理界面
2. File → Install Extensions
3. 选择对应工程项目目录
4. 重启Ghidra
5. 在Script Manager中找到并运行`SVD-Loader.py`
6. 选择对应的SVD文件

![importfile](./image/importfile.png)
![script](./image/script.png)

## 项目结构

```
SVD-Loader-Ghidra/
├── SVD-Loader.py          # 主脚本文件，Ghidra插件
├── cmsis_svd/             # CMSIS-SVD解析库
│   ├── __init__.py
│   ├── model.py           # 数据模型定义
│   └── parser.py          # SVD文件解析器
├── SVD/                   # SVD配置文件目录
│   ├── Cores/             # ARM Cortex核心定义
│   │   ├── Cortex-M0.svd
│   │   ├── Cortex-M33.svd
│   │   └── ...
│   └── STM32/             # STM32系列定义
│       ├── STM32F0x0.svd
│       ├── STM32F103.svd
│       └── ...
└──README.md              # 项目说明文档
```

### 核心文件说明

- **SVD-Loader.py**: 主要的Ghidra插件脚本，包含所有功能逻辑
- **cmsis_svd/**: 从[posborne/cmsis-svd](https://github.com/posborne/cmsis-svd)移植的Python库，用于解析SVD文件
- **SVD/**: 存放各种微控制器的SVD定义文件

## 支持的SVD文件

### 获取SVD文件

- [cmsis-svd contains over 650 SVDs](https://github.com/posborne/cmsis-svd/)
- [Keil Software Packs](https://www.keil.com/pack)


## 贡献
测试环境，这里只在MAC环境下进行过测试，其他环境暂没有进行测试过；
欢迎提交Issue和Pull Request来改进这个项目！

## Credits

- 原始项目: [leveldown-security/SVD-Loader-Ghidra](https://github.com/leveldown-security/SVD-Loader-Ghidra)
- cmsis-svd库: [posborne/cmsis-svd](https://github.com/posborne/cmsis-svd/)
- 本版本更新: 修复了多个关键错误并增强了功能

## Licensing

- `cmsis_svd/`目录下的代码遵循Apache License v2.0
- SVD-Loader主脚本遵循GPLv3许可证
- 详见[LICENSE](LICENSE)文件
