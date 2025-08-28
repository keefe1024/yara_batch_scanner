# Python3 脚本：使用 yara64.exe 批量扫描 yara 规则

一个批量扫描yara规则的脚本工具，通过多线程调用 yara64.exe 扫描指定可执行文件，并处理文件夹中的所有 yara 规则文件，最后将结果保存到 result.csv 文件中。

## 使用说明

1. 将脚本保存为 `yara_batch_scanner.py`
2. 确保 `yara64.exe` 与脚本在同一目录，或者通过 `--yara-exe` 参数指定路径
3. 运行示例：

```bash
python3 yara_batch_scanner.py -a target.exe -f yara_rules_folder -t 8
```

参数说明：
- `-a/--target-exe`: 要扫描的目标可执行文件
- `-f/--rules-dir`: 包含 yara 规则文件的文件夹
- `-t/--threads`: 线程数量（默认为4）
- `--yara-exe`: yara64.exe 的路径（默认为当前目录的 yara64.exe）

## 输出结果

结果将保存在 `result.csv` 文件中，包含以下列：
- yara_rule: 使用的 yara 规则文件名
- target_file: 扫描的目标文件
- result: yara 的输出结果（匹配信息）
- error: 错误信息（如果有）

## 特性

1. 多线程支持，提高扫描效率
2. 递归扫描指定文件夹中的所有 .yara 和 .yar 文件
3. 错误处理和结果收集
4. 显示进度和统计信息
5. 支持用户中断（Ctrl+C）
