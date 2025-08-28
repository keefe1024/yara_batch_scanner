import argparse
import subprocess
import os
import csv
from concurrent.futures import ThreadPoolExecutor
import time

def scan_with_yara(yara_exe, yara_rule, target_file):
    """使用 yara64.exe 扫描单个规则文件"""
    try:
        # 构建命令
        cmd = [yara_exe, yara_rule, target_file]
        # 执行命令并捕获输出
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {
            'yara_rule': os.path.basename(yara_rule),
            'target_file': target_file,
            'result': result.stdout.strip(),
            'error': result.stderr.strip()
        }
    except subprocess.CalledProcessError as e:
        return {
            'yara_rule': os.path.basename(yara_rule),
            'target_file': target_file,
            'result': e.stdout.strip(),
            'error': e.stderr.strip()
        }
    except Exception as e:
        return {
            'yara_rule': os.path.basename(yara_rule),
            'target_file': target_file,
            'result': '',
            'error': str(e)
        }

def process_rule(args, yara_rule):
    """处理单个 yara 规则文件的扫描任务"""
    return scan_with_yara(args.yara_exe, yara_rule, args.target_exe)

def main():
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='使用 yara64.exe 批量扫描 yara 规则')
    parser.add_argument('-a', '--target-exe', required=True, help='要扫描的目标可执行文件 (xxx.exe)')
    parser.add_argument('-f', '--rules-dir', required=True, help='包含 yara 规则文件的文件夹')
    parser.add_argument('-t', '--threads', type=int, default=4, help='线程数量 (默认: 4)')
    parser.add_argument('--yara-exe', default='yara64.exe', help='yara64.exe 的路径 (默认为当前目录的 yara64.exe)')
    args = parser.parse_args()

    # 验证目标文件是否存在
    if not os.path.isfile(args.target_exe):
        print(f"错误: 目标文件 '{args.target_exe}' 不存在")
        return

    # 验证 yara64.exe 是否存在
    if not os.path.isfile(args.yara_exe):
        print(f"错误: yara 可执行文件 '{args.yara_exe}' 不存在")
        return

    # 验证规则目录是否存在
    if not os.path.isdir(args.rules_dir):
        print(f"错误: 规则目录 '{args.rules_dir}' 不存在")
        return

    # 收集所有的 yara 规则文件 (.yara 或 .yar)
    yara_rules = []
    for root, _, files in os.walk(args.rules_dir):
        for file in files:
            if file.lower().endswith(('.yara', '.yar')):
                yara_rules.append(os.path.join(root, file))

    if not yara_rules:
        print(f"警告: 在目录 '{args.rules_dir}' 中未找到任何 .yara 或 .yar 文件")
        return

    print(f"开始扫描 {len(yara_rules)} 个 yara 规则, 使用 {args.threads} 线程...")

    # 用于存储结果的列表
    results = []
    start_time = time.time()

    # 使用线程池并发执行扫描任务
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_rule = {executor.submit(process_rule, args, rule): rule for rule in yara_rules}
        
        try:
            for future in future_to_rule:
                rule = future_to_rule[future]
                try:
                    result = future.result()
                    results.append(result)
                    print(f"完成: {result['yara_rule']} - {'匹配' if result['result'] else '无匹配'}")
                except Exception as e:
                    print(f"处理 '{rule}' 时出错: {str(e)}")
                    results.append({
                        'yara_rule': os.path.basename(rule),
                        'target_file': args.target_exe,
                        'result': '',
                        'error': str(e)
                    })
        except KeyboardInterrupt:
            print("\n用户中断, 停止扫描...")
            executor.shutdown(wait=False)
            return

    # 计算耗时
    elapsed_time = time.time() - start_time
    print(f"扫描完成! 共处理 {len(results)} 个规则, 耗时 {elapsed_time:.2f} 秒")

    # 将结果写入 CSV 文件
    csv_file = 'result.csv'
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['yara_rule', 'target_file', 'result', 'error'])
            writer.writeheader()
            writer.writerows(results)
        print(f"结果已保存到 {csv_file}")
    except Exception as e:
        print(f"写入 CSV 文件时出错: {str(e)}")

if __name__ == '__main__':
    main()
