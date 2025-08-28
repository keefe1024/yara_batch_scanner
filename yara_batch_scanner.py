import argparse
import subprocess
import os
import csv
from concurrent.futures import ThreadPoolExecutor
import time

def scan_with_yara(yara_exe, yara_rule, target_file):
    """使用 yara64.exe 扫描单个规则文件"""
    try:
        cmd = [yara_exe, yara_rule, target_file]
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        matched = bool(result.stdout.strip())
        return {
            'yara_rule': os.path.basename(yara_rule),
            'target_file': target_file,
            'result': result.stdout.strip(),
            'error': result.stderr.strip(),
            'status': matched
        }
    except subprocess.CalledProcessError as e:
        return {
            'yara_rule': os.path.basename(yara_rule),
            'target_file': target_file,
            'result': e.stdout.strip(),
            'error': e.stderr.strip(),
            'status': False
        }
    except Exception as e:
        return {
            'yara_rule': os.path.basename(yara_rule),
            'target_file': target_file,
            'result': '',
            'error': str(e),
            'status': False
        }

def process_rule(args, yara_rule):
    return scan_with_yara(args.yara_exe, yara_rule, args.target_exe)

def main():
    parser = argparse.ArgumentParser(description='使用 yara64.exe 批量扫描 yara 规则')
    parser.add_argument('-a', '--target-exe', required=True, help='要扫描的目标可执行文件')
    parser.add_argument('-f', '--rules-dir', required=True, help='包含 yara 规则文件的文件夹')
    parser.add_argument('-t', '--threads', type=int, default=4, help='线程数量 (默认: 4)')
    parser.add_argument('--yara-exe', default='yara64.exe', help='yara 可执行文件路径')

    args = parser.parse_args()

    if not os.path.isfile(args.target_exe):
        print(f"错误: 目标文件 '{args.target_exe}' 不存在")
        return

    if not os.path.isfile(args.yara_exe):
        print(f"错误: yara 可执行文件 '{args.yara_exe}' 不存在")
        return

    if not os.path.isdir(args.rules_dir):
        print(f"错误: 规则目录 '{args.rules_dir}' 不存在")
        return

    yara_rules = []
    for root, _, files in os.walk(args.rules_dir):
        for file in files:
            if file.lower().endswith(('.yara', '.yar')):
                yara_rules.append(os.path.join(root, file))

    if not yara_rules:
        print(f"警告: 未找到任何 .yara 或 .yar 文件")
        return

    results = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_rule = {executor.submit(process_rule, args, rule): rule for rule in yara_rules}
        
        try:
            for future in future_to_rule:
                rule = future_to_rule[future]
                try:
                    result = future.result()
                    results.append(result)
                    status = "匹配" if result['status'] else "无匹配"
                    print(f"完成: {result['yara_rule']} - {status}")
                except Exception as e:
                    print(f"处理 '{rule}' 时出错: {str(e)}")
                    results.append({
                        'yara_rule': os.path.basename(rule),
                        'target_file': args.target_exe,
                        'result': '',
                        'error': str(e),
                        'status': False
                    })
        except KeyboardInterrupt:
            print("\n用户中断, 停止扫描...")
            executor.shutdown(wait=False)
            return

    csv_file = 'result.csv'
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['yara_rule', 'target_file', 'status', 'result', 'error'])
            writer.writeheader()
            writer.writerows(results)
        print(f"结果已保存到 {csv_file}")
    except Exception as e:
        print(f"写入 CSV 文件时出错: {str(e)}")

if __name__ == '__main__':
    main()
