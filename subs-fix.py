# 由于在线订阅转换链接转换的节点有时候用了 YAML 行内简写结构 {}，其中嵌套的 ws-opts 再次使用 {}，造成了 YAML 无法准确解析结构层次的问题
# YAML 对 {} 的嵌套解析非常敏感，嵌套中 headers 没有适当引号包裹的值（如 Host），path: 字段值中含有 /@xxx 这类特殊字符没加引号
# 需要用 Python 或 YAML 专用工具转换将每个行内简写结构 {} 展开为 YAML 格式，就可以被正常解析了
#command -v python
#python -m pip install ruamel.yaml
from ruamel.yaml import YAML
from ruamel.yaml.scalarstring import DoubleQuotedScalarString
import sys

yaml = YAML()
yaml.preserve_quotes = True

def quote_all_scalars(obj):
    """递归地为所有字符串值加双引号"""
    if isinstance(obj, dict):
        return {k: quote_all_scalars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [quote_all_scalars(i) for i in obj]
    elif isinstance(obj, str):
        return DoubleQuotedScalarString(obj)
    else:
        return obj

input_path = sys.argv[1]
output_path = sys.argv[2]

with open(input_path, 'r', encoding='utf-8') as f:
    data = yaml.load(f)

# 遍历 proxy 节点
if isinstance(data, dict):
    for section in ['proxies', 'proxy-providers']:
        if section in data and isinstance(data[section], list):
            data[section] = [quote_all_scalars(proxy) for proxy in data[section]]

with open(output_path, 'w', encoding='utf-8') as f:
    yaml.dump(data, f)

print(f"✅ 修复完成：{output_path}")
