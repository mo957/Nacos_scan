import os
import zipfile
import keywords
import re

class OutToMd:
    # 吐出一份文件清单
    # 文件内容 + 敏感信息标红
    def __init__(self, filename):
        self.filename = filename
    
    def write_file_content(self):
        file_size = os.path.getsize(self.filename)
        # 22 为空文件
        if file_size > 22:
            prefix_name = str(self.filename).replace('.zip', '').replace("./config_zip/", "")
            output_filename = f"./file_list_md/{prefix_name}.md"
            with open(output_filename, 'w', encoding='utf-8') as file:
                with zipfile.ZipFile(self.filename, 'r') as zip_ref:
                    for config_file_name in zip_ref.namelist():
                        if config_file_name.endswith('/') or config_file_name.endswith('\\'):
                            continue
                        with zip_ref.open(config_file_name) as c_file:
                            content = c_file.read().decode('gbk')
                            #content = re.sub(r'\n', ' ', content)
                            # 删除空行
                            lines = content.splitlines()
                            non_empty_lines = [line for line in lines if line.strip()]
                            cleaned_text = "\n".join(non_empty_lines)
                            for keyword in keywords.basic_keywords:
                                cleaned_text = cleaned_text.replace(keyword, f'🔴{keyword}')

                        file.write(f"### {config_file_name.replace(prefix_name + '/', '')}\n")
                        file.write("```java{.line-numbers}\n" + cleaned_text + "\n```\n")

# 使用示例
if __name__ == '__main__':
    filename = "192_168_17_154_8848(2024-01-11).zip"
    out = OutToMd(filename).write_file_content()