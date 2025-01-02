import vul_scan as vulscan
import argparse
import datetime
from concurrent.futures import ThreadPoolExecutor
import time

def main(host, down, proxy):
    # 漏洞探测
    return vulscan.vul_scan(host, down, proxy)
     
if __name__ == "__main__":
    start_time = datetime.datetime.now()
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="目标 URL , example: http://192.168.1.1:8848")
    parser.add_argument("-f", "--file", help="批量扫描文件，example：1.txt")
    parser.add_argument("-d", "--down", help="是否下载所有配置文件,直接-d 即为true", action='store_true')
    parser.add_argument("-p", "--proxy", help="设置代理, example： http://127.0.0.1:8080", required=False)
    args = parser.parse_args()

    if args.url:
        results = main(args.url, args.down, args.proxy)
        for result in results:
            print(result)
        end_time = datetime.datetime.now()    

    elif args.file:
        filename = args.file
        target = []
        with open(filename, "r") as file:
            for url in file.readlines():
                target.append(url.strip())
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(main, url, args.down, args.proxy) for url in target]
            for future in futures:
                for results in future.result():
                    print(results)
                print("")
                # 防止输出乱
                time.sleep(0.1)
        end_time = datetime.datetime.now()
    else:
        print("[错误] 请输入目标 URL 或者 file.")
        end_time = datetime.datetime.now()
    duration = end_time - start_time
    minutes, seconds = divmod(duration.seconds, 60)
    print(f"程序运行时间：{minutes} 分钟, {seconds} 秒")

