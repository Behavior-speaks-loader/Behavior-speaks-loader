# -*- coding: utf-8 -*-

import time
import random
import asyncio
from bs4 import BeautifulSoup
from pyppeteer.launcher import launch

def screen_size():
    """使用tkinter获取屏幕大小"""
    import tkinter
    tk = tkinter.Tk()
    width = tk.winfo_screenwidth()
    height = tk.winfo_screenheight()
    tk.quit()
    return width, height

async def get_data(sha256_code, target_path):
    browser = await launch(
        {'headless': False, 'args': ['--no-sandbox'], },
        userDataDir='./userdata',
        args=['--window-size=1366,768']
    )  # open chrome
    page = await browser.newPage()
    width, height = screen_size()
    await page.setViewport(viewport={"width": width, "height": height})
    await page.setUserAgent(
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299'
    )
    page1 = await browser.newPage()
    url1 = f'https://www.virustotal.com/ui/file_behaviours/{sha256_code}_Tencent HABO/html'
    await page1.goto(url1,timeout=10000000)
    content = await page1.content()
    # path_write_txt='D:/here/work/2021-knowledge-graph/DB_txt/'+code+'.txt'
    path_write_txt = target_path + sha256_code + '.txt'
    bs = BeautifulSoup(content, "lxml")

    news_contents = bs.find_all('div',class_="enum-container")
    file = open(path_write_txt, 'w', encoding="utf-8")
    for i in news_contents:
         file.write(i.get_text())
    await browser.close()
    print(f'{sha256_code} success')
    return path_write_txt

def collect_behaviors(file_path):

    txt_file = open(file_path, 'r', encoding='utf-8')
    # csv_file = open(base_path + 'behavior_result.csv', 'a')

    file_sh256 = file_path.split('\\')[-1].split('.')[0]
    # csv_file.write(file_sh256)
    # csv_file.write(',')
    flag = False
    behaviour_list = []
    for line in txt_file.readlines():
        if flag:
            if line.strip() not in behaviour_list:
                behaviour_list.append(line.strip())
                # csv_file.write(line.strip())
                # csv_file.write(',')
            flag = False
        if line.strip() == 'Behaviour:':
            flag = True
    # csv_file.write('\n')
    # csv_file.close()
    return behaviour_list

if __name__ == '__main__':
    sha_file = open('D:\\lab_related\\malware_spider\\sha_result.txt', 'r')
    error_file = open('D:\\lab_related\\malware_spider\\error_sha256.txt', 'w')
    for index, line in enumerate(sha_file.readlines()):
        sha256_code = line.strip()
        print(f'test {index+1}:{sha256_code}')
        try:
            print(f'{sha256_code} success')
            asyncio.get_event_loop().run_until_complete(get_data(sha256_code))
        except:
            print(f'{sha256_code} error')
            error_file.write(sha256_code)
            error_file.write('\n')
        print('\n')

