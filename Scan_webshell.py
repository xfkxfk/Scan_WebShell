#coding:utf-8

#-----------------------------------------------
#   程序：scan_webshell.py
#   版本：v1.0
#   作者：vforbox
#   日期：2016-1-8
#   语言：Python 2.7
#   操作：运行 python scan_webshell.py 查看帮助
#   功能：查杀服务器里面的
#----------------------------------------------

import os
import sys
import re
import time

print u'''
\t\t◢████████████◣　　　　　　　 
\t\t　　　██████████████　　　　　　　 
\t\t　　　██　　　◥██◤　　　██　　　　　　　 
\t\t　◢███　　　　◥◤　　　　██◣　　　　　　 
\t\t　▊▎██◣　　　　　　　　◢█▊▊　　　　　　 
\t\t　▊▎██◤　　●　　●　　◥█▊▊　　　　　 
\t\t　▊　██　　　　　　　　　　█▊▊　　　　　　 
\t\t　◥▇██　▊　　　　　　▊　█▇◤　　　　　　 
\t\t　　　██　◥▆▄▄▄▄▆◤　█▊　　　◢▇▇◣ 
\t\t◢██◥◥▆▅▄▂▂▂▂▄▅▆███◣　▊◢　█ 
\t\t█╳　　　　　　　　　　　　　　　╳█　◥◤◢◤ 
\t\t◥█◣　　　˙　　　　　˙　　　◢█◤　　◢◤　 
\t\t　　▊　　　　　　　　　　　　　▊　　　　█　　 
\t\t　　▊　　　　　　　　　　　　　▊　　　◢◤　　 
\t\t　　▊　　　　　　⊕　　　　　　█▇▇▇◤　　 
\t\t　◢█▇▆▆▆▅▅▅▅▆▆▆▇█◣　　　　　　 
\t\t　▊　▂　▊　　　　　　▊　▂　
\t\t
\t\t┏━━━━━━━━━━━━━━┓
\t\t┃    Scan_webshell v1.0      ┃
\t\t┃    Author: vforbox         ┃
\t\t┗━━━━━━━━━━━━━━┛
'''

rulelist = [
    '(\$_(GET|POST|REQUEST)\[.{0,15}\]\s{0,10}\(\s{0,10}\$_(GET|POST|REQUEST)\[.{0,15}\]\))',
    '(base64_decode\([\'"][\w\+/=]{200,}[\'"]\))',
    '(eval(\s|\n)*\(base64_decode(\s|\n)*\((.|\n){1,200})',
    '((eval|assert)(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
    '(\$[\w_]{0,15}(\s|\n)*\((\s|\n)*\$_(POST|GET|REQUEST)\[.{0,15}\]\))',
    '(call_user_func\(.{0,15}\$_(GET|POST|REQUEST))',
    '(preg_replace(\s|\n)*\(.{1,100}[/@].{0,3}e.{1,6},.{0,10}\$_(GET|POST|REQUEST))',
    '(wscript\.shell)',
    '(cmd\.exe)',
    '(shell\.application)',
    '(documents\s+and\s+settings)',
    '(system32)',
    '(serv-u)',
    '(phpspy)',
    '(jspspy)',
    '(webshell)',
    '(Program\s+Files)'
]

def Filescan(path):
    print u'\n\t\t\t\t可疑文件'
    Count = 1
    Asterisk = "*"
    Horizontal = "-"
    print  Asterisk*70
    for root,dirs,files in os.walk(path):
        for filespath in files:
            if os.path.getsize(os.path.join(root,filespath))<10240000:
                file= open(os.path.join(root,filespath))
                filestr = file.read()
                file.close()
                for rule in rulelist:
                    result = re.compile(rule).findall(filestr)
                    if result:
                        print u'\n文件：'+os.path.join(root,filespath)
                        print u'恶意代码：'+str(result[0])[0:200]
                        print u'最后修改时间：'+time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(os.path.join(root,filespath))))
                        print u'提示：查杀完成',Count,u'个'
                        Count += 1
                        print Horizontal*70
                        break

def Get_Timefiles(_path,_time):
    _time = time.mktime(time.strptime(_time, '%Y-%m-%d %H:%M:%S'))
    print '\n'
    print u'\t\t\t\t可疑文件'
    xing = "*"
    print  xing*70
    print u'\n|\t文件路径\t|\t|\t最后修改时间\t|\n'
        
    for _root,_dirs,files in os.walk(_path):
        for file in files:
            if file.find('.')!=-1:
                _txt = file[(file.rindex('.')+1):].lower()
                    
                if _txt=='php' or _txt=='jsp': 
                    file_Time =os.path.getmtime(_root+'/'+file)
                    if file_Time>_time:
                        print "| "+_root+'/'+file+'  |\t|  '+ time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(os.path.getmtime(_root+'/'+file)))+'\t|'


if len(sys.argv)!=3 and len(sys.argv)!=2:
    print u'参数错误:'
    print u'\t1.按恶意代码查杀: '+"python "+sys.argv[0]+u' 目录名'
    print u'\t2.按修改时间查杀: '+"python "+sys.argv[0]+u' 目录名 修改时间(格式:"2016-01-08 10:00:00")'

try:

    if not os.path.exists(sys.argv[1])==True:
        print u'提示：指定的扫描目录不存在---->|^^|'

    print u'\n\n开始查杀：'+sys.argv[1] +u' 目录下的所有文件'
    if len(sys.argv)==2:
        Filescan(sys.argv[1])
    else:
        Get_Timefiles(sys.argv[1],sys.argv[2])
except:
    pass

