'''
功能：
统计各个家族的软件数量
按从多到少排列
相当于给家族进行编号

输入参数：
global文件中的data_path

输入文件：
feature_vectors_5removed
sha256_family_5removed.csv

输出文件：
在data_path目录下生成
familyCode.txt
familyNumber.txt
'''

import csv
import os
import sys

#########################################################################################

#输入参数
sys.path.append('../')
from share import data_path

#输入文件
all_apk_path = "E:\\AndroidMalwareDataset\\drebin\\feature_vectors"                    #其中去掉了五个无法反编译的 共有129008个软件
malware_family_path = "E:\\AndroidMalwareDataset\\drebin\\sha256_family.csv"

#输出文件
family_code_path = os.path.join(data_path, "familyCode.txt")
family_number_path = os.path.join(data_path, "familyNumber.txt")

########################################################################################

def family_count():
    apk_families = []           #list  包含所有家族名称的列表
    every_family_count ={}      #dict  key是恶意家族的名称   value是家族中恶意软件的数量 
    all_apk_name = os.listdir(all_apk_path)   
    # with open("needDeleteAPK.txt",'r',encoding="utf-8") as f:
    #     for item in f.readlines():
    #         item = item.strip()
    #         if item in all_apk_name:
    #             all_apk_name.remove(item)
    
    apk_number = len(all_apk_name)
    print("apk_number = " + str(apk_number))
    
#     # malicious_apk
    count = 0          #恶意软件的总数
    lines = csv.reader(open(malware_family_path, encoding='utf-8'))
    for line in lines:
        if line[0] != "sha256":
            count += 1
    print("malicious_apk_number = ", str(count))
    print("benign_apk_number = ",str((apk_number - count)))
    apk_families.append("Benign")
    every_family_count["Benign"] = apk_number - count
     
    lines = csv.reader(open(malware_family_path, encoding='utf-8'))
    for line in lines:
        if line[0] != "sha256":
            apk_belong_family = line[1].strip()
            if apk_belong_family not in apk_families:
                apk_families.append(apk_belong_family)
                every_family_count[apk_belong_family] = 1
            else:
                every_family_count[apk_belong_family] +=1
                 
    toatal_kinds_families = len(apk_families)     #180
    print("toatal_kinds_families:" + str(toatal_kinds_families))
    #遍历每个apk家族的数量
#     for item in apk_families:
#         print(str(every_family_count[item]))
#     print(len(every_family_count))
 
    sorted_dict= sorted(every_family_count.items(), key=lambda d:d[1], reverse = True)   #按值的大小对字典进行排序
    
    print(sorted_dict) 
    ff = open(family_code_path,"w+",encoding="utf-8")   #文件中以空格为分割符
    with open(family_number_path,'w+',encoding="utf-8") as f:
        for item in sorted_dict:
            item = list(item)
            f.write(str(item[0])+' '+str(item[1])+"\n")
            ff.write(str(item[0]+'\n'))
    ff.close()     
     
if __name__ == "__main__":
    family_count()      
