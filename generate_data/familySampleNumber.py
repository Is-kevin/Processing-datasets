'''
程序功能：统计每个子数据集中各个恶意软件家族的个数，并在相应的子数据集目录下生成csv文件

输入参数：
share文件中的
selected_benign_sample_number
selected_malicious_sample_number
data_path

输入文件：
familyCode.txt
sha256_family.csv
data_path/data_{selected_benign_sample_number}_{selected_malicious_sample_number}目录下的
sample
family

输出文件：
family_count.csv
    
'''
import csv
import os

global malicious_apk_name_and_family #dict 

#输入参数
from share import selected_benign_sample_number
from share import selected_malicious_sample_number
from share import data_path

selectedBenign = selected_benign_sample_number
selectedMalware = selected_malicious_sample_number

#输入文件
sample = "data_"+str(selectedBenign)+"_"+str(selectedMalware)+"\\sample"
family = "data_"+str(selectedBenign)+"_"+str(selectedMalware)+"\\family"
# family_code_path = os.path.join(data_path,'AMDfamilyCode.txt')
# malware_family_path = os.path.join(data_path,'AMDFamily.csv')
family_code_path = os.path.join(data_path,'DrebinfamilyCode.txt')
malware_family_path = os.path.join(data_path,'sha256_family.csv')
#输出文件
family_number = "data_"+str(selectedBenign)+"_"+str(selectedMalware)+"\\family_count.csv"

sample_path = os.path.join(data_path,sample)
family_path = os.path.join(data_path,family)
family_number_path = os.path.join(data_path,family_number)

def count_family():
    every_family_count = {} #key为家族名称，value为家族对应的apk的数目
    #统计各个家族的样本的数量及其所占的比例
    with open(family_path,'r') as f:
        for line in f.readlines():
            id = line.strip()
            if id in every_family_count.keys():
                every_family_count[id] += 1
            else:
                every_family_count[id] = 1
   
    sorted_dict= sorted(every_family_count.items(), key=lambda d:d[1], reverse = True)
    
    #family_code
    family_name = []
    with open(family_code_path, 'r') as f:
        for line in f.readlines():
            name = line.strip()
            family_name.append(name) 
            
    family_p = dict()  #各个家族所占的比例
    tmp_family_number = dict()
    all_number = selectedBenign + selectedMalware
    for i in range(len(family_name)):
        if str(i) in dict(sorted_dict).keys():
            #family_p[family_name[i]] = round((dict(sorted_dict)[str(i)]/all_number),3)
            family_p[family_name[i]] = round((dict(sorted_dict)[str(i)]/selectedMalware),3)
            tmp_family_number[family_name[i]] = dict(sorted_dict)[str(i)]
            
    sum = 0
    for k,v in family_p.items():
        sum+=v
    print("概率总和："+str(sum))
    print(family_p)
    print(sorted_dict)
    print(tmp_family_number)
    with open(family_number_path,'w+',newline='') as f: 
        csv_writer = csv.writer(f)
        file_header = ['恶意家族','样本数量','样本比例']
        csv_writer.writerow(file_header)
        for k,v in family_p.items():
            line = []
            line.append(k)
            line.append(tmp_family_number[k])
            line.append(v)
            csv_writer.writerow(line)   

if __name__ == '__main__':
    count_family()
