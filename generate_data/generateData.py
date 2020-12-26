'''
功能：
根据指定的良性和恶意软件数量，产生数据集

输入参数：
global文件中的
selected_benign_sample_number
selected_malicious_sample_number
data_path

输入文件:
feature_vectors_5removed
sha256_family_5removed.csv
familyCode.txt

输出文件：
在data_path/data_{selected_benign_sample_number}_{selected_malicious_sample_number}目录下生成
family          家族
feature         特征矩阵
allFeatureSet   所有特征的集合
label           标签
sample          样本名
'''

import os
#from sklearn import model_selection
import csv
import random
import sys

##############################################################################################

#输入参数
#sys.path.append('../')
from share import selected_benign_sample_number
from share import selected_malicious_sample_number
from share import data_path
# data_path = "E:\\AndroidMalwareDataset\\amd\\my"
# feature_selection_percentage = 100

# 输入文件
# all_apk_path = "E:\\AndroidMalwareDataset\\drebin\\feature_vectors"
all_apk_path = "G:\\AndroidDataset\\dataset2"
# malware_family_path = "E:\\AndroidMalwareDataset\\drebin\\sha256_family.csv"
# malware_family_path = "sha256_family.csv"
# family_code_path = os.path.join(data_path, "DrebinfamilyCode.txt")
# family_code_path = "DrebinfamilyCode.txt"

# 输出目录
data_file_path = "data_"+str(selected_benign_sample_number)+"_"+str(selected_malicious_sample_number)
file_temp = os.path.join(data_path, data_file_path)
if not os.path.exists(file_temp):
    os.makedirs(file_temp)  # 创建外层文件夹

# 输出文件
sub_sample_path = os.path.join(file_temp, "sample")
sub_feature_path = os.path.join(file_temp, "feature")
sub_label_path = os.path.join(file_temp, "label")
sub_family_path = os.path.join(file_temp, "family")
sub_allFeatureSet_path = os.path.join(file_temp, "allFeatureSet")

##############################################################################################

global attribute_total_number   # 属性的总个数
global attribute_number          # list
global attribute_name           # list
global selected_attribute_file  # 从文件中加载的选中的特征

##############################################################################################


def split_data2():
    all_apk_name = []  # list  包含所有apk名称的列表
    malware_list = []  # 包含所有恶意软件的列表
    benign_list = []  # 包含所有良性软件的列表
    tmp_all_apk_path = os.path.join(all_apk_path, "AMD")
    # res = os.listdir(tmp_all_apk_path)
    for line in os.listdir(tmp_all_apk_path):
        if not line.startswith("."):  # 去除隐藏文件
            line = line.strip().strip('\n')
            all_apk_name.append(line)
            malware_list.append(line)

    tmp_all_apk_path = os.path.join(all_apk_path, "Google")
    # res = os.listdir(tmp_all_apk_path)
    for line in os.listdir(tmp_all_apk_path):
        if not line.startswith("."):
            line = line.strip().strip('\n')
            all_apk_name.append(line)
            benign_list.append(line)


    print("数据集样本总数：", str(len(all_apk_name)))
    print("malicious_apk_number = ", str(len(malware_list)))
    print("benign_apk_number = ", str(len(benign_list)))

    # 列表中随机抽取数据
    # 设置seed()时，每次生成的随机数相同，不设置seed()时，则每次生成的随机数都不同
    # random.seed(10)
    benign_apk_sample = random.sample(benign_list, selected_benign_sample_number)
    malware_apk_sample = random.sample(malware_list, selected_malicious_sample_number)

    print("去重前：")
    print(len(benign_apk_sample))
    print(len(malware_apk_sample))

    #     print("去重后：")
    #     benign_apk_sample = list(set(benign_apk_sample))
    #     malware_apk_sample = list(set(malware_apk_sample))
    #     print(len(benign_apk_sample))
    #     print(len(malware_apk_sample))

    all_sample_apk_list = benign_apk_sample + malware_apk_sample  # 将两个列表进行合并，生成一个包含所有样本的列表
    random.shuffle(all_sample_apk_list)
    print("总样本个数：" + str(len(all_sample_apk_list)))

    with open(sub_sample_path, 'w+', encoding="utf-8") as f:
        for item in all_sample_apk_list:
            f.write(str(item) + '\n')

    with open(sub_label_path, 'w+') as f:
        for item in all_sample_apk_list:
            if item in benign_apk_sample:
                f.write('0\n')
            elif item in malware_apk_sample:
                f.write('1\n')


###########################################################################################
def split_data():
    all_apk_name = []         # list  包含所有apk名称的列表
    malware_list = []         # 包含所有恶意软件的列表
    benign_list = []          # 包含所有良性软件的列表
    res = os.listdir(all_apk_path)
    for line in res:
        line = line.strip().strip('\n')
        all_apk_name.append(line)
    print("数据集样本总数：", str(len(all_apk_name)))
    
    lines = csv.reader(open(malware_family_path, encoding='utf-8'))
    for line in lines:
        if line[0] != "sha256":
            apk = line[0].strip()
            malware_list.append(apk)
    
    print("malicious_apk_number = ", str(len(malware_list)))
    
    for item in all_apk_name:
        if item not in malware_list:
            benign_list.append(item)
    print("benign_apk_number = ", str(len(benign_list)))
    
    # 列表中随机抽取数据
    # 设置seed()时，每次生成的随机数相同，不设置seed()时，则每次生成的随机数都不同
    # random.seed(10)
    benign_apk_sample = random.sample(benign_list, selected_benign_sample_number)       
    malware_apk_sample = random.sample(malware_list, selected_malicious_sample_number)
    
    print("去重前：")
    print(len(benign_apk_sample))
    print(len(malware_apk_sample))
    
#     print("去重后：")
#     benign_apk_sample = list(set(benign_apk_sample))
#     malware_apk_sample = list(set(malware_apk_sample))
#     print(len(benign_apk_sample))
#     print(len(malware_apk_sample))
    
    all_sample_apk_list = benign_apk_sample + malware_apk_sample    # 将两个列表进行合并，生成一个包含所有样本的列表
    random.shuffle(all_sample_apk_list)
    print("总样本个数："+str(len(all_sample_apk_list)))
    
    with open(sub_sample_path, 'w+', encoding="utf-8") as f:
        for item in all_sample_apk_list:
            f.write(str(item) + '\n')
            
    with open(sub_label_path, 'w+') as f:
        for item in all_sample_apk_list:
            if item in benign_apk_sample:
                f.write('0\n')
            elif item in malware_apk_sample:
                f.write('1\n')

############################################################################################


# def family_prepare():
#     # input
#     global malware_family_path
#     '''
#         family_name_and_id              #dict  key为家族的名称  value为家族的id
#         malicious_apk_name_and_family   #dict  key为恶意apk名称  value为家族名称
#         malware_family_path             #sha256_family.csv的文件路径
#     '''
#     family_name_and_id = dict()
#     count = 0
#     with open(family_code_path, 'r') as f:
#         for family in f.readlines():
#             family = family.strip('\n')
#             family_name_and_id[family] = count
#             count += 1
#     # print(family_name_and_id)
#
#     lines = csv.reader(open(malware_family_path, encoding='utf-8'))
#     # 包含所有的恶意apk，包含所以的恶意家族
#     malicious_apk_name_and_family = dict()
#     for line in lines:
#         if line[0] != "sha256":
#             apk = line[0]
#             family = line[1]
#             malicious_apk_name_and_family[apk] = family
#     # print(malicious_apk_name_and_family)
#
#     apk_sample = []
#     with open(sub_sample_path,'r') as f:
#         for item in f.readlines():
#             item = item.strip()
#             apk_sample.append(item)
#
#
#     # 给样本集设置family标签
#     with open(sub_family_path,'w+') as f:
#         for item in apk_sample:
#             if item in malicious_apk_name_and_family.keys():
#                 f.write(str(family_name_and_id[malicious_apk_name_and_family[item]])+'\n')
#             else:
#                 f.write(str(0)+'\n')
                
###############################################################################################


def analyze_attribute():
    # output
    global attribute_total_number   # 属性的总个数
    global attribute_number         # list
    global attribute_name           # list
    
    # input
    global all_apk_path            
    global malware_family_path

    all_apk_name = []  # 所有样本
    with open(sub_sample_path, 'r', encoding="utf-8") as f:
        for item in f.readlines():
            item = item.strip().strip('\n')
            all_apk_name.append(item)
    apk_number = len(all_apk_name)
    print("apk_number = " + str(apk_number))    

    # # malicious_apk
    # all_malicious_apk_name = []
    # lines = csv.reader(open(malware_family_path, encoding='utf-8'))
    # for line in lines:
    #     if line[0] != "sha256":
    #         all_malicious_apk_name.append(line[0])
    # # 样本集中的malware_apk
    # malware_apk_name = []
    # for item in all_apk_name:
    #     if item in all_malicious_apk_name:
    #         malware_apk_name.append(item)
    #
    # print("malicious_apk_number = ", str(len(malware_apk_name)))
    # print("benign_apk_number = ", str((apk_number - len(malware_apk_name))))
    
    apk_count = 0           # apk编号
    attribute_count = 0     # 属性编号
    apk_name_and_id = {}    # 字典  key为apk的name， value为对应的id
    
    attribute_name_and_id = {}   # 字典    key为属性，value 为其对应的id
    # 下面这两个其实应该弄成map的
    attribute_name = []        # 属性id
    attribute_number = []    # id所对应的属性的数量
    
    attribute_category_number = {
        'feature': 0,
        'call': 0,
        'intent': 0,
        'permission': 0,
        'api_call': 0,
        'real_permission': 0,
        'provider': 0,
        'service_receiver': 0,
        'activity': 0,
        'url': 0      # 10类，待修改
    }    
    
    for apk in all_apk_name:
        apk_name_and_id[apk] = apk_count
        apk_count += 1
        path = os.path.join(all_apk_path, "MixAll")
        path = os.path.join(path, apk)  # 每一个apk的路径
        # 对所有apk的attribute进行统计，统计所有出现过的attribute以及对应出现过多少次
        with open(path, 'r', encoding="utf-8") as f:
            for line in f.readlines():
                attribute = line.strip()
                if attribute in attribute_name_and_id:
                    attribute_number[attribute_name_and_id[attribute]] += 1
                else:
                    attribute_name_and_id[attribute] = attribute_count
                    attribute_name.append(attribute)
                    attribute_number.append(1)
                    attribute_count += 1
                    
                    # 从attribute中提取category
                    # categorys = line.strip().split("::")
                    # category = categorys[0]
                    # if category in attribute_category_number:
                    #     attribute_category_number[category] += 1
                    # else:
                    #     # attribute_category_number[category] = 1
                    #     print("warning,warning...add new category:", category)
                    
        # print(file)
    attribute_total_number = attribute_count
    print("###################################################################################")
    print('attribute_total_number = ' + str(attribute_total_number))

    # 统计attribute_number，得到出现次数等于1/2/3/4/5的属性，并计算数量和百分比
    # print("###################################################################################")
    # print('attribute_number:')
    # print('attribute_count_1_number:', attribute_number.count(1))
    # print('attribute_count_2_number:', attribute_number.count(2))
    # print('attribute_count_3_number:', attribute_number.count(3))
    # print('attribute_count_4_number:', attribute_number.count(4))
    # print('attribute_count_5_number:', attribute_number.count(5))
    #
    # print("属性出现最多的次数：" + str(max(attribute_number)))
    # print("属性最多的所占的比例：" + str(max(attribute_number)/attribute_count))

#     d= collections.Counter(attribute_number)
#     d1 = sorted(d.items(),key=lambda item:item[1], reverse=True)  #按key逆序排列
#     print(d1)
#     print("属性只出现1次所占的比例为：" + str(d1[0][1]/attribute_count))
#     print("属性只出现2次所占的比例为：" + str(d1[1][1]/attribute_count))
#     d2 = sorted(d.items(),key=lambda item:item[0], reverse=True)  #按value排序
#     print(d2)
    # 统计不同类别属性的数量attribute_category_number
    # print("###################################################################################")
    # print("attribute_category_number:")
    # 这里并没有把增加的attribute统计进去
    # for i in attribute_category_number:
    #     print("%s:%s"%(i,attribute_category_number[i]))


###################################################################################

def select_attribute():
    print("###################################################################################")

    # input
    global attribute_total_number
    global attribute_name
    global attribute_number
    
    '''
        selected_attribute_number   挑选的特征的数量
    '''
    
    selected_attribute = []     # 选中的属性id值
    
    # 遍历所有属性，淘汰掉一部分
    for i in range(0, attribute_total_number):      
        # 去掉四大组件以及url
        if attribute_name[i].strip().split("::")[0] in ['url', 'activity', 'service_receiver', 'provider', '']:
            continue
        selected_attribute.append(i)
    
    selected_attribute_number = len(selected_attribute)
    print('selected_attribute count: ', selected_attribute_number)
#     print('selected_attribute:')
#     print(selected_attribute)

    # 将属性输出到文件
    with open(sub_allFeatureSet_path, 'w+', encoding="utf-8") as f:
        for i in selected_attribute:
            f.write(str(attribute_name[i])+"\n")
            
#####################################################################################################


def selectedFeature_prepare():
    # output
    global selected_attribute_file   # 挑选的特征总数
    
    selected_attribute_file = []     # list
    with open(sub_allFeatureSet_path, 'r', encoding="utf-8") as f:
        for line in f.readlines():
            feature = line.strip()
            selected_attribute_file.append(feature)  

#####################################################################################################


def gen_matrix(apk_path, feature_path):
    # input
    global selected_attribute_file

    row_number = len(open(apk_path, 'r').readlines())

    file_feature = open(feature_path, 'w+')
    
    selected_attribute_number = len(selected_attribute_file)
    print("selected_attribute_file count:"+str(selected_attribute_number))
    count = 0
    with open(apk_path, 'r') as f:
        for line in f.readlines():  
            apk = line.strip()
            selected_attribute_number = len(selected_attribute_file)
            path = os.path.join(all_apk_path, "MixAll")
            path = os.path.join(path, apk)
            row = [0] * selected_attribute_number
            with open(path, 'r', encoding="utf-8") as ff:
                for feature in ff.readlines():
                    feature = feature.strip()
                    if feature in selected_attribute_file:
                        # 这里是在挑选出来的特征中的编号
                        col = selected_attribute_file.index(feature)
                        row[col] = 1
                        
            row_str = str(row[0])
            for i in range(1, selected_attribute_number):
                row_str = row_str + ' ' + str(row[i])
            file_feature.write(row_str + '\n')
            
            count += 1
            if count % 100 == 0:
                print(str(count) + '/' + str(row_number) + ' ')

    file_feature.close()


def create_matrix():
    
    gen_matrix(sub_sample_path, sub_feature_path)


def main():
    split_data2()        # 产生数据集
    # family_prepare()    # 生成家族编号的标签
    analyze_attribute()  # 分析特征
    select_attribute()  # 选择特征
    selectedFeature_prepare()  # 从文件中读取特征
    create_matrix()     # 生成矩阵


if __name__ == '__main__':
    main()
