'''
#检查特征是否重复
程序功能：得到软件的所有的API
输入参数：
global文件中的data_path

#输入文件


#输出文件

'''
import os
import sys
import re
import csv
from androguard.misc import AnalyzeAPK
from androguard.core.api_specific_resources import load_permission_mappings

#输入参数
dataSet_path = r"I:\AndroidMalwareDataset\dataset\apk"
featureSet_path = r'I:\AndroidMalwareDataset\dataset\feature'
prepare_folder = r'I:\AndroidMalwareDataset\dataset\prepare'

#不能编译的APK
exception_apk_file = os.path.join(prepare_folder,"exception_apk.txt")
sensitive_API_path = os.path.join(prepare_folder,"sensitiveAPI.txt")
sensitive_command_path = os.path.join(prepare_folder,"sensitive_command.txt")
formal_command_path = os.path.join(prepare_folder,"formal_command.txt")

def get_androguard_obj(path):
    ao = None
    try:
        ao = AnalyzeAPK(path)
    except:
        with open(exception_apk_file,'a+') as f:
            f.write(path+'\n')
        ao = None
    return ao
 
def read_file():
    offical_formal_Command = load_formal_Command()
    offical_API_permission = load_permission_API()
    offical_Suspicious_API = load_Suspicious_API()
    offical_Shell_Command = load_Shell_Command()
    return offical_formal_Command,offical_API_permission,offical_Suspicious_API,offical_Shell_Command

def load_permission_API():
    mapping = load_permission_mappings(25)      # 25 is the API level
    offical_API_permission = {}       #官方api和权限的映射
    for k,v in mapping.items():
        api_split = k.split(';-')
        api_pre = api_split[0]
        api_back = api_split[1].split('-(')[0]
        api = api_pre + ":" + api_back
        permission = v
        offical_API_permission[api] = permission
    return offical_API_permission

def load_Suspicious_API():   #提取可疑的API
    offical_Suspicious_API = []
    with open(sensitive_API_path,'r',encoding='utf-8') as f:
        for line in f.readlines():
            line = line.strip()
            offical_Suspicious_API.append(line)
    return offical_Suspicious_API

def load_Shell_Command():   #提取可疑的API
    offical_Shell_Command = []
    with open(sensitive_command_path,'r') as f:
        for line in f.readlines():
            line = line.strip()
            offical_Shell_Command.append(line)
    return offical_Shell_Command

def load_formal_Command():   #提取可疑的API
    offical_formal_Command = []
    with open(formal_command_path,'r') as f:
        for line in f.readlines():
            line = line.strip()
            offical_formal_Command.append(line)
    return offical_formal_Command

def extract_api(ao,offical_API_permission,offical_Suspicious_API):
    a,d,dx = ao
    all_methods = []
    #为了尽量多的提取API，采用以下两种方法
    #Round One
    for current_class in d[0].get_classes():
        for method in current_class.get_methods():
            method_name = method.get_class_name()
            new_method_name = method_name.replace(';','').replace('[','').replace(']','')
            tmp_method = new_method_name +":" + method.get_name()
            if tmp_method not in all_methods:
                all_methods.append(tmp_method)
                
#     #Round Two
#     for method in dx.get_methods():
#         method_class = method.get_method()
#         class_name = method_class.get_class_name()
#         new_class_name = class_name.replace(';','').replace('[','').replace(']','')
#         method_name = method_class.get_name()
#         tmp_method = new_class_name + ":" + method_name
#         if tmp_method not in all_methods:
#                 all_methods.append(tmp_method)
    ############################################################           
                
    #限制性API
    Restricted_API_list =[]
    for api in all_methods:
        if api in offical_API_permission.keys():
            if api not in Restricted_API_list:
                Restricted_API_list.append(api)
    
    #获取Used_permission
    Used_permission = []
    for api in all_methods:
        if api in offical_API_permission.keys():
            permissions = offical_API_permission[api]
            for item in permissions:
                if item not in Used_permission:
                    Used_permission.append(item)
                
    #提取Suspicious_API            
    Suspicious_API = []
    for api in all_methods:
        for p_api in offical_Suspicious_API:
            if p_api in api and p_api not in Suspicious_API:
                Suspicious_API.append(p_api)
    
    return Restricted_API_list,Used_permission,Suspicious_API

def extract_ShellCommand(ao,offical_Shell_Command,offical_formal_Command):
    a,d,dx = ao
    bc_codes = []
    #这里以后研究"'ExternalMethod' object has no attribute 'get_code'"
    #Round One
    for current_class in d[0].get_classes():
        for method in current_class.get_methods():
            byte_code = method.get_code()
            if byte_code != None:
                byte_code = byte_code.get_bc()
                for i in byte_code.get_instructions():
                    bb = "%s%s\n" %(i.get_name(),i.get_output())
                    if bb not in bc_codes:
                        bc_codes.append(bb)
    
    Shell_command = []
    for item in bc_codes:
        res_command = []
        for pattern in offical_Shell_Command:
            command = re.search(pattern, item)
            if command is None:
                continue
            elif command.group() not in Shell_command:
                res_command.append(command.group())
        if len(res_command) > 0:
            for item in res_command:
                if item not in Shell_command:
                    Shell_command.append(item)
                
    Sensitive_command = []
    for com in offical_formal_Command:
        if com in Shell_command and com not in Sensitive_command:
            Sensitive_command.append(com)

    return Sensitive_command

#feature
def extract_feature(a):
    features_list = list(a.get_features())
    return features_list

#Manifest permission
def extract_permission(a):
    permissions_list = a.get_permissions()
    return permissions_list

#四大组件
#activity
def extract_activity(a):
    activities_list = a.get_activities()
    return activities_list

#service
def extract_service(a):
    services_list = a.get_services()
    return services_list
  
#receivers
def extract_receiver(a):
    receivers_list = a.get_receivers()
    return receivers_list
    
#providers
def extract_provider(a):
    providers_list = a.get_providers()
    #print(providers_list)
    return providers_list

#获取Intent特征(用于组件之间的消息传递)
def extract_intent_filters(a):
    intent_attr_list = []
    
    #获得receiver的intent
    receiver_list = extract_receiver(a);
    #遍历activity_list 获得每个android:name的名称
    for items in receiver_list:
        intent_list = a.get_intent_filters("receiver",items) #返回的是字典
        #遍历字典，得到所有的键值， 即'action' 'category'
        for key,value in intent_list.items():
            for v in value:
                intent_attr_sp = v.split('.')
                if(intent_attr_sp[0] == 'android') and v not in intent_attr_list:
                    intent_attr_list.append(v)  
                
    #获得service的intent
    service_list = extract_service(a);
    #遍历activity_list获得每个android:name的名称
    for items in service_list:
        intent_list = a.get_intent_filters("service",items) #返回的是字典
        #遍历字典，得到所有的键值， 即'action' 'category'
        for key,value in intent_list.items():
            for v in value:
                intent_attr_sp = v.split('.')
                if(intent_attr_sp[0] == 'android') and v not in intent_attr_list:
                    intent_attr_list.append(v)
                    
    #获得activity的intent
    activity_list = extract_activity(a);
    #遍历activity_list获得每个android:name的名称
    for items in activity_list:
        intent_list = a.get_intent_filters("activity",items) #返回的是字典
        #遍历字典，得到所有的键值， 即'action' 'category'
        for key,value in intent_list.items():
            for v in value:
                intent_attr_sp = v.split('.')
                if(intent_attr_sp[0] == 'android') and v not in intent_attr_list:
                    intent_attr_list.append(v) 

    return intent_attr_list,receiver_list,service_list,activity_list    #返回intent属性的特征列表

#将属性写入文件
def write_attr_toFile(ao,path,current_apk_folder,intent,receiver,service,activity,feature,permission,provider,Sensitive_command,Restricted_API_list,Used_permission,Suspicious_API):
    a,d,dx = ao
    apk_name = path.split('\\')[-1]
    #属性输出文件
    attr_file = os.path.join(current_apk_folder,apk_name)
    
    #考虑特征集合去重
    with open(attr_file,'w+',encoding='utf-8') as f:
        for item in intent:
            f.write("intent::"+item+"\n")
            
        for item in feature:
            f.write("feature::"+item+"\n")
            
        for item in permission:
            f.write("permission::"+item+"\n")
        
        for item in activity:
            f.write("activity::"+item+"\n")
        
        for item in service:
            f.write("service::"+item+"\n")
    
        for item in receiver:
            f.write("receiver::"+item+"\n")
            
        for item in provider:
            f.write("provider::"+item+"\n")
        
        for item in Restricted_API_list:
            f.write("api_call::"+item+"\n")
        
        for item in Used_permission:
            f.write("real_permission::"+item+"\n")
            
        for item in Suspicious_API:
            f.write("call::"+item+"\n") 
        
        for item in Sensitive_command:
            f.write("command::"+item+"\n")

def remove_duplicates(feature_set):  #将提取的特征列表去重
    feature_set = list(set(feature_set))
    return feature_set
    
def extract_Manifest(ao):
    a,d,dx = ao
    feature = extract_feature(a)
    permission = extract_permission(a)
    provider = extract_provider(a)
    intent,receiver,service,activity = extract_intent_filters(a)
    return intent,receiver,service,activity,feature,permission,provider
    
def extract_main(path,current_apk_folder):
    ao = get_androguard_obj(path)
    if ao is None:
        return None
    offical_formal_Command,offical_API_permission,offical_Suspicious_API,offical_Shell_Command = read_file()
    intent,receiver,service,activity,feature,permission,provider = extract_Manifest(ao)
    Restricted_API_list,Used_permission,Suspicious_API = extract_api(ao,offical_API_permission,offical_Suspicious_API)
    Sensitive_command = extract_ShellCommand(ao,offical_Shell_Command,offical_formal_Command)
    
    write_attr_toFile(ao,path,current_apk_folder,intent,receiver,service,activity,feature,permission,provider,Sensitive_command,Restricted_API_list,Used_permission,Suspicious_API)

#层次遍历文件夹
def iter_files(rootDir):
    apk_name_path = {}
    count = 0
    #遍历根目录
    for root,dirs,files in os.walk(rootDir):
        for file in files:
            file_name = os.path.join(root,file)
            count = count + 1
            apk_name_path[file] = file_name
        for dirname in dirs:
            iter_files(dirname)
    return apk_name_path,count

def main():
    all_number = iter_files(dataSet_path)[1]
    #设置计数指针
    count = 0 #记录当前反编译的个数
    apk_folder_path = r'I:\AndroidMalwareDataset\dataset\apk\benign\MyGoogle'   #apk的数据集
    destination_folder_path = r'I:\AndroidMalwareDataset\dataset\feature\benign\MyGoogle'
    apk_name_path,number = iter_files(apk_folder_path)
    original_all_apk = list(apk_name_path.keys())
    current_apk_source_decompilation_apk = os.listdir(destination_folder_path)
    for apk in original_all_apk:
        if apk in current_apk_source_decompilation_apk: #如果已经反编译则跳过
            continue
        apk_path = apk_name_path[apk]
        print(apk_path)
        #开始进行反编译
        try:
            extract_main(apk_path,destination_folder_path)
            count +=1
            if count % 10 == 0:
                print(str(count) + '/' + str(number))
        except Exception:
            continue

if __name__=='__main__':
    main()
    



