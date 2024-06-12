import csv
import glob
import os
import pickle
from src.scrapy_behavior import get_data, collect_behaviors
from src.static_analysis import *


def get_behavior_list(target_path, apk_sha256):
    if os.path.exists(target_path + apk_sha256 + '_behavior.txt'):
        scrap_path = target_path + apk_sha256 + '_behavior.txt'
    else:
        scrap_path = get_data(apk_sha256,target_path)
    behavior_list = collect_behaviors(scrap_path)
    return behavior_list

def behavior_api_match():
    re_dict = {}
    with open("../res/Behavior_mapped_APIs.csv",'r') as f:
        for line in f.readlines():
            e_list = line.strip().split(',')
            behavior = e_list[0]
            api_list = e_list[1:]
            print(behavior + ":  " + str(api_list))
            re_dict[behavior] = api_list
    fre = open("../res/Behavior_mapped_APIs.data", 'wb')
    pickle.dump(re_dict, fre)
    f.close()

def label_related_api():
    label_related_API_path = "../res/label_related_APIs.data"
    if os.path.exists(label_related_API_path):
        f = open(label_related_API_path, 'rb')
        label_related_API = pickle.load(f)
    else:
        label_related_API = {}
        with open("../res/label_related_APIs.csv", 'r') as l2a_f:
            for line in l2a_f.readlines():
                api_ = line.strip().split(',')[0]
                label = line.strip().split(',')[1]
                if api_ not in label_related_API:
                    label_related_API[api_] = label
        f = open(label_related_API_path, 'wb')
        pickle.dump(label_related_API, f)
        f.close()
    return label_related_API

def malicious_subgraph(apk_sha256, node_path, edge_path, targt_path,layer=1):
    behavior_api_match = pickle.load(open("../res/Behavior_mapped_APIs.data", "rb"))
    behavior_list = get_behavior_list(targt_path, apk_sha256)
    # behavior_api_match = pickle.load(open("../res/Behavior_mapped_APIs.data","rb"))

    temp_core_node_list = []
    for behavior in behavior_list:
        if behavior in behavior_api_match:
            temp_core_node_list += behavior_api_match[behavior]

    core_node_list = []
    node_f = open(node_path, 'r', encoding='utf-8')
    line0 = node_f.readline()
    for line in node_f.readlines():
        api_ = line.strip().split(',')[1]
        part_qian = api_.split(';->')[0].split('/')[-1]
        part_hou = api_.split(';->')[-1].split('(')[0]
        temp_core_node = part_qian + '->' + part_hou
        if temp_core_node in temp_core_node_list:
            core_node_list.append(api_)
    node_list = get_center_list(node_path, edge_path, core_node_list, layer)
    return node_list

def malicious_label(apk_sha256, node_path,edge_path,target_path):
    label_list = []
    label_related_apis = label_related_api()
    node_list = malicious_subgraph(apk_sha256, node_path, edge_path, target_path,layer=1)
    node_ff = open(node_path, 'r', encoding='utf-8')
    line0 = node_ff.readline()
    for index, line in enumerate(node_ff.readlines()):
        api = line.strip().split(',')[1]
        if index in node_list:
            api_class = api.strip().split(';->')[0].split('/')[-1]
            api_method = api.strip().split(';->')[-1].split('(')[0]
            api_now = api_class + '->' + api_method
            if api_now in label_related_apis:
                label_now = label_related_apis[api_now]
                if label_now not in label_list:
                    label_list.append(label_now)
    return label_list

def get_center_list(node_path,edge_path, api_list, layer):
    node_list = []
    node_list_2 = []
    wating_list = []
    node_file = open(node_path, 'r')
    line0 = node_file.readline()
    for index, line in enumerate(node_file.readlines()):
        name = line.strip().split(',')[1]
        function = name.strip().split('->')[1].split('(')[0]
        if name in api_list:
            node_list.append(index)
    edge_file = open(edge_path, 'r')
    for line in edge_file.readlines():
        source = int(line.strip().split(' ')[0])
        target = int(line.strip().split(' ')[1])
        if source in node_list or target in node_list:
            # g.add_edge(source, target)
            if target not in node_list:
                wating_list.append(target)
            if source not in node_list:
                wating_list.append(source)
    node_list = node_list + wating_list
    print(f'length of first layer is {len(node_list)}')

    if layer == 2:
        edge_file.close()
        edge_file = open(edge_path, 'r')
    else:
        return node_list
    for line in edge_file.readlines():
        source = int(line.strip().split(' ')[0])
        target = int(line.strip().split(' ')[1])
        if source in node_list or target in node_list:
            if target not in node_list:
                node_list_2.append(target)
            if source not in node_list:
                node_list_2.append(source)
    node_list = node_list + node_list_2
    print(f'length of second layer is {len(node_list)}')
    return node_list

def malware_report(apk_sha256, apk_path, output_path):
    if not os.path.exists(output_path + apk_sha256):
        os.mkdir(output_path + apk_sha256)
    re_f = open(output_path + 'report.txt', 'w')

    # node_path = r"D:\lab_related\script_project\AMBL\res\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610_node.csv"
    # edge_path = r"D:\lab_related\script_project\AMBL\res\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610_edgelist.txt"

    adguard_cg(apk_sha256, apk_path, output_path)
    node_path, edge_path = change_format_gml(apk_sha256, output_path)
    labels = malicious_label(apk_sha256,node_path, edge_path,target_path)

    permission_list = adguard_permission(apk_path)

    intents = adguard_intents(apk_path)

    apis_path = adguard_api(node_path,target_path)

    re_f.write(apk_sha256 + ":")
    re_f.write(str(labels) + '\n')
    re_f.write('-' * 30 + '\n')
    re_f.write('Permissions:\n')
    for p in permission_list:
        re_f.write(p + '\n')
    re_f.write('-' * 30 + '\n')
    re_f.write('API:\n')
    re_f.write(apis_path + '\n')
    re_f.write('-' * 30 + '\n')
    re_f.write('Intent:\n')
    for key in intents:
        for intent in intents[key]:
            re_f.write(intent + '\n')
    re_f.write('-' * 30 + '\n')
    re_f.write('Function call graph:\n')
    re_f.write('node path: ' + node_path + '\n')
    re_f.write('edge path: ' + edge_path)

# # node_path = r"D:\lab_related\script_project\AMBL\res\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610_node.csv"
# # edge_path = r"D:\lab_related\script_project\AMBL\res\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610_edgelist.txt"
# apk_sha256 = "4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610"
# target_path = r"D:\lab_related\script_project\AMBL\res\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610\\"
# apk_path = r"D:\lab_related\script_project\AMBL\res\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610\4fe0bc6ec7c284b92f6e45aca7ea7972d1b60a913f2af884dd79b03cd2add610"
# # label_list = malicious_label(apk_sha256,node_path, edge_path,target_path)
# # print(label_list)
#
# malware_report(apk_sha256,apk_path,target_path)
