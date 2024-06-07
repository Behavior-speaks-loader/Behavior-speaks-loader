import csv
import glob
import os
import pickle

def get_behavior_list():
    behavior_list = []
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
    re_dict = {}
    return re_dict

def malicious_subgraph(node_path,edge_path,layer=1):
    behavior_list = get_behavior_list()
    behavior_api_match = pickle.load(open("../res/Behavior_mapped_APIs.data","rb"))

    temp_core_node_list = []
    for behavior in behavior_list:
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

def malicious_label(node_path,edge_path):
    label_list = []
    label_related_apis = label_related_api()
    node_list = malicious_subgraph(node_path, edge_path)
    node_ff = open(node_path, 'r', encoding='utf-8')
    line0 = node_ff.readline()
    for index, line in enumerate(node_ff.readlines()):
        api = line.strip().split(',')[1]
        if index in node_list:
            if api in label_related_apis:
                label_now = label_related_apis[api]
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

behavior_api_match()