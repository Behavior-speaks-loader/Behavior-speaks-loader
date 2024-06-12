import os
from androguard.core.bytecodes.apk import APK

def adguard_permission(apk_path):
    a = APK(apk_path)
    permissions = a.get_permissions()
    print(permissions)
    return permissions

def adguard_intents(apk_path):
    a = APK(apk_path)
    activities = a.get_activities()
    services = a.get_services()
    receives = a.get_receivers()
    d= {}
    for ac in activities:
        intents_temp = a.get_intent_filters("activity",ac)
        d.update(intents_temp)
    for se in services:
        intents_temp = a.get_intent_filters("service",se)
        d.update(intents_temp)
    for re in receives:
        intents_temp = a.get_intent_filters("receiver",re)
        d.update(intents_temp)
    return d

def adguard_cg(apk_id, apk_path, target_path):
    command = 'androguard cg ' + apk_path + ' -o ' + target_path + apk_id + '.gml'
    print(apk_id)
    os.system(command)

def change_format_gml(apk_id, target_path):
    gml_path = target_path
    # apk_name = gml_file.strip().split('/')[-1].split('.')[0]
    print(apk_id)
    # base_path = '/home/fly/fly/dataset_file/virusshare_after_cg'
    base_path = target_path
    node_path = base_path + apk_id + '_node.csv'
    edge_path = base_path + apk_id + '_edgelist.txt'
    with open(gml_path + apk_id + '.gml', 'r', encoding='utf-8') as gml_f:
        node_info = open(base_path + apk_id + '_node.csv', 'w', encoding='utf-8')
        node_info.write('id,label,external,entrypoint\n')  #写列名
        edge_list = open(base_path + apk_id + '_edgelist.txt', 'w', encoding='utf-8')
        line0 = gml_f.readline()
        id, label, external, entrypoint = '', '', '', ''
        source, target = '', ''
        for line in gml_f.readlines():
            type = line.strip().split(' ')[0]
            if type == 'id':
                id = line.strip().split(' ')[1]
            elif type == 'label':
                label = line.strip().split('"')[1]
            elif type == 'external':
                external = line.strip().split(' ')[1]
            elif type == 'entrypoint':
                entrypoint = line.strip().split(' ')[1]
                node_info.write(id + ',' + label + ',' + external + ',' + entrypoint + '\n')
                id, label, external, entrypoint = '', '', '', ''

            if type == 'source':
                source = line.strip().split(' ')[1]
            elif type == 'target':
                target = line.strip().split(' ')[1]
                edge_list.write(source + ' ' + target + '\n')
                source, target = '', ''
    return node_path, edge_path

def adguard_api(node_path, target_path):
    re_f = open(target_path + 'api.txt', 'w')
    api_ist = []
    with open(node_path, 'r') as f:
        line0 = f.readline()
        for line in f.readlines():
            api = line.strip().split(',')[1]
            re_f.write(api+'\n')
    return target_path + 'api.txt'
