import os
from androguard.core.bytecodes.apk import APK

def adguard_permission(apk_id):
    base_path = 'I:\\B326_backup\\lab_file\\GooglePlay_Malware\\ICSE22ArtifactsZip\\ICSE22ArtifactsZip\\GPMalware_ICSE22\\malware_samples\\'
    a = APK(base_path + apk_id + '.apk')
    permissions = a.get_permissions()
    print(permissions)
    return permissions
def adguard_intents(apk_id):
    base_path = 'I:\\B326_backup\\lab_file\\GooglePlay_Malware\\ICSE22ArtifactsZip\\ICSE22ArtifactsZip\\GPMalware_ICSE22\\malware_samples\\'
    a = APK(base_path + apk_id + '.apk')
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

def adguard_cg(apk_id):
    base_path = 'I:\\B326_backup\\lab_file\\GooglePlay_Malware\\ICSE22ArtifactsZip\\ICSE22ArtifactsZip\\GPMalware_ICSE22\\malware_samples\\'
    target_path = 'D:\\lab_related\\dataset_work\\GooglePlay_Malware_cg\\'
    command = 'androguard cg ' + base_path + apk_id + '.apk -o ' + target_path + apk_id + '.gml'
    print(apk_id)
    os.system(command)

def change_format_gml(apk_id):
    '''
    对于androguard生成的call graph的gml文件，改一下格式用于输入deepwalk
    :param gml_file:
    :return:
    '''
    gml_path = 'D:\\lab_related\\dataset_work\\GooglePlay_Malware_cg\\'
    # apk_name = gml_file.strip().split('/')[-1].split('.')[0]
    print(apk_id)
    # base_path = '/home/fly/fly/dataset_file/virusshare_after_cg'
    base_path = 'D:\\lab_related\\dataset_work\\GooglePlay_Malware_cg\\'
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