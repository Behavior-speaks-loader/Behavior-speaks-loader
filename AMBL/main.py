import argparse
import os
from src.malicious_label import malicious_label, malware_report
from src.static_analysis import adguard_cg, change_format_gml, adguard_intents,adguard_permission

def begin_arg():
    parse = argparse.ArgumentParser()
    parse.add_argument('--apk_sha256', type=str, required=True,help='SHA256 of the malware')
    parse.add_argument('--apk_path', type=str, required=True, help='The file path of malware')
    parse.add_argument('--output_path', default='./res/', type=str, help='output path')
    parse.add_argument('--Permission', action='store_true', help='Print permissions used by the malware')
    parse.add_argument('--API', action='store_true', help='Print APIs used by the malware')
    parse.add_argument('--Intent', action='store_true', help='Print intents used by the malware')
    parse.add_argument('--Function_call_graph', action='store_true',help="Generate the function call graph for malware,"
                                                     " with the output file ending in a. gml suffix")
    parse.add_argument('--Malicious_label', action='store_true',help='Print the malicious labels of the malware')
    parse.add_argument('--Malware_report', action='store_true',help='Generate the malware report for the malware')
    args = parse.parse_args()
    return args

if __name__ == '__main__':
    args = begin_arg()
    apk_sha256 = args.apk_sha256
    result_folder = args.output_path + apk_sha256 + '/'
    os.mkdir(result_folder)

    fcg_flag = False
    if args.Function_call_graph:
        adguard_cg(apk_sha256, args.apk_path, result_folder)
        node_path, edge_path = change_format_gml(apk_sha256, result_folder)
        fcg_flag = True

    if args.Malicious_label:
        if not fcg_flag:
            adguard_cg(apk_sha256, args.apk_path, result_folder)
            node_path, edge_path = change_format_gml(apk_sha256, result_folder)
        label_list = malicious_label(node_path, edge_path)
        print("malicious labels of apk_sha256 are: ", label_list)

    if args.Permission:
        Permission = adguard_permission(args.apk_path)
        print(Permission)
    if args.API:
        api_list = []
        if not fcg_flag:
            adguard_cg(apk_sha256, args.apk_path, result_folder)
            node_path, edge_path = change_format_gml(apk_sha256, result_folder)
        with open(node_path, 'r') as f:
            line0 = f.readline()
            for line in f.readlines():
                api = line.strip().split(',')[-1]
                if api not in api_list:
                    api_list.append(api)
        print(api_list)

    if args.Intent:
        intent = adguard_intents(args.apk_path)
        print(intent)

    if args.Malware_report:
        malware_report(apk_sha256, args.apk_path, args.output_path)

