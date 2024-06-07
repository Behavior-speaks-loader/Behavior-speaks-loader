import argparse

def begin_arg():
    parse = argparse.ArgumentParser()
    parse.add_argument('--apk_sha256', type=str)
    parse.add_argument('--apk_path', type=str)
    parse.add_argument('--output_path', default='./res', type=str, help='output path')
    args = parse.parse_args()
    return args

if __name__ == '__main__':
    args = begin_arg()