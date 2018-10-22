import sys
from pwn import *

STR = 'oidn1be8!kasgm2q5jwplz7rhvy094xfu6t3c'
ORDER = [10, 8, 3, 2, 7, 9, 12, 0, 4, 6, 11, 5, 1, 13]

context.log_level = 'error'

def check_2(flag):
    p = process(['./party_patched', flag])
    data = p.recvall()
    p.close()
    return 'hitcon' in data

def check_3(flag):
    p = process(['./party-0efe21e5fab4f979555c100a2f4242bd', flag])
    data = p.recvall()
    p.close()
    if 'hitcon' in data:
        print(data)

def str2set(str):
    return [STR.find(c) for c in str]

def set2str(set):
    tmp = ''
    for j in range(37):
        if j in set:
            tmp += STR[j]
    res = ''
    for j in range(len(tmp)):
        res += tmp[ORDER[j]]
    return res

def transform(flag):
    a = str2set(flag)
    for i in range(37):
        if i in a:
            b = filter(lambda j: j != i, a)
            for j in range(i):
                if j not in a:
                    flag = set2str(b + [j])
                    if check_2(flag):
                        return flag
    return None

if __name__ == '__main__':
    flag = '645q9f3ozytrac'
    if len(sys.argv) > 1:
        flag = sys.argv[1]
    while True:
        f = transform(flag)
        print(flag, f)
        if f:
            flag = f
        else:
            check_3(flag)
            break

# 9renp0to!m4gic
