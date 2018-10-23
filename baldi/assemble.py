from leb128 import *
from pwn import *
from keystone import *

def assemble_wasm(code):
    res = ''

    opcode = {
        'i32.clz'  :  '\x67',
        'i32.ctz'  :  '\x68',
        'i32.popcn':  '\x69',
        'i32.add'  :  '\x6a',
        'i32.sub'  :  '\x6b',
        'i32.mul'  :  '\x6c',
        'i32.div_s':  '\x6d',
        'i32.div_u':  '\x6e',
        'i32.rem_s':  '\x6f',
        'i32.rem_u':  '\x70',
        'i32.and'  :  '\x71',
        'i32.or'   :  '\x72',
        'i32.xor'  :  '\x73',
        'i32.shl'  :  '\x74',
        'i32.shr_s':  '\x75',
        'i32.shr_u':  '\x76',
        'i32.rotl' :  '\x77',
        'i32.rotr' :  '\x78',
        'return'   :  '\x0f',
        'end'      :  '\x0b',
    }

    for line in code.splitlines():
        ops = line.split(' ')
        ins = ops[0]
        ops = ops[1:]
        if ins == 'i32.const':
            res += '\x41'
            x = str(leb128s_encode(int(ops[0])))
            print(ops[0], x.encode('hex'))
            res += x
        elif ins in opcode:
            res += opcode[ins]
        else:
            print('[UNKNOWN]: ' +  line)
    return res

def assemble(code, arch):
    if arch == 'wasm':
        return assemble_wasm(code);
    elif arch == 'mips':
        ks_arch, ks_mode = KS_ARCH_MIPS, KS_MODE_MIPS32 | KS_MODE_BIG_ENDIAN
        ks = Ks(ks_arch, ks_mode)
        code, count = ks.asm(code)
        code = str(bytearray(code[:-4]))
    else:
        code = asm(code, arch=arch)

    return code

