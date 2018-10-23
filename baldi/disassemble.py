from pwn import *
from capstone import *
from leb128 import *
import re

def format_riscv(code, arch):
    off = 32
    res = []
    for line in code.split('\n'):
        s = line[off:].lower()
        s = s.replace(',', ', ').replace('-', ' - ').replace('+', ' + ').replace(',  - ', ', -')

        p = s.find('#')
        if p != -1:
            s = s[:p]

        arr = re.split(' +', s.strip())
        s = ' '.join(arr)
        res.append(s)

    res = '\n'.join(res)
    return res

def get_cs_params(arch):
    if arch == 'i386':
        return CS_ARCH_X86, CS_MODE_32
    elif arch == 'x86_64':
        return CS_ARCH_X86, CS_MODE_64
    elif arch == 'arm':
        return CS_ARCH_ARM, CS_MODE_ARM
    elif arch == 'aarch64':
        return CS_ARCH_ARM64, CS_MODE_ARM
    elif arch == 'mips':
        return CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN
    elif arch == 'powerpc':
        return CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN

def disassemble_wasm(code):
    code2op = {
        '\x41': 'i32.const',
        '\x67': 'i32.clz'  ,
        '\x68': 'i32.ctz'  ,
        '\x69': 'i32.popcn',
        '\x6a': 'i32.add'  ,
        '\x6b': 'i32.sub'  ,
        '\x6c': 'i32.mul'  ,
        '\x6d': 'i32.div_s',
        '\x6e': 'i32.div_u',
        '\x6f': 'i32.rem_s',
        '\x70': 'i32.rem_u',
        '\x71': 'i32.and'  ,
        '\x72': 'i32.or'   ,
        '\x73': 'i32.xor'  ,
        '\x74': 'i32.shl'  ,
        '\x75': 'i32.shr_s',
        '\x76': 'i32.shr_u',
        '\x77': 'i32.rotl' ,
        '\x78': 'i32.rotr' ,
        '\x0f': 'return'   ,
        '\x0b': 'end'      ,
    }

    i, n = 0, len(code)
    res = []
    while i < n:
        if code[i] not in code2op:
            print('  [UNKNOWN] %02x' % ord(code[i]))
        op = code2op[code[i]]
        if op == 'i32.const':
            x, l = leb128s_decode(bytearray(code[i+1:i+5]))
            i += l
            op += ' ' + str(x)
        i += 1
        res.append(op)
    return '\n'.join(res)

def disassemble(code, arch, show_addr=False):
    if arch == 'riscv':
        code = disasm(code, arch=arch)
        code = format_riscv(code, arch)
        return code
    elif arch == 'wasm':
        code = disassemble_wasm(code)
        return code

    cs_arch, cs_mode = get_cs_params(arch)
    md = Cs(cs_arch, cs_mode)

    res = []
    for i in md.disasm(code, 0x0):
        line = ('%s %s' % (i.mnemonic, i.op_str)).strip()
        if show_addr:
            line = '0x%08x[0x%02x]: %s'% (i.address, i.size, line)
        res.append(line)
    return '\n'.join(res)
