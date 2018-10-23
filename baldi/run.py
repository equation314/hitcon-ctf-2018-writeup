from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *
from disassemble import *

def get_uc_params(arch):
    if arch == 'i386':
        return UC_ARCH_X86, UC_MODE_32
    elif arch == 'x86_64':
        return UC_ARCH_X86, UC_MODE_64
    elif arch == 'arm':
        return UC_ARCH_ARM, UC_MODE_ARM
    elif arch == 'aarch64':
        return UC_ARCH_ARM64, UC_MODE_ARM
    elif arch == 'mips':
        return UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN
    elif arch == 'powerpc':
        return UC_ARCH_PPC, UC_MODE_PPC32 | UC_MODE_BIG_ENDIAN

def run_power_pc(asm_code):
    r = [0 for i in range(32)]
    m = [0 for i in range(0x200)]
    r[1] = 0x100

    def S(x):
        return x & 0xffffffff
    def I(s):
        if '0x' in s:
            return int(s, 16)
        else:
            return int(s, 10)
    def R(s):
        return int(s[1:])
    def MR(s):
        p = s.find('(')
        return R(s[p+1:-1])
    def MO(s):
        p = s.find('(')
        if p != -1:
            s = s[:p]
        return I(s)
    def M(s):
        return r[MR(s)] + MO(s)

    for line in asm_code.splitlines():
        p = line.find(' ')
        if p == -1:
            p = len(line)
        ins = line[:p]
        ops = line[p+1:].split(', ')
        # print(ins, ops)
        if ins == 'mr':
            r[R(ops[0])] = r[R(ops[1])]
        elif ins == 'li':
            r[R(ops[0])] = I(ops[1])
        elif ins == 'lis':
            r[R(ops[0])] = I(ops[1]) << 16
        elif ins == 'ori':
            r[R(ops[0])] = r[R(ops[1])] | I(ops[2])
        elif ins == 'andi.':
            r[R(ops[0])] = r[R(ops[1])] & I(ops[2])
        elif ins == 'xori':
            r[R(ops[0])] = r[R(ops[1])] ^ I(ops[2])
        elif ins == 'addi':
            r[R(ops[0])] = r[R(ops[1])] + I(ops[2])
        elif ins == 'mulli':
            r[R(ops[0])] = S(r[R(ops[1])] * I(ops[2]))
        elif ins == 'addis':
            r[R(ops[0])] = r[R(ops[1])] + (I(ops[2]) << 16)
        elif ins == 'subfic':
            r[R(ops[0])] = I(ops[2]) - r[R(ops[1])]
        elif ins == 'and':
            r[R(ops[0])] = r[R(ops[1])] & r[R(ops[2])]
        elif ins == 'or':
            r[R(ops[0])] = r[R(ops[1])] | r[R(ops[2])]
        elif ins == 'xor':
            r[R(ops[0])] = r[R(ops[1])] ^ r[R(ops[2])]
        elif ins == 'add':
            r[R(ops[0])] = r[R(ops[1])] + r[R(ops[2])]
        elif ins == 'sub':
            r[R(ops[0])] = r[R(ops[1])] - r[R(ops[2])]
        elif ins == 'subf':
            r[R(ops[0])] = r[R(ops[2])] - r[R(ops[1])]
        elif ins == 'mullw':
            r[R(ops[0])] = S(r[R(ops[1])] * r[R(ops[2])])
        elif ins == 'stw':
            m[M(ops[1])] = r[R(ops[0])]
        elif ins == 'lwz':
            r[R(ops[0])] = m[M(ops[1])]
        elif ins == 'stwu':
            a = M(ops[1])
            r[R(ops[0])] = m[a]
            r[MR(ops[1])] = a
        elif ins == 'blr':
            pass
        else:
            print('   [UNKNOWN]: ' + line)
        # print(r[1], r[2], r[3], r[4], r[31])
    return S(r[3])

def run_riscv(asm_code):
    r = [0 for i in range(32)]
    m = [0 for i in range(0x200)]

    def S(x):
        return x & 0xffffffff
    def I(s):
        if '0x' in s:
            return int(s, 16)
        else:
            return int(s, 10)
    def R(s):
        m = {
            'x0': 0,
            'ra': 1,
            'sp': 2,
            'gp': 3,
            'tp': 4,
            't0': 5,
            't1': 6,
            't2': 7,
            's0': 8,
            's1': 9,
        }
        if s in m:
            return m[s]
        off = {'a': 10, 's': 16, 't': 25}[s[0]]
        return int(s[1:]) + off
    def MR(s):
        p = s.find('(')
        return R(s[p+1:-1])
    def MO(s):
        p = s.find('(')
        if p != -1:
            s = s[:p]
        return I(s)
    def M(s):
        return r[MR(s)] + MO(s)

    r[R('sp')] = 0x100

    for line in asm_code.splitlines():
        p = line.find(' ')
        if p == -1:
            p = len(line)
        ins = line[:p]
        ops = line[p+1:].split(', ')
        # print(ins, ops)
        if ins == 'lui':
            r[R(ops[0])] = I(ops[1]) << 12
        elif ins == 'li':
            r[R(ops[0])] = I(ops[1])
        elif ins == 'ori':
            r[R(ops[0])] = r[R(ops[1])] | I(ops[2])
        elif ins == 'andi':
            r[R(ops[0])] = r[R(ops[1])] & I(ops[2])
        elif ins == 'xori':
            r[R(ops[0])] = r[R(ops[1])] ^ I(ops[2])
        elif ins == 'addi':
            r[R(ops[0])] = r[R(ops[1])] + I(ops[2])
        elif ins == 'and':
            r[R(ops[0])] = r[R(ops[1])] & r[R(ops[2])]
        elif ins == 'or':
            r[R(ops[0])] = r[R(ops[1])] | r[R(ops[2])]
        elif ins == 'xor':
            r[R(ops[0])] = r[R(ops[1])] ^ r[R(ops[2])]
        elif ins == 'add':
            r[R(ops[0])] = r[R(ops[1])] + r[R(ops[2])]
        elif ins == 'sub':
            r[R(ops[0])] = r[R(ops[1])] - r[R(ops[2])]
        elif ins == 'mul':
            r[R(ops[0])] = S(r[R(ops[1])] * r[R(ops[2])])
        elif ins == 'sw':
            m[M(ops[1])] = r[R(ops[0])]
        elif ins == 'lw':
            r[R(ops[0])] = m[M(ops[1])]
        elif ins == 'j':
            pass
        elif ins == 'ret':
            pass
        else:
            print('   [UNKNOWN]: ' + line)
        # print(r[R('s0')], r[R('s1')], r[R('sp')], r[R('a0')])

    # for i in range(len(r)):
    #     print('x%s = %08x' % (i, S(r[i])))
    # for i in range(0x80,0x120,4):
    #     line = '0x%08x: ' % i
    #     for j in range(4):
    #         line += '%08x ' % S(m[i])
    #     print(line)

    return S(r[R('a0')])

def run_wasm(asm_code):
    global s
    s = [0 for i in range(0x200)]

    def push(x):
        global s
        s.append(x)
    def pop():
        global s
        x = s[-1]
        s = s[:-1]
        return x

    for line in asm_code.splitlines():
        ops = line.split(' ')
        ins = ops[0]
        if ins == 'i32.const':
            x = int(ops[1])
            push(x)
        elif ins == 'i32.sub':
            x = pop()
            y = pop()
            push(y - x)
        elif ins == 'i32.add':
            x = pop()
            y = pop()
            push(x + y)
        elif ins == 'i32.and':
            x = pop()
            y = pop()
            push(x & y)
        elif ins == 'i32.or':
            x = pop()
            y = pop()
            push(x | y)
        elif ins == 'i32.xor':
            x = pop()
            y = pop()
            push(x ^ y)
        elif ins == 'i32.mul':
            x = pop()
            y = pop()
            push(x * y)
        elif ins == 'return':
            break
        else:
            print('   [UNKNOWN]: ' + line)

    x = s[-1] & 0xffffffff
    if x & 0x80000000:
        x = -((~x + 1) & 0xffffffff)
    return x

def run(code, arch):
    asm_code = disassemble(code, arch)
    print(asm_code)

    if arch == 'powerpc':
        return hex(run_power_pc(asm_code))
    elif arch == 'riscv':
        return hex(run_riscv(asm_code))
    elif arch == 'wasm':
        return str(run_wasm(asm_code))

    off = 0
    base = 0x1000000
    size = 0x100000
    stack_base = 0x8000000
    stack_size = 0x100000
    sp = stack_base - 0x10

    uc_arch, uc_mode = get_uc_params(arch)
    mu = Uc(uc_arch, uc_mode)
    mu.mem_map(base, size)
    mu.mem_map(stack_base - stack_size, stack_size)
    mu.mem_write(base, code)

    if arch == 'i386':
        mu.reg_write(UC_X86_REG_ESP, sp)
        reg = UC_X86_REG_EAX
        off = 1
    elif arch == 'x86_64':
        mu.reg_write(UC_X86_REG_RSP, sp)
        reg = UC_X86_REG_RAX
        off = 1
    elif arch == 'arm':
        mu.reg_write(UC_ARM_REG_SP, sp)
        reg = UC_ARM_REG_R0
        off = 4
    elif arch == 'aarch64':
        mu.reg_write(UC_ARM64_REG_SP, sp)
        reg = UC_ARM64_REG_X0
        off = 4
    elif arch == 'mips':
        mu.reg_write(UC_MIPS_REG_SP, sp)
        reg = UC_MIPS_REG_V0
        off = 4

    mu.emu_start(base, base + len(code) - off)
    res = mu.reg_read(reg)

    return hex(res)
