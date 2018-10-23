from pwn import *
from base64 import *
from assemble import assemble
from disassemble import disassemble
from run import run

HOST = '13.231.83.89'
PORT = 30262
r = remote(HOST, PORT)

def get_arch():
    s = r.recvuntil('Press the Enter key to start the challenge...')[7:]
    print(s)

    if '|________________|' in s:
        return 'x86_64'
    elif '___   _______   _____   ___ ' in s:
        return 'i386'
    elif '.----------------.' in s:
        return 'mips'
    elif '\xe2\x96\x84' in s:
        return 'powerpc'
    elif '      _       _______     ____    ____' in s:
        return 'arm'
    elif '/__(  )__\ /__(  )__' in s:
        return 'aarch64'
    elif '_____  _____  _____  _____   __      __' in s:
        return 'riscv'

def do_assemble(arch):
    r.recvuntil('( in base64 encoded format ): \n')
    code = r.recvuntil('Answer:')[:-7]
    print(code)

    code = assemble(code, arch)
    code = b64encode(code)
    print(code)
    r.sendline(code)

def do_disassemble(arch):
    r.recvuntil('( in base64 encoded format ): \n')
    code = r.recvline()
    print(code)

    code = disassemble(b64decode(code), arch)
    print(code)
    code = b64encode(code)
    print(code)
    r.sendline(code)

def do_run(arch):
    r.recvuntil('What is ')
    code = r.recvuntil('?\n')[:-3]

    res = run(code, arch)
    print(res)
    r.sendline(res)

CMDS = [
    'w' * 5,
    'a' * 15 + 'w',
    'd' * 5 + 's' * 4 + 'a',
    's' * 4 + 'a' * 5 + 's',
    'd' * 14 + 's',
    'd' * 16 + 's',
    'w' * 9,
    's' * 3 + 'd' * 5
]

def goto_level(level):
    cmds = CMDS[level]
    for c in cmds:
        r.recvuntil('w/a/s/d:')
        r.send(c)
    r.sendline()

def goto_final():
    for i in range(3):
        r.recvuntil('(Press the Enter key to continue...)')
        r.sendline()

    for cmds in CMDS:
        for c in cmds:
            r.recvuntil('w/a/s/d:')
            r.send(c)
        print(r.recvuntil('Press the Enter key')[7:])
        r.sendline()

    for i in range(3):
        r.recvuntil('Press the Enter key')
        r.sendline()

if __name__ == '__main__':
    code = """addi sp, sp, -64
sw ra, 4(sp)
sw s0, 0(sp)
addi s0, sp, 8
addi sp, sp, -16
sw s1, 12(sp)
sw s2, 8(sp)
sw s3, 4(sp)
lui s1, 0x7
addi s1, s1, -742
sw s1, 0(s0)
lui s1, 0xb
addi s1, s1, 61
sw s1, 4(s0)
lui s1, 0x5
addi s1, s1, 734
sw s1, 8(s0)
lui s1, 0x7
addi s1, s1, -1810
sw s1, 12(s0)
lui s1, 0x2
addi s1, s1, 1876
sw s1, 16(s0)
lui s1, 0x3
addi s1, s1, -1951
sw s1, 20(s0)
lui s1, 0x5
addi s1, s1, 1682
sw s1, 24(s0)
lui s1, 0x5
addi s1, s1, 1141
sw s1, 28(s0)
lui s1, 0x2
addi s1, s1, -1696
sw s1, 32(s0)
lui s1, 0x2
addi s1, s1, 1701
sw s1, 36(s0)
lw s2, 0(s0)
lw a7, 4(s0)
lw a6, 8(s0)
lw a5, 12(s0)
lw a4, 16(s0)
lw a3, 20(s0)
lw a2, 24(s0)
lw a1, 28(s0)
lw a0, 32(s0)
lw s1, 36(s0)
lui s3, 0xf
addi s3, s3, -905
and s2, s3, s2
mul a7, s2, a7
or a6, a7, a6
add a5, a6, a5
or a4, a5, a4
and a3, a4, a3
mul a2, a3, a2
add a1, a2, a1
or a0, a1, a0
or a0, a0, s1
j 0xf0
lw s1, 12(sp)
lw s2, 8(sp)
lw s3, 4(sp)
addi sp, sp, 16
lw ra, 4(sp)
lw s0, 0(sp)
addi sp, sp, 64
ret
"""
    # arch = 'riscv'
    # code_bin = assemble(code, arch=arch)
    # print(code_bin.encode('hex'))
    # code_asm = disassemble(code_bin, arch=arch)
    # print(code_asm)
    # for i, j in zip(code.splitlines(), code_asm.splitlines()):
    #     if i != j:
    #         print(i, j)
    # print(run(code_bin,arch=arch))
    # exit(0)

    r.send('\n\n\nA\n\nB\n\n\n')
    for level in range(7):
        goto_level(level)
        print('level %d:' % level)

        arch = get_arch()
        print(arch)

        do_assemble(arch)
        print('================ assemble done ================')
        do_disassemble(arch)
        print('================ disassemble done ================')
        do_run(arch)
        print('================ run done ================')

    goto_final()

    arch = 'wasm'
    do_assemble(arch)
    print('================ assemble done ================')
    do_disassemble(arch)
    print('================ disassemble done ================')
    do_run(arch)
    print('================ run done ================')

    r.interactive()

# hitcon{U_R_D4_MA5T3R_0F_R3_AND_PPC_!#3}
