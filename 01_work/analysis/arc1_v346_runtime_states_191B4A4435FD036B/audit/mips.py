import struct

REGS = ['zero','at','v0','v1','a0','a1','a2','a3','t0','t1','t2','t3','t4','t5','t6','t7',
        's0','s1','s2','s3','s4','s5','s6','s7','t8','t9','k0','k1','gp','sp','fp','ra']

def sext16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v

def disasm_one(word, addr):
    op = (word >> 26) & 0x3F
    rs = (word >> 21) & 0x1F
    rt = (word >> 16) & 0x1F
    rd = (word >> 11) & 0x1F
    sh = (word >> 6) & 0x1F
    funct = word & 0x3F
    imm = word & 0xFFFF
    simm = sext16(imm)
    target = word & 0x3FFFFFF
    R = lambda n: '$'+REGS[n]

    if word == 0:
        return 'nop'
    if op == 0:
        if funct == 0x00: return f'sll {R(rd)}, {R(rt)}, {sh}' if word else 'nop'
        if funct == 0x02: return f'srl {R(rd)}, {R(rt)}, {sh}'
        if funct == 0x03: return f'sra {R(rd)}, {R(rt)}, {sh}'
        if funct == 0x08: return f'jr {R(rs)}'
        if funct == 0x09: return f'jalr {R(rd)}, {R(rs)}'
        if funct == 0x21: return f'addu {R(rd)}, {R(rs)}, {R(rt)}'
        if funct == 0x23: return f'subu {R(rd)}, {R(rs)}, {R(rt)}'
        if funct == 0x24: return f'and {R(rd)}, {R(rs)}, {R(rt)}'
        if funct == 0x25: return f'or {R(rd)}, {R(rs)}, {R(rt)}'
        if funct == 0x2A: return f'slt {R(rd)}, {R(rs)}, {R(rt)}'
        if funct == 0x2B: return f'sltu {R(rd)}, {R(rs)}, {R(rt)}'
        return f'.special funct={funct:#x} word={word:#010x}'
    if op == 0x02: return f'j {((addr+4)&0xF0000000)|(target<<2):#010x}'
    if op == 0x03: return f'jal {((addr+4)&0xF0000000)|(target<<2):#010x}'
    if op == 0x04: return f'beq {R(rs)}, {R(rt)}, {addr+4+simm*4:#010x}'
    if op == 0x05: return f'bne {R(rs)}, {R(rt)}, {addr+4+simm*4:#010x}'
    if op == 0x06: return f'blez {R(rs)}, {addr+4+simm*4:#010x}'
    if op == 0x07: return f'bgtz {R(rs)}, {addr+4+simm*4:#010x}'
    if op == 0x08: return f'addi {R(rt)}, {R(rs)}, {simm}'
    if op == 0x09: return f'addiu {R(rt)}, {R(rs)}, {simm}'
    if op == 0x0A: return f'slti {R(rt)}, {R(rs)}, {simm}'
    if op == 0x0B: return f'sltiu {R(rt)}, {R(rs)}, {simm}'
    if op == 0x0C: return f'andi {R(rt)}, {R(rs)}, {imm:#x}'
    if op == 0x0D: return f'ori {R(rt)}, {R(rs)}, {imm:#x}'
    if op == 0x0F: return f'lui {R(rt)}, {imm:#x}'
    if op == 0x10: return f'.cop0 word={word:#010x}'
    if op == 0x20: return f'lb {R(rt)}, {simm}({R(rs)})'
    if op == 0x21: return f'lh {R(rt)}, {simm}({R(rs)})'
    if op == 0x23: return f'lw {R(rt)}, {simm}({R(rs)})'
    if op == 0x24: return f'lbu {R(rt)}, {simm}({R(rs)})'
    if op == 0x25: return f'lhu {R(rt)}, {simm}({R(rs)})'
    if op == 0x28: return f'sb {R(rt)}, {simm}({R(rs)})'
    if op == 0x29: return f'sh {R(rt)}, {simm}({R(rs)})'
    if op == 0x2B: return f'sw {R(rt)}, {simm}({R(rs)})'
    return f'.word {word:#010x}'

def disasm_range(buf, file_off, va_start, nwords):
    out = []
    for i in range(nwords):
        off = file_off + i*4
        if off+4 > len(buf):
            break
        word = struct.unpack_from('<I', buf, off)[0]
        addr = va_start + i*4
        out.append((addr, word, disasm_one(word, addr)))
    return out

if __name__ == '__main__':
    pass
