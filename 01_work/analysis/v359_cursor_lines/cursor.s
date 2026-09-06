.set noreorder
        addiu $sp, $sp, -16
        lw $t0, 8($a1)
        lw $t1, 16($a1)
        lw $t2, 24($a1)
        lw $t3, 32($a1)
        sw $t0, 0($sp)
        sw $t1, 4($sp)
        sw $t2, 8($sp)
        sw $t3, 12($sp)
        srl $t0, $s1, 4
        sltiu $t1, $t0, 9
        bne $t1, $zero, valid
        nop
        or $t0, $zero, $zero
    valid:
        sll $t0, $t0, 3
        lui $t1, 32799
        ori $t1, $t1, 62856
        addu $t0, $t0, $t1
        lbu $t2, 0($t0)
        addiu $t0, $t0, 1
        addiu $t1, $t2, 2
        sb $t1, 3($a1)
        lui $t1, 0x48ff
        ori $t1, $t1, 0xffff
        sw $t1, 4($a1)
        addiu $t3, $a1, 8
    vertex:
        lbu $t1, 0($t0)
        addiu $t0, $t0, 1
        addu $t1, $sp, $t1
        lw $t1, 0($t1)
        addiu $t2, $t2, -1
        sw $t1, 0($t3)
        bne $t2, $zero, vertex
        addiu $t3, $t3, 4
        lui $t1, 0x5555
        ori $t1, $t1, 0x5555
        sw $t1, 0($t3)
        j 2149027716
        addiu $sp, $sp, 16
    