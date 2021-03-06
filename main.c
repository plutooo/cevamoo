#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef   signed short s16;
typedef unsigned int u32;
typedef unsigned long long int u64;

#define RAM_SIZE 0x800000

static u16 ram[RAM_SIZE/sizeof(u16)];
static u16 pc;

/*
  Memory structure:

  Program RAM:
  | VA        | PA                    | Name | Notes
  +-----------+-----------------------+------+-------
  | 0000-FFFF | 0x1FF00000-0x1FF20000 | Pmem | Can be read/write protected

  Data RAM (x, y configurable, multiples of 0x1000):
  | VA        | PA                    | Name | Notes
  +-----------+-----------------------+------+-------
  | 0000-xxxx | ?                     | Xmem |
  | xxxx-yyyy | ?                     | Zmem | Shared-mem and/or mem-mapped IO (uncached)
  | yyyy-FFFF | ?                     | Ymem |

  My guess for Data RAM:
  | VA        | PA                    | Name | Notes
  +-----------+-----------------------+------+-------
  | 0000-xxxx | ?                     | Xmem |
  | xxxx-FFFF | ?                     | Zmem | Shared-mem and/or mem-mapped IO (uncached)

 */

struct {
    u16 x, y;

    // ph = high 16 bits
    u32 p;

    // a0, a1, b0, b1: 36-bit registers.
    // Notation: a0l is bit0-15. a0h is bit16-31. a0e is bit32-35.
    u64 a0, a1, b0, b1;

    s16 sv; // shift register

    // cfgi: bit15-31: modi, bit0-15: stepi
    u16 cfgi, cfgj;

    u16 r[6];

    u16 sp; // stack ptr
    u16 fp; // frame ptr?

    u16 rb; // base ptr (segmentation?), sometimes called r7?

    u16 mixp; // wut?

    // "banked" r-registers
    u16 r0b, r1b, r4b;

    u32 pc; // 18 bits
    u8  prpage; // program ram page? 4 or 2 bits?

    u16 lc; // link?

    u16 repc; // repeat counter? read-only!

    // status registers
    u16 st0, st1, st2; // wut? shadow registers? weird structure.

    /*
      st0 structure:
       | Bit    | Description             | Notes
       +--------+-------------------------+--------
       |      0 | Saturation mode (?)     |
       |      1 | Interrupt Enable        | Can be set/cleared by eint,dint,reti,retid instructions.
       |    2-3 | Interrupt Mask (bit0-1) |
       |      4 | "Is rN zero" Flag       | Affected by modr, norm instructions. When rN is modified, it is updated.
       |      5 | Limit Flag (?)          | This is some kind of weird overflow functionality.
       |      6 | Extension Flag          | Set if upper 4 bits of 36-bit register are not identical.
       |      7 | Carry Flag              | Set on 36-bit carry (also for shift+rot).
       |      8 | Overflow Flag           | Set on 36-bit overflow.
       |      9 | Normalized Flag (?)     | Set iff Z | (~E & (3<<30))
       |     10 | Minus Flag              | Set iff bit35 of output is set.
       |     11 | Zero Flag               | Set iff output equals zero. Also set by tst0, tst1, tstb.
       |  12-15 | a0e
     */

    /*
      st1 structure:
       | Bit    | Description                | Notes
       +--------+----------------------------+------
       |    0-7 | Page (high 8-bits of addr) | Can be set by load,lpg instructions.
       |    8-9 | Reserved (?)               |
       |  10-11 | Product Shifter Control    | Apply a shift to p-register outputs. 00=no,01=lsr#1,10=lsl#1,11=lsl#2
       |  12-15 | a1e
     */

    /*
      st2 structure:
       | Bit    | Description
       +--------+--------------
       |    0-5 | Modulo enable           | If N:th bit is set, it means "the modulo" will be applied for rN.
       |      6 | Interrupt Mask (bit2)   |
       |      7 | Shift Mode              | 0=arithmetic shift, 1=logic shift. Affects: shfc,shfi,moda,modb,movs,movsi.
       |    8-9 | User extensions OUTPUT  |
       |  10-11 | User extensions INPUT   | Read-only
       |     12 | Reserved                |
       |  13-15 | Interrupt Pending       | Set regardless of the active interrupt mask
     */

    u16 icr;
    /*
      icr structure:
       | Bit    | Description
       +--------+--------------
       |      0 | NMI Context-switching Enable
       |    1-3 | INT<1-3> Context-switching Enable
       |      4 | InLoop Flag (when interrupted), writing to this one can cause weird things
       |    5-7 | Block-repeat Counter state (when interrupted), COMPLICATED
    */


    u16 dvm; // HW breakpoint for data accesses. Debug register. Also used for TRAP/BI routine.
    u16 ext[4]; // External registers..

} r; // registers

#define ARITHMETIC_SHIFTMODE (r.st2 & (1<<7))


typedef struct {
    u8 rsa[0x100];
    u32 magic;
    u32 size;
    u16 layout;
    u16 unk;
    u8 unk2;
    u8 special_segment_type;
    u8 num_segments;
    u8 flags;
    u32 special_segment_base;
    u32 special_segment_size;
    u32 zero[2];

    struct {
        u32 offset;
        u32 base;
        u32 size;
        u8 unkk[3];
        u8 type;
        u8 sha256[0x20];
    } segments[10];
} DSP_Header;

u32 data_mappings[8];
u32 prog_mappings[8];


/* cpu status */
int  get_z() { return r.st0 & (1<<11); }
void set_z() { r.st0 |= (1<<11); }
void clr_z() { r.st0 &= ~(1<<11); }
int  get_m() { return r.st0 & (1<<10); }
void set_m() { r.st0 |= (1<<10); }
void clr_m() { r.st0 &= ~(1<<10); }
int  get_n() { return r.st0 & (1<<9); }
void set_n() { r.st0 |= (1<<9); }
void clr_n() { r.st0 &= ~(1<<9); }
int  get_v() { return r.st0 & (1<<8); }
void set_v() { r.st0 |= (1<<8); }
void clr_v() { r.st0 &= ~(1<<8); }
int  get_c() { return r.st0 & (1<<7); }
void set_c() { r.st0 |= (1<<7); }
void clr_c() { r.st0 &= ~(1<<7); }
int  get_e() { return r.st0 & (1<<6); }
void set_e() { r.st0 |= (1<<6); }
void clr_e() { r.st0 &= ~(1<<6); }
int  get_l() { return r.st0 & (1<<5); }
void set_l() { r.st0 |= (1<<5); }
void clr_l() { r.st0 &= ~(1<<5); }



/* ram */
u16 read16(u16 addr) { // data-bus
    printf("read16(): %04x\n", addr); // XXX: TODO
    return 0x0;
}

void write16(u16 addr, u16 val) { // data-bus
    printf("write16(): *%04x <- %04x\n", (unsigned int) addr, (unsigned int) val);
}

u16 read_pram(u16 addr) {
    return ram[addr]; // XXX: TODO
}

/* emu */
const char* cccc_str[] = { // conditions
    "",    ".eq", ".ne", ".gt",
    ".ge", ".lt", ".le", ".nn", // nn = normalize flag cleared
    ".c",   ".v", ".e",   ".l",
    ".nr",                      // r flag cleared (???)
    ".niu0", ".iu0", ".iu1"     // 3 user-input conditions
};

const char* moda_str[] = {
    "shr",  "shr4", "shl", "shl4",
    "ror",  "rol",  "clr", "RESERVED",
    "not",  "neg",  "rnd", "pacr",
    "clrr", "inc",  "dec", "copy"
};

const char* alm_str[] = {
    "or",     "and",    "xor",  "add",
    "tst0_a", "tst1_a", "cmp",  "sub",
    "msu",    "addh",   "addl", "subh",
    "subl",   "sqr",    "sqra", "cmpu"
};

const char* alu_str[] = {
    "or", "and", "xor", "add",
    "RESERVED", "RESERVED", "cmp", "sub"
};

const char* rrrrr_str[] = {
    "r0",   "r1",
    "r2",   "r3",
    "r4",   "r5",
    "rb",   "y" ,
    "st0",  "st1",
    "st2",  "p/ph",
    "pc",   "sp",
    "cfgi", "cfgj",
    "b0h",  "b1h",
    "b0l",  "b1l",
    "ext0", "ext1",
    "ext2", "ext3",
    "a0",   "a1",
    "a0l",  "a1l"
    "a0h",  "a1h"
    "lc",   "sv"
};

const char* AB_str[] = {
    "b0", "b1",
    "a0", "a1"
};

const char* modstt_str[] = {
    "stt0", "stt1", "stt2", "WRONG!",
    "mod0", "mod1", "mod2", "mod3"
};

#define BIT(x, n) \
    (((x)>>(n))&1)



// Sign extend from s16 to s36.
u64 se_1636(u16 in) {
    if(BIT(in, 15))
        return 0xFFFFF0000ull | in;

    return in;
}

// Apply rN post modification (0, +1, -1, +step).
void rN_post_mod(int rN, int type) {
    int step=0; // XXX: TODO

    switch(type) {
    case 0: return;
    case 1: r.r[rN]++; return;
    case 2: r.r[rN]--; return;
    case 3: printf("TODO: rN_post_mod step\n"); r.r[rN]+=step; return;
    }

    printf("Warning: Unknown rN mod.\n");
}

u64 get_rrrrr_reg(int rrrrr) {
    switch(rrrrr) {
    case 0: case 1: case 2: case 3: case 4: case 5:
        return r.r[rrrrr];
    case 6:  return r.rb;
    case 7:  return r.y;
    case 8:  return r.st0;
    case 9:  return r.st1;
    case 10: return r.st2;
    case 11: return r.p; // p/ph?
    case 12: return r.pc;
    case 13: return r.sp;
    case 14: return r.cfgi;
    case 15: return r.cfgj;
    case 16: return (r.b0 >> 16) & 0xFFFF;
    case 17: return (r.b1 >> 16) & 0xFFFF;
    case 18: return r.b0 & 0xFFFF;
    case 19: return r.b1 & 0xFFFF;
    case 20: case 21: case 22: case 23:
        return r.ext[rrrrr-20];
    case 24: return r.a0;
    case 25: return r.a1;
    case 26: return r.a0 & 0xFFFF;
    case 27: return r.a1 & 0xFFFF;
    case 28: return (r.a0>>16) & 0xFFFF;
    case 29: return (r.a1>>16) & 0xFFFF;
    case 30: return r.lc;
    case 31: return r.sv;
    }
}

// Sign extension on 16-bit regs, nothing on 36-bit regs.
u64 get_rrrrr_reg_se(int rrrrr) {
    switch(rrrrr) {
    case 0: case 1: case 2: case 3: case 4: case 5:
        return se_1636(r.r[rrrrr]);
    case 6:  return se_1636(r.rb);
    case 7:  return se_1636(r.y);
    case 8:  return se_1636(r.st0);
    case 9:  return se_1636(r.st1);
    case 10: return se_1636(r.st2);
    case 11: return r.p; // XXX: Sign extend s32 -> s36?
    case 12: return se_1636(r.pc);
    case 13: return se_1636(r.sp);
    case 14: return se_1636(r.cfgi);
    case 15: return se_1636(r.cfgj);
    case 16: return se_1636((r.b0 >> 16) & 0xFFFF);
    case 17: return se_1636((r.b1 >> 16) & 0xFFFF);
    case 18: return se_1636(r.b0 & 0xFFFF);
    case 19: return se_1636(r.b1 & 0xFFFF);
    case 20: case 21: case 22: case 23:
        return se_1636(r.ext[rrrrr-20]);
    case 24: return r.a0;
    case 25: return r.a1;
    case 26: return se_1636(r.a0 & 0xFFFF);
    case 27: return se_1636(r.a1 & 0xFFFF);
    case 28: return se_1636((r.a0>>16) & 0xFFFF);
    case 29: return se_1636((r.a1>>16) & 0xFFFF);
    case 30: return se_1636(r.lc);
    case 31: return se_1636(r.sv);
    }
}

void set_rrrrr_reg(int rrrrr, u64 val) {
    switch(rrrrr) {
    case 0: case 1: case 2: case 3: case 4: case 5:
        r.r[rrrrr] = val;
        break;
    case 6: r.rb = val;    break;
    case 7: r.y = val;     break;
    case 8: r.st0 = val;   break;
    case 9: r.st1 = val;   break;
    case 10: r.st2 = val;  break;
    case 11: r.p = val;    break; // p/ph?
    case 12: r.pc = val;   break;
    case 13: r.sp = val;   break;
    case 14: r.cfgi = val; break;
    case 15: r.cfgj = val; break;
    case 16:
        r.b0 &= ~0xFFFF0000ull;
        r.b0 |= (val & 0xFFFF) << 16;
        break;
    case 17:
        r.b1 &= ~0xFFFF0000ull;
        r.b1 |= (val & 0xFFFF) << 16;
        break;
    case 18:
        r.b0 &= ~0xFFFFull;
        r.b0 |= val & 0xFFFF;
        break;
    case 19:
        r.b1 &= ~0xFFFFull;
        r.b1 |= val & 0xFFFF;
        break;
    case 20: case 21: case 22: case 23:
        r.ext[rrrrr-20] = val;
        break;
    case 24: r.a0 = val & 0xFFFFFFFFFull; break;
    case 25: r.a1 = val & 0xFFFFFFFFFull; break;
    case 26:
        r.a0 = (val & 0xFFFF) | (r.a0 & 0xF00000000ull);
        // Maybe: r.a0 = (val & 0xFFFF)
        break;
    case 27:
        r.a1 = (val & 0xFFFF) | (r.a1 & 0xF00000000ull);
        // Maybe: r.a1 = (val & 0xFFFF)
        break;
    case 28:
        r.a0 = ((val & 0xFFFF) << 16) | (r.a0 & 0xF00000000ull);
        // Maybe: r.a0 = (val & 0xFFFF) << 16
        break;
    case 29:
        r.a1 = ((val & 0xFFFF) << 16) | (r.a1 & 0xF00000000ull);
        // Maybe: r.a0 = (val & 0xFFFF) << 16
        break;
    case 30: r.lc = val; break;
    case 31: r.sv = val; break;
    }
}

bool check_cccc(int cccc) {
    switch(cccc) {
    case  0: return true;
    case  1: return  get_z();
    case  2: return !get_z();
    case  3: return !get_m() && !get_z();
    case  4: return !get_m();
    case  5: return  get_m();
    case  6: return  get_m() || get_z();
    case  7: return !get_n();
    case  8: return  get_v();
    case  9: return  get_c();
    case 10: return  get_e();
    case 11: return  get_l();
    }

    printf("TODO: nr, niu0, iu0, iu1 condition.\n");
    return true;
}

void set_ezm_flags_on_aX(u64 aX) {
    // Extension flag
    u64 aXe = (aX & 0xF00000000ull) >> 32;
    if((aXe == 0xF) || (aXe == 0)) clr_e(); else set_e();

    // Zero flag
    if(aX == 0) set_z(); else clr_z();

    // Minus flag
    if(aX & (1ull<<35)) set_m(); else clr_m();
}

void set_ezmn_flags_on_aX(u64 aX) {
    set_ezm_flags_on_aX(aX);

    // Normalized flag
    if(get_z() || (!get_e() && (((aX>>31)&1) == ((aX>>30)&1)))) set_n();
    else clr_n();
}

void alm_op(int op, u64 val, u64 val_se, bool A) {
    u64* aX = A ? (&r.a1) : (&r.a0);
    printf("alm_op(), op=%x\n", (unsigned int) op);

    switch(op) {
    case 0: // or
        *aX |= val;
        set_ezmn_flags_on_aX(*aX);
        return;
    case 1: // and
        *aX |= val;
        set_ezm_flags_on_aX(*aX);
        return;
    case 2:
        *aX ^= val;
        set_ezmn_flags_on_aX(*aX);
        return;
    case 3:
        *aX = (*aX + val_se) & 0xFFFFFFFFFull; // XXX: V,C,L flags
        set_ezmn_flags_on_aX(*aX);
        return;
    case 4:
        printf("tst0_a\n");
        return;
    case 5:
        printf("tst1_a\n");
        return;
    case 6:
        printf("cmp\n");
        return;
    case 7:
        printf("sub\n");
        return;
    case 8:
        printf("msu\n");
        return;
    case 9:
        // XXX: fix this
        *aX = (*aX + ((val & 0xFFFF) << 16)) & 0xFFFFFFFFFull; // XXX: V,C,L flags
        set_ezmn_flags_on_aX(*aX);
        return;
    case 10:
        // XXX: fix this
        *aX = (*aX + (val & 0xFFFF)) & 0xFFFFFFFFFull; // XXX: V,C,L flags
        set_ezmn_flags_on_aX(*aX);
        return;
    case 11:
        // XXX: fix this
        *aX = (*aX - ((val & 0xFFFF) << 16)) & 0xFFFFFFFFFull; // XXX: V,C,L flags
        set_ezmn_flags_on_aX(*aX);
        return;
    case 12:
        // XXX: fix this
        *aX = (*aX - (val & 0xFFFF)) & 0xFFFFFFFFFull; // XXX: V,C,L flags
        set_ezmn_flags_on_aX(*aX);
        return;
    case 13:
        printf("sqr\n");
        return;
    case 14:
        printf("sqra\n");
        return;
    case 15: // cmpu
        // XXX: fix this
        set_ezmn_flags_on_aX(*aX - val);
        return;
    }
}

void alu_op(int op, u16 val, bool A) {
    u64* aX = A ? (&r.a1) : (&r.a0);
    printf("alm_op(), op=%x\n", (unsigned int) op);

    switch(op) {
    case 0: // or
        return;
    case 1: // and
        return;
    case 2: // xor
        return;
    case 3: // add
        return;
    case 6: // cmp
        return;
    case 7: // sub
        return;
    }

    printf("DSP WARNING: undefined ALU op\n");
}

int run_dsp() {
    /*
      Different instruction addressing modes:

      (1) The opcode contains the lower 8 bits of data-addr,
          the st1 register contains the upper 8 bits.
          Together, they form a 16-bit address for data-ram.

      (2) The opcode contains a 16-bit data-addr directly.

      (3) rN registers are 16-bit addresses directly into X/Y-mem.
          Zmem not supported. Note: Pmem can be read!!

      (4) rb register can contain any 16-bit data-addr. 
    */
    u16 opc = read_pram(r.pc++);
    printf("%04x | %02x %02x  |  ", r.pc-1, opc & 0xFF, (opc>>8) & 0xFF);

    int A        = (opc&0x100) ? 1 : 0;
    int dddddddd =  opc & 0xFF;
    int XXXX     = (opc>>9) & 0xF;
    int XXX      = (opc>>9) & 0x7;
    int nnn      =  opc & 0x7;
    int mm       = (opc>>3) & 3;
    int rrrrr    =  opc & 0x1F;
    int cccc     =  opc & 0xF;
    int ooooooo  = (opc>>4) & 0x7F;
    int ooooooo_ =  opc & 0x7F;
    int f        = (opc>>4) & 1;
    int vvvvvvvv =  opc & 0xFF;
    int ffff     = (opc>>4) & 0xF;
    int A_       = (opc>>12) & 1;
    int AB       = (opc>>5) & 3;
    int modstt   = opc & 7;

    /*_______________________________________________________________________*/
    /*___ alu+multiplier ____________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xE000) == 0xA000) { // ALM direct
        // Load address higher-bits from st1 status register.
        u16 addr = ((r.st1&0xFF) << 8) | dddddddd;
        printf("%s [0x%04x], a%d\n", alm_str[XXXX], addr, A);

        alm_op(XXXX, read16(addr), se_1636(read16(addr)), A);
        return 0;
    }
    if((opc & 0xE0E0) == 0x8080) { // ALM (rN)
        if(nnn < 6) {
            u16 deref = read16(r.r[nnn]);
            printf("%s (r%d), a%d      ;; (r%d) = (0x%04x) = 0x%04x\n",
                alm_str[XXXX], nnn, A, nnn, r.r[nnn] & 0xFFFF, deref & 0xFFFF);

            alm_op(XXXX, deref, se_1636(deref), A);
            rN_post_mod(nnn, mm);
            return 0;
        }
    }
    if((opc & 0xE0E0) == 0x8090) { // ALM register
        printf("%s r%d, a%d            ;; r%d = 0x%02x\n",
            alm_str[XXXX], nnn, rrrrr_str[rrrrr], nnn, r.r[nnn] & 0xFFFF);

        alm_op(XXXX, get_rrrrr_reg(rrrrr), get_rrrrr_reg_se(rrrrr), A);
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ alu _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xF000) == 0xC000) { // ALU #short imm
        printf("%s #0x%02x, a%d\n", alu_str[XXX], vvvvvvvv, A);
        alu_op(XXX, vvvvvvvv, A);
        return 0;
    }
    if((opc & 0xF0E0) == 0x80C0) { // ALU ##long imm
        if(opc & 0xF) {
            printf("DSP WARNING: reserved bits are set!\n");
        }

        u16 imm = read_pram(r.pc++);
        printf("%s #0x%04x, a%d\n", alu_str[XXX], imm & 0xFFFF, A);

        alu_op(XXX, imm, A);
        return 0;
    }
    if((opc & 0xF080) == 0x4000) { // ALU (rb+#offset7), aX
        if(BIT(ooooooo_, 7)) ooooooo_ |= 0xFF80; // sign extension
        printf("%s (rb+#0x%02x), a%d\n", alu_str[XXX], ooooooo_, A);

        alu_op(XXX, read16(r.rb+ooooooo_), A);
        return 0;
    }
    if((opc & 0xFEF8) == 0xD4D8) { // ALU (rb+##offset), aX
        u16 off = read_pram(r.pc++);
        printf("%s (rb+#0x%04x), a%d\n", alu_str[XXX], off & 0xFFFF, A);

        alu_op(XXX, read16(r.rb+off), A);
        return 0;
    }
    if((opc & 0xFEF8) == 0xD4F8) { // ALU [##direct add.],aX
        u16 direct = read_pram(r.pc++);
        printf("%s #0x%02, a%d\n", alu_str[XXX], direct & 0xFFFF, A);

        alu_op(XXX, read16(direct), A);
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ modify aX _________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xEF00) == 0x6700) { // moda
        printf("%s%s a%d %s\n", moda_str[ffff], cccc_str[cccc], A_, check_cccc(cccc) ? "" : "(skipped)");

        if(!check_cccc(cccc))
            return 0;

        u64* aX = A_ ? (&r.a1) : (&r.a0);

        switch(ffff) {
        case 0: // shr
            if(BIT(*aX, 0)) set_c(); else clr_c(); // carry flag

            if(ARITHMETIC_SHIFTMODE) {
                if(BIT(*aX, 35)) *aX = (1ull<<35) | (*aX>>1);
                else *aX = *aX>>1;

                clr_v(); // overflow flag
            }
            else {
                *aX = *aX>>1;
            }

            set_ezmn_flags_on_aX(*aX);
            break;

        case 1: // shr4
            if(BIT(*aX, 3)) set_c(); else clr_c(); // carry flag

            if(ARITHMETIC_SHIFTMODE) {
                if(BIT(*aX, 35)) *aX = (0xFull<<32) | (*aX>>4);
                else *aX = *aX>>4;

                clr_v(); // overflow flag
            }
            else {
                *aX = *aX>>4;
            }

            set_ezmn_flags_on_aX(*aX);
            break;

        case 2: // shl
            if(BIT(*aX, 35)) { set_c(); if(ARITHMETIC_SHIFTMODE) set_l(); } else clr_c(); // carry flag
            if(BIT(*aX, 35) != BIT(*aX, 34)) set_v(); else clr_v(); // overflow flag

            *aX = (*aX<<1) & 0xFFFFFFFFFull;
            set_ezmn_flags_on_aX(*aX);
            break;

        case 3: // shl4
            if(BIT(*aX, 32)) set_c(); else clr_c(); // carry flag
            if(BIT(*aX, 32) != BIT(*aX, 31)) set_v(); else clr_v(); // overflow flag (?)
            if(ARITHMETIC_SHIFTMODE && (*aX & 0xF00000000ull)) set_l();

            *aX = (*aX<<4) & 0xFFFFFFFFFull;
            set_ezmn_flags_on_aX(*aX);
            break;

        case 4: // ror
            if(BIT(*aX, 0)) set_c(); else clr_c();

            *aX = (*aX>>1) | (BIT(*aX, 0)<<35);
            set_ezmn_flags_on_aX(*aX);
            break;

        case 5: // rol
            if(BIT(*aX, 35)) set_c(); else clr_c();

            *aX = (*aX<<1) | BIT(*aX, 35);
            set_ezmn_flags_on_aX(*aX);
            break;

        case 6: // clr
            *aX = 0;
            set_ezmn_flags_on_aX(*aX);
            break;

        case 7: // reserved
            printf("RESERVED!\n");
            return 1;

        case 8: // not
            *aX = (~*aX) & 0xFFFFFFFFFull;
            set_ezmn_flags_on_aX(*aX);
            break;

        case 9: // neg
            *aX = ((~*aX) + 1) & 0xFFFFFFFFFull;
            set_ezmn_flags_on_aX(*aX); // TODO: V,C,L flags
            break;

        case 10: // round
            printf("round (TODO)\n");
            return 1;

        case 11: // pacr
            printf("pacr (TODO)\n");
            return 1;

        case 12: // clrr
            *aX = 0x8000;
            set_ezmn_flags_on_aX(*aX);
            break;

        case 13: // inc
            *aX = (*aX + 1) & 0xFFFFFFFFFull;
            set_ezmn_flags_on_aX(*aX); // TODO: V,C,L flags
            break;

        case 14: // dec
            if(*aX == 0)
                *aX = 0xFFFFFFFFFull;
            else
                *aX = *aX - 1;
            set_ezmn_flags_on_aX(*aX); // TODO: V,C,L flags
            break;

        case 15: // copy
            *aX = *aX;
            set_ezmn_flags_on_aX(*aX);
            break;
        }

        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ norm ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFEC0) == 0x94C0) {
        if(BIT(opc, 5)) {
            printf("DSP WARNING: reserved bit was set!\n");
        }

        printf("norm (TODO)\n");
        return 1;
    }

    /*_______________________________________________________________________*/
    /*___ divs ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFE00) == 0x0E00) {
        printf("divs (TODO)\n");
        return 1;
    }

    /*_______________________________________________________________________*/
    /*___ alb _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xF1E0) == 0x80E0) {
        printf("alb instruction (TODO)\n"); // (rN)
        return 1;
    }
    if((opc & 0xF1E0) == 0x81E0) {
        printf("alb instruction (TODO)\n"); // register
        return 1;
    }
    if((opc & 0xF100) == 0xE100) {
        printf("alb instruction (TODO)\n"); // direct
        r.pc++;//XXX
        return 1;
    }

    /*_______________________________________________________________________*/
    /*___ maxd ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFCE0) == 0x8060) {
        if(opc & 7) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("maxd (TODO)\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ max _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFCE0) == 0x8460) {
        if(opc & 7) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("max (TODO)\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ min _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xF8E0) == 0x8860) {
        if((opc & 7) || BIT(opc, 10)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("min (TODO)\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ lim _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFFC0) == 0x49C0) {
        if(opc & 15) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("lim (TODO)\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ mul _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xF0E0) == 0x8020) { // y, (rN)
        printf("mul (TODO)\n");
        return 0;
    }
    if((opc & 0xF0E0) == 0x8040) { // y, register
        printf("mul (TODO)\n");
        return 0;
    }
    if((opc & 0xF080) == 0xD000) { // (rJ, rI)
        printf("mul (TODO)\n");
        return 0;
    }
    if((opc & 0xF080) == 0xD000) { // (rN), #long imm
        printf("mul (TODO)\n");
        r.pc++;//XXX
        return 0;
    }
    if((opc & 0xF100) == 0xE000) { // y, direct addr
        printf("mul (TODO)\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ mpyi ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFF00) == 0x0800) {
        printf("mpyi (TODO)\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ msu _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFEC0) == 0x90C0) { // (rN), ##long imm
        if(BIT(opc, 7)) {
            printf("DSP WARNING: reversed bit was set!\n");
        }

        printf("msu (TODO)\n");
        r.pc++;//XXX
        return 0;
    }
    if((opc & 0xFE80) == 0xD080) {
        printf("msu (TODO)\n"); // (rJ), (rI)
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ tstb ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xF0E0) == 0x9020) {
        printf("tstb (TODO)\n"); // (rN)
        return 0;
    }
    if((opc & 0xF0E0) == 0x9000) {
        printf("tstb (TODO)\n"); // register
        return 0;
    }
    if((opc & 0xF000) == 0xF000) {
        printf("tstb (TODO)\n"); // direct address
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ shfc ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xF390) == 0xD280) {
        printf("shfc (TODO)\n"); 
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ shfi ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xF240) == 0x9240) {
        printf("shfi (TODO)\n"); 
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ modb ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xEF00) == 0x6F00) {
        if(BIT(opc, 7)) {
            printf("DSP WARNING: reserved bit was set!\n");
        }

        printf("modb (TODO)\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ exp _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFEC0) == 0x9840) { // (rN), aX
        if(BIT(opc, 5)) {
            printf("DSP WARNING: reserved bit was set!\n");
        }

        printf("exp (TODO)\n");
        return 0;
    }
    if((opc & 0xFEE0) == 0x9040) { // register, aX
        printf("exp (TODO)\n");
        return 0;
    }
    if((opc & 0xFEE0) == 0x9060) { // bX, aX
        if((opc >> 1) & 0xF) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("exp (TODO)\n");
        return 0;
    }
    if((opc & 0xFEC0) == 0x9C40) { // (rN), sv
        if(BIT(opc, 5) || BIT(opc, 8)) {
            printf("DSP WARNING: reserved bit was set!\n");
        }

        printf("exp (TODO)\n");
        return 0;
    }
    if((opc & 0xFEE0) == 0x9440) { // register, sv
        if(BIT(opc, 8)) {
            printf("DSP WARNING: reserved bit was set!\n");
        }

        printf("exp (TODO)\n");
        return 0;
    }
    if((opc & 0xFEE0) == 0x9460) { // bx, sv
        if(BIT(opc, 8)) {
            printf("DSP WARNING: reserved bit was set!\n");
        }

        printf("exp (TODO)\n");
        return 0;
    }

    /*___ mov ________________________________________________________________*/
    if((opc & 0xFC00) == 0x5800) { // register, register
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xF398) == 0xD290) { // ab, AB
        if(opc & 0x7) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xF3D8) == 0xD298) { // ABI, dvm
        if(opc & 0x7 || BIT(opc, 6)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xF3D8) == 0xD2D8) { // ABI, x
        if(opc & 0x7 || BIT(opc, 6)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFFC0) == 0x5EC0) { // register, bX
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFFC0) == 0x5E80) { // register, mixp
        if(BIT(opc, 6)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFC00) == 0x1800) { // register, (rN)
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFFE0) == 0x47C0) { // mixp, register
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFE9B) == 0xD490) { // repc, AB
        if(BIT(opc, 3) || BIT(opc, 8)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFE9B) == 0xD491) { // dvm, AB
        if(BIT(opc, 3) || BIT(opc, 8)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFE9B) == 0xD492) { // icr, AB
        if(BIT(opc, 3) || BIT(opc, 8)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFE9B) == 0xD493) { // x, AB
        if(BIT(opc, 3) || BIT(opc, 8)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFC00) == 0x1C00) { // (rN), register)
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFEC0) == 0x98C0) { // (rN), bX
        if(BIT(opc, 5)) {
            printf("DSP WARNING: reserved bits were set!\n");
        }

        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFFE0) == 0x47E0) { // (sp), register
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xF100) == 0x2000) { // rN*, direct
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xF100) == 0x3000) { // ABLH, direct
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xE300) == 0x6000) { // direct, rN*
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xE700) == 0x6100) { // direct, AB
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xE300) == 0x6200) { // direct, ABLH
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xEF00) == 0x6500) { // direct, aXHeu
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFF00) == 0x6D00) { // direct, sv
        printf("mov (TODO)\n");
        return 0;
    }
    if((opc & 0xFF00) == 0x7D00) { // sv, direct
        printf("mov (TODO)\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ branch absolute ___________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFFC0) == 0x4180) {
        printf("br%s 0x%04x %s\n", cccc_str[cccc], read_pram(r.pc), check_cccc(cccc) ? "" : "(skipped)");

        if(check_cccc(cccc))
            r.pc = read_pram(r.pc);
        else r.pc++;

        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ branch relative ___________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xF800) == 0x5000) {
        printf("brr%s 0x%04x %s\n", cccc_str[cccc], r.pc+ooooooo, check_cccc(cccc) ? "" : "(skipped)");

        // XXX: sign extension on ooooooo?
        if(check_cccc(cccc))
            r.pc += ooooooo;
        else r.pc++;

        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ nop _______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & (~0x1F)) == 0) {
        printf("nop\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ trap ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if(opc == 0x0020) {
        // XXX: TODO
        printf("trap\n");
        r.pc = 2;
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ cntx ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFFC0) == 0xD380) {
        // XXX: TODO
        printf("cntx\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ enable interrupt __________________________________________________*/
    /*_______________________________________________________________________*/

    if(opc == 0x4380) {
        r.st0 |= 2;
        printf("eint\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ disable interrupt _________________________________________________*/
    /*_______________________________________________________________________*/

    if(opc == 0x43C0) {
        r.st0 &= ~2;
        printf("dint\n");
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ modify rN _________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFF80) == 0x80) {
        // XXX: TODO
        printf("modr\n");

        if(opc & (1<<5)) { // disable modulo

        }
        else {

        }

        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ mov pp (unknown reg) ______________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFFF8) == 0x0030) {
        u16 imm = read_pram(r.pc++);
        // XXX: TODO
        printf("mov #0x%04x, %s\n", imm & 0xFFFF, modstt_str[modstt]);
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ move shifted ______________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFF80) == 0x0100) { 
        printf("movs %s, %s\n", rrrrr_str[rrrrr], AB_str[AB]);

        u64* ab;

        switch(AB) {
        case 0: ab = &r.b0; break;
        case 1: ab = &r.b1; break;
        case 2: ab = &r.a0; break;
        case 3: ab = &r.a1; break;
        }

        s16 sv = r.sv; // sign value

        if((sv >= 0) && (sv <= 36)) {
            // XXX: Sign extension on rrrrr value!!
            *ab = get_rrrrr_reg(rrrrr) << sv;
            // XXX: flags
            return 0;
        }
        else if((sv < 0) && (sv >= -36)) {
            // XXX: Sign extension on rrrrr value!!
            *ab = get_rrrrr_reg(rrrrr) >> -sv;
            // XXX: flags
            return 0;
        }

        printf("mov shifted: weird sv value.\n");
        return 1;
    }

    /*_______________________________________________________________________*/
    /*___ move ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFFE0) == 0x5E00) {
        u16 imm = read_pram(r.pc++);
        printf("mov #0x%04x, %s (todo)\n", imm & 0xFFFF, rrrrr_str[rrrrr]);
        // XXX: TODO
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ reset bitfield ____________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFFF8) == 0x4388) {
        u16 imm = read_pram(r.pc++);
        printf("rst #0x%04x, %s (todo)\n", imm & 0xFFFF, modstt_str[modstt]);
        // XXX: TODO
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ call ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFFC0) == 0x41C0) {
        u16 imm = read_pram(r.pc++);
        printf("call%s 0x%04x\n", cccc_str[cccc], imm, check_cccc(cccc) ? "" : "(skipped)");
        r.sp--;
        write16(r.sp, pc);
        r.pc = imm;
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ addv ______________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFFE0) == 0x87E0) {
        u16 imm = read_pram(r.pc++);
        printf("addv #0x%04x, %s (todo)\n", imm & 0xFFFF, rrrrr_str[rrrrr]);
        // XXX: TODO
        return 0;
    }

    /*_______________________________________________________________________*/
    /*___ load page _________________________________________________________*/
    /*_______________________________________________________________________*/

    if((opc & 0xFF00) == 0x0400) {
        printf("load #0x%04x, st1.page\n", vvvvvvvv << 8);

        // Set lower 8 bits of st1 register.
        r.st1 &= ~0xFF;
        r.st1 |= vvvvvvvv;
        return 0;
    }



    printf("Unknown op: %04x\n", read_pram(r.pc-1));
    return 1;
}


int load_firm(u8* p, size_t len) {
    DSP_Header* hdr = (DSP_Header*) p;

    if(len < sizeof(DSP_Header))
        return 1;
    if(memcmp(&hdr->magic, "DSP1", 4) != 0)
        return 2;
    if(hdr->size > len)
        return 3;

    size_t i;
    printf("Memory layout:\n");
    for(i=0; i<8; i++) {
        if((1<<i) & hdr->layout)
            printf("   0x%08x [PROGRAM]\n", 0x1FF00000 + 0x8000*i);
    }
    for(i=8; i<16; i++) {
        if((1<<i) & hdr->layout)
            printf("   0x%08x [DATA]\n", 0x1FF00000 + 0x8000*i);
    }
    printf("\n");

    printf("Special segment:\n");
    printf("   type: %d\n",   hdr->special_segment_type & 0xFF);
    printf("   base: 0x%x\n", hdr->special_segment_base & 0xFFFFFFFF);
    printf("   size: 0x%x\n", hdr->special_segment_size & 0xFFFFFFFF);
    printf("\n");

    if(hdr->num_segments > 10)
        return 4;

    for(i=0; i<hdr->num_segments; i++) {
        printf("Segment %d:\n", i);
        //printf("   offset: 0x%x\n", hdr->segments[i].offset);
        printf("   base:   0x%x\n", hdr->segments[i].base);
        printf("   size:   0x%x\n", hdr->segments[i].size);
        u8 type = hdr->segments[i].type & 0xFF;
        const char* type_s = "";

        switch(type) {
        case 0:
            memcpy(&ram[hdr->segments[i].base],
                   p + hdr->segments[i].offset,
                   hdr->segments[i].size);
            type_s = "PROGRAM";
            break;
        case 2:
            memcpy(&ram[hdr->segments[i].base+RAM_SIZE/4],
                   p + hdr->segments[i].offset,
                   hdr->segments[i].size);
            type_s = "DATA";
            break;
        default:
            printf("Unknown type 0x%x\n", type);
            return 5;
        }

        printf("   type:   %x (%s)\n", type, type_s);
    }
    printf("\n");

    return 0;
}

void init() {
    r.pc = 0;
    memset(ram, 0, sizeof(ram));
    memset(&r, 0, sizeof(r));
}


int main(int argc, char* argv[]) {
    if(argc != 2) {
        printf("%s <firm.bin>\n", argv[0]);
        return 1;
    }

    FILE* fd = fopen(argv[1], "rb");
    if(fd == NULL) {
        perror("fopen");
        return 1;
    }

    fseek(fd, 0, SEEK_END);

    size_t len = ftell(fd);
    char* p = malloc(len);

    if(p == NULL) {
        perror("malloc");
        fclose(fd);
        return 1;
    }

    fseek(fd, 0, SEEK_SET);
    fread(p, len, 1, fd);
    fclose(fd);

    if(!load_firm(p, len)) {
        while(1) {
            if(run_dsp())
                break;

            fgetc(stdin); // wait for user input
        }
    }
    else {
        printf("Failed to load firm.\n");
    }

    free(p);
    return 0;
}
