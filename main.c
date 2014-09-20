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
    u16 rb; // base ptr (segmentation?)

    u16 mixp; // wut?

    // "banked" r-registers
    u16 r0b, r1b, r4b;

    u16 pc;
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
int get_z() { return r.st0 & (1<<11); }
void set_z() { r.st0 |= (1<<11); }
void clr_z() { r.st0 &= ~(1<<11); }
int get_m() { return r.st0 & (1<<10); }
void set_m() { r.st0 |= (1<<10); }
void clr_m() { r.st0 &= ~(1<<10); }
int get_n() { return r.st0 & (1<<9); }
void set_n() { r.st0 |= (1<<9); }
void clr_n() { r.st0 &= ~(1<<9); }
int get_v() { return r.st0 & (1<<8); }
void set_v() { r.st0 |= (1<<8); }
void clr_v() { r.st0 &= ~(1<<8); }
int get_c() { return r.st0 & (1<<7); }
void set_c() { r.st0 |= (1<<7); }
void clr_c() { r.st0 &= ~(1<<7); }
int get_e() { return r.st0 & (1<<6); }
void set_e() { r.st0 |= (1<<6); }
void clr_e() { r.st0 &= ~(1<<6); }
int get_l() { return r.st0 & (1<<5); }
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

u64 get_reg_by_rrrrr(int rrrrr) {
    switch(rrrrr) {
    case 0: case 1: case 2: case 3: case 4: case 5:
        return r.r[rrrrr];
    case 6: return r.rb;
    case 7: return r.y;
    case 8: return r.st0;
    case 9: return r.st1;
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

void set_ezmn_flags_on_aX(u64 aX) {
    // Extension flag
    u64 aXe = (aX & 0xF00000000ull) >> 32;
    if((aXe == 0xF) || (aXe == 0)) clr_e(); else set_e();

    // Zero flag
    if(aX == 0) set_z(); else clr_z();

    // Minus flag
    if(aX & (1ull<<35)) set_m(); else clr_m();

    // Normalized flag
    if(get_z() || (!get_e() && (((aX>>31)&1) == ((aX>>30)&1)))) set_n(); else clr_n(); 
}

void alm_op(int op, u64 val, bool A) {
    printf("alm_op(), op=%x\n", (unsigned int) op);

    u64* aX = A ? (&r.a1) : (&r.a0);

    switch(op) {
    case 0:
        printf("or\n");
        return;
    case 1:
        printf("and\n");
        return;
    case 2:
        printf("xor\n");
        return;
    case 3:
        printf("add\n");
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
        printf("addh\n");
        return;
    case 10:
        printf("addl\n");
        return;
    case 11:
        printf("subh\n");
        return;
    case 12:
        printf("subl\n");
        return;
    case 13:
        printf("sqr\n");
        return;
    case 14:
        printf("sqra\n");
        return;
    case 15: // cmpu
        set_ezmn_flags_on_aX(*aX - val); // TODO
        return;
    }
}

int run_dsp() {
    /*
      Different instruction addressing modes:
      (1) The opcode contains the lower 8 bits of data-addr, the st1 register contains the upper 8 bits.
          Together, they form a 16-bit address for data-ram.
      (2) The opcode contains a 16-bit data-addr directly.
      (3) rN registers are 16-bit addresses directly into X/Y-mem. Zmem not supported. Note: Pmem can be read!!
      (4) rb register can contain any 16-bit data-addr. 
    */
    u16 opc = read_pram(r.pc++);
    printf("%04x | %02x %02x  | ", r.pc, opc & 0xFF, (opc>>8) & 0xFF);

    int A        = (opc&0x100) ? 1 : 0;
    int dddddddd =  opc & 0xFF;
    int ALM_XXXX = (opc>>9) & 0xF;
    int nnn      =  opc & 0x7;
    int mm       = (opc>>3) & 3;
    int rrrrr    =  opc & 0x1F;
    int cccc     =  opc & 0xF;
    int ooooooo  = (opc>>4) & 0x7F;
    int f        = (opc>>4) & 1;
    int vvvvvvvv =  opc & 0xFF;
    int ffff     = (opc>>4) & 0xF;
    int A_       = (opc>>12) & 1;
    int AB       = (opc>>5) & 3;
    int modstt = opc & 7;


    /*___ move shifted ______________________________________________________*/
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
            *ab = get_reg_by_rrrrr(rrrrr) << sv;
            // XXX: flags
            return 0;
        }
        else if((sv < 0) && (sv >= -36)) {
            // XXX: Sign extension on rrrrr value!!
            *ab = get_reg_by_rrrrr(rrrrr) >> -sv;
            // XXX: flags
            return 0;
        }

        printf("mov shifted: weird sv value.\n");
        return 1;
    }

    /*___ move ______________________________________________________________*/
    if((opc & 0xFFE0) == 0x5E00) {
        u16 imm = read_pram(r.pc++);
        printf("mov #0x%04x, %s\n", imm & 0xFFFF, rrrrr_str[rrrrr]);
        // XXX: TODO
        return 0;
    }

    /*___ reset bitfield ____________________________________________________*/
    if((opc & 0xFFF8) == 0x4388) {
        u16 imm = read_pram(r.pc++);
        printf("rst #0x%04x, %s\n", imm & 0xFFFF, modstt_str[modstt]);
        // XXX: TODO
        return 0;
    }

    /*___ call ______________________________________________________________*/
    if((opc & 0xFFC0) == 0x41C0) {
        u16 imm = read_pram(r.pc++);
        printf("call%s 0x%04x\n", cccc_str[cccc], imm, check_cccc(cccc) ? "" : "(skipped)");
        r.sp--;
        write16(r.sp, pc);
        r.pc = imm;
        return 0;
    }

    /*___ addv ______________________________________________________________*/
    if((opc & 0xFFE0) == 0x87E0) {
        u16 imm = read_pram(r.pc++);
        printf("addv #0x%04x, %s\n", imm & 0xFFFF, rrrrr_str[rrrrr]);
        // XXX: TODO
        return 0;
    }


    /*___ load page _________________________________________________________*/
    if((opc & 0xFF00) == 0x0400) {
        printf("load #0x%04x, st1.page\n", vvvvvvvv << 8);

        // Set lower 8 bits of st1 register.
        r.st1 &= ~0xFF;
        r.st1 |= vvvvvvvv;
        return 0;
    }

    /*___ alu+multiplier ____________________________________________________*/
    if((opc & 0xE000) == 0xA000) { // ALM
        // Load address higher-bits from st1 status register.
        u16 addr = ((r.st1&0xFF) << 8) | dddddddd;

        printf("%s a%d, [0x%04x]\n", alm_str[ALM_XXXX], A, addr);

        alm_op(ALM_XXXX, read16(addr), A);
        return 0;
    }

    /*___ alu+multiplier ____________________________________________________*/
    if((opc & 0xE0E0) == 0x8080) { // ALM
        if(nnn < 6) {
            alm_op(ALM_XXXX, read16(r.r[nnn]), A);
            rN_post_mod(nnn, mm);
            return 0;
        }
    }

    /*___ alu+multiplier ____________________________________________________*/
    if((opc & 0xE0E0) == 0x8090) { // ALM
        alm_op(ALM_XXXX, get_reg_by_rrrrr(rrrrr), A);
        return 0;
    }

    /*___ modify aX _________________________________________________________*/
    if((opc & 0xEF00) == 0x6700) { // moda
        printf("%s%s a%d %s\n", moda_str[ffff], cccc_str[cccc], A_, check_cccc(cccc) ? "" : "(skipped)");

        if(!check_cccc(cccc))
            return 0;

        u64* aX = A_ ? (&r.a1) : (&r.a0);

        switch(ffff) {
        case 0: // shr
            if(*aX & 1) set_c(); else clr_c(); // carry flag

            if(ARITHMETIC_SHIFTMODE) {
                if(*aX & (1ull<<35)) *aX = (1ull<<35) | (*aX>>1);
                else                 *aX = *aX>>1;
                // TODO: update L flag
            }
            else {
                *aX = *aX>>1;
            }

            clr_v(); // overflow flag
            set_ezmn_flags_on_aX(*aX);
            break;

        case 1: // shr4
            if(*aX & (1<<3)) set_c(); else clr_c(); // carry flag

            if(ARITHMETIC_SHIFTMODE) {
                if(*aX & (1ull<<35)) *aX = (0xFull<<32) | (*aX>>4);
                else                 *aX = *aX>>4;
                // TODO: update L flag
            }
            else {
                *aX = *aX>>4;
            }

            clr_v(); // overflow flag
            set_ezmn_flags_on_aX(*aX);
            break;

        case 2: // shl
            if(*aX & (1ull<<35)) set_c(); else clr_c(); // carry+overflow flag
            // TODO: V flag
            *aX = (*aX<<1) & 0xFFFFFFFFFull;
            // TODO: update L flag on arithmetic mode
            set_ezmn_flags_on_aX(*aX);
            break;

        case 3: // shl4
            if(*aX & (1ull<<32)) set_c(); else clr_c(); // carry flag
            // TODO: V flag
            *aX = (*aX<<4) & 0xFFFFFFFFFull;
            // TODO: update L flag on arithmetic mode
            set_ezmn_flags_on_aX(*aX);
            break;

        case 4: // ror
        case 5: // rol
            printf("ror/rol: TODO!\n");
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
            printf("round: TODO!\n");
            break;

        case 11: // pacr
            printf("pacr: TODO!\n");
            break;

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

    /*___ branch absolute ___________________________________________________*/
    if((opc & 0xFFC0) == 0x4180) {
        printf("br%s 0x%04x %s\n", cccc_str[cccc], read_pram(r.pc), check_cccc(cccc) ? "" : "(skipped)");

        if(check_cccc(cccc))
            r.pc = read_pram(r.pc);
        else r.pc++;

        return 0;
    }

    /*___ branch relative ___________________________________________________*/
    if((opc & 0xF800) == 0x5000) {
        printf("brr%s 0x%04x %s\n", cccc_str[cccc], r.pc+ooooooo, check_cccc(cccc) ? "" : "(skipped)");

        // XXX: sign extension on ooooooo?
        if(check_cccc(cccc))
            r.pc += ooooooo;
        else r.pc++;

        return 0;
    }

    /*___ nop _______________________________________________________________*/
    if((opc & (~0x1F)) == 0) {
        printf("nop\n");
        return 0;
    }

    /*___ trap ______________________________________________________________*/
    if(opc == 0x0020) {
        // XXX: TODO
        printf("trap\n");
        r.pc = 2;
        return 0;
    }

    /*___ cntx ______________________________________________________________*/
    if((opc & 0xFFC0) == 0xD380) {
        // XXX: TODO
        printf("cntx\n");
        return 0;
    }

    /*___ enable interrupt __________________________________________________*/
    if(opc == 0x4380) {
        // XXX: TODO
        printf("eint\n");
        return 0;
    }

    /*___ disable interrupt _________________________________________________*/
    if(opc == 0x43C0) {
        // XXX: TODO
        printf("dint\n");
        return 0;
    }

    /*___ modify rN _________________________________________________________*/
    if((opc & 0xFF80) == 0x80) {
        // XXX: TODO
        printf("modr\n");

        if(opc & (1<<5)) { // disable modulo

        }
        else {

        }

        return 0;
    }

    /*___ mov pp (unknown reg) ______________________________________________*/
    if((opc & 0xFFF8) == 0x0030) {
        u16 imm = read_pram(r.pc++);
        // TODO
        printf("mov #0x%04x, %s\n", imm & 0xFFFF, modstt_str[modstt]);
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
            printf("   0x%08x [A]\n", 0x1FF00000 + 0x8000*i);
    }
    for(i=8; i<16; i++) {
        if((1<<i) & hdr->layout)
            printf("   0x%08x [B]\n", 0x1FF00000 + 0x8000*i);
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
        printf("   offset: 0x%x\n", hdr->segments[i].offset);
        printf("   base:   0x%x\n", hdr->segments[i].base);
        printf("   size:   0x%x\n", hdr->segments[i].size);
        printf("   type:   %x\n", hdr->segments[i].type & 0xFF);

        u8 type = hdr->segments[i].type;
        switch(type) {
        case 0:
            memcpy(&ram[hdr->segments[i].base],
                   p + hdr->segments[i].offset,
                   hdr->segments[i].size);
            break;
        case 2:
            memcpy(&ram[hdr->segments[i].base+RAM_SIZE/4],
                   p + hdr->segments[i].offset,
                   hdr->segments[i].size);
            break;
        default:
            printf("Unknown type 0x%x\n", type);
            return 5;
        }
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
