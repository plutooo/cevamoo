#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef unsigned char u8;
typedef unsigned short u16;
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

    u16 sv;

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





u16 read16(u16 addr) { // data-bus
    printf("read16(): %04x\n", addr);
    return 0;
}

void write16(u16 addr, u16 val) { // data-bus
    printf("write16(): *%04x <- %04x\n", (unsigned int) addr, (unsigned int) val);
}

u16 read_pram(u16 addr) {
    return ram[addr]; // XXX: TODO
}


void alm_op(int op, u16 addr, bool a01) {
    // XXX: TODO
    printf("alm_op()\n");
}

void rN_post_mod(int rN, int type) {
    int step=0; // XXX: TODO

    switch(type) {
    case 0: return;
    case 1: r.r[rN]++; return;
    case 2: r.r[rN]--; return;
    case 3: r.r[rN]+=step; return;
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
    // XXX: TODO
    return true;
}

const char* cccc_str[] = {
    "al", "eq", "ne", "gt",
    "ge", "lt", "le", "nn",
    "c", "v", "e", "l",
    "nr", "niu0", "iu0", "iu1"
};

int run_dsp() {
    /*
      Different instruction addressing modes:
      (1) The opcode contains the lower 8 bits of data-addr, the st1 register contains the upper 8 bits.
          Together, they form a 16-bit address for data-ram.
      (2) The opcode contains a 16-bit data-addr directly.
      (3) rN registers are 16-bit addresses directly into X/Y-mem. Zmem not supported. Note: Pmem can be read!!
      (4) rb register can contain any 16-bit data-addr. 
    */
    printf("%04x: ", r.pc);
    u16 opc = read_pram(r.pc++);

    int A = (opc&0x100) ? 1 : 0;
    int dddddddd = opc & 0xFF;
    int ALM_XXXX = (opc>>9) & 0xF;
    int nnn = opc & 0x7;
    int mm = (opc>>3) & 3;
    int rrrrr = opc & 0x1F;
    int cccc = opc & 0xF;
    int ooooooo = (opc>>4) & 0x7F;
    int f = (opc>>4) & 1;

    if((opc & 0xE000) == 0xA000) {
        // Load address higher-bits from st1 status register.
        u16 addr = ((r.st1&0xFF) << 8) | dddddddd;

        alm_op(ALM_XXXX, read16(addr), A);
        return 0;
    }
    if((opc & 0xE0E0) == 0x8080) {
        if(nnn < 6) {
            alm_op(ALM_XXXX, read16(r.r[nnn]), A);
            rN_post_mod(nnn, mm);
            return 0;
        }
    }
    if((opc & 0xE0E0) == 0x8090) {
        alm_op(ALM_XXXX, get_reg_by_rrrrr(rrrrr), A);
        return 0;
    }
    if((opc & 0xFFC0) == 0x4180) { // branch absolute
        printf("br.%s 0x%04x\n", cccc_str[cccc], read_pram(r.pc));

        if(check_cccc(cccc))
            r.pc = read_pram(r.pc);
        else r.pc++;

        return 0;
    }
    if((opc & 0xF800) == 0x5000) { // branch relative
        printf("brr.%s 0x%04x\n", cccc_str[cccc], r.pc+ooooooo);

        // XXX: sign extension on ooooooo?
        if(check_cccc(cccc))
            r.pc += ooooooo;
        else r.pc++;

        return 0;
    }
    if((opc & (~0x1F)) == 0) {
        printf("nop\n");
        return 0;
    }
    if((opc & (~0x1F)) == 0x20) {
        // XXX: TODO
        printf("trap\n");
        r.pc = 2;
        return 0;
    }
    if((opc & 0xFFC0) == 0xD380) { // cntx
        // XXX: TODO
        printf("cntx\n");
        return 0;
    }
    if((opc & 0xFFC0) == 0x4380) {
        // XXX: TODO
        printf("eint\n");
        return 0;
    }
    if((opc & 0xFFC0) == 0x43C0) {
        // XXX: TODO
        printf("dint\n");
        return 0;
    }
    if((opc & 0xFF80) == 0x80) {
        // XXX: TODO
        printf("modr\n");

        if(opc & (1<<5)) { // disable modulo

        }
        else {

        }

        return 0;
    }
    //0000 0000 1.fmmnnn

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
