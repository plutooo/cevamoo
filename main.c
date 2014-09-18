#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

#define RAM_SIZE 0x800000

static u16 ram[RAM_SIZE];
static u16 pc;

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


int run_dsp() {
    pc = 0;

    printf("Op: %04x\n", ram[pc] & 0xFFFF);

    switch(ram[pc]) {

    }
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
        printf("   type:   0x%x\n", hdr->segments[i].type & 0xFF);

        u8 type = hdr->segments[i].type;
        switch(type) {
        case 0:
            memcpy(ram+hdr->segments[i].base, p+hdr->segments[i].offset,
                   hdr->segments[i].size);
            break;
        case 2:
            memcpy(ram+hdr->segments[i].base+RAM_SIZE/4, p+hdr->segments[i].offset,
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

    printf("load_firm: %d\n", load_firm(p, len));
    printf("run_dsp: %d\n", run_dsp());

    free(p);
    return 0;
}
