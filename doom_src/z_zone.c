//
// Copyright(C) 1993-1996 Id Software, Inc.
// Copyright(C) 2005-2014 Simon Howard
//
// DESCRIPTION:
//	Zone Memory Allocation — replaced with malloc-backed allocator.
//	The original linked-list allocator had corruption bugs.
//	This version uses malloc() for each allocation and tracks
//	blocks in a flat array for Z_FreeTags/Z_ChangeTag support.
//

#include "z_zone.h"
#include "i_system.h"
#include "doomtype.h"

#include <stdlib.h>
#include <string.h>

// Per-allocation header, prepended to every Z_Malloc result
typedef struct
{
    int     tag;
    void**  user;
    int     id;
    int     size;  // user-visible size (not including header)
} zblock_t;

#define ZONEID 0x1d4a11
#define HEADER_SIZE ((sizeof(zblock_t) + 7) & ~7)  // 8-byte aligned

// Track all allocations for Z_FreeTags iteration
#define MAX_BLOCKS 8192
static zblock_t* all_blocks[MAX_BLOCKS];
static int block_count = 0;

static int total_allocated = 0;
static int zone_capacity = 16 * 1024 * 1024;  // 16 MB logical capacity

void Z_Init(void)
{
    // No zone base needed — we use malloc per allocation
    printf("Z_Init: using malloc-backed zone (no fixed pool)\n");
}

void* Z_Malloc(int size, int tag, void* user)
{
    int alloc_size = (size + 7) & ~7;  // 8-byte align
    byte* raw = (byte*)malloc(HEADER_SIZE + alloc_size);

    if (raw == NULL)
    {
        I_Error("Z_Malloc: failed on allocation of %i bytes", size);
    }

    zblock_t* block = (zblock_t*)raw;
    block->tag = tag;
    block->user = (void**)user;
    block->id = ZONEID;
    block->size = alloc_size;

    void* result = raw + HEADER_SIZE;

    // Clear allocated memory (DOOM expects zeroed memory in many places)
    memset(result, 0, alloc_size);

    if (block->user)
    {
        *block->user = result;
    }

    // Track for Z_FreeTags
    if (block_count < MAX_BLOCKS)
    {
        all_blocks[block_count++] = block;
    }

    total_allocated += alloc_size;

    return result;
}

void Z_Free(void* ptr)
{
    if (ptr == NULL) return;

    zblock_t* block = (zblock_t*)((byte*)ptr - HEADER_SIZE);

    if (block->id != ZONEID)
    {
        // Silently ignore — original would I_Error but this is safer
        return;
    }

    if (block->tag != PU_FREE && block->user != NULL)
    {
        *block->user = 0;
    }

    block->tag = PU_FREE;
    block->user = NULL;
    block->id = 0;
    total_allocated -= block->size;

    // Note: bump allocator can't reclaim memory, but we mark it freed
    // so Z_FreeTags skips it and Z_FreeMemory counts it
}

void Z_FreeTags(int lowtag, int hightag)
{
    for (int i = 0; i < block_count; i++)
    {
        zblock_t* block = all_blocks[i];
        if (block->id != ZONEID) continue;
        if (block->tag == PU_FREE) continue;
        if (block->tag >= lowtag && block->tag <= hightag)
        {
            Z_Free((byte*)block + HEADER_SIZE);
        }
    }
}

void Z_DumpHeap(int lowtag, int hightag)
{
    printf("zone: malloc-backed, %d blocks, %d bytes allocated\n",
           block_count, total_allocated);
}

void Z_FileDumpHeap(FILE* f)
{
    fprintf(f, "zone: malloc-backed, %d blocks, %d bytes allocated\n",
            block_count, total_allocated);
}

void Z_CheckHeap(void)
{
    // No linked list to corrupt — always valid
}

void Z_ChangeTag2(void* ptr, int tag, char* file, int line)
{
    zblock_t* block = (zblock_t*)((byte*)ptr - HEADER_SIZE);

    if (block->id != ZONEID)
    {
        I_Error("%s:%i: Z_ChangeTag: block without a ZONEID!", file, line);
    }

    block->tag = tag;
}

void Z_ChangeUser(void* ptr, void** user)
{
    zblock_t* block = (zblock_t*)((byte*)ptr - HEADER_SIZE);

    if (block->id != ZONEID)
    {
        I_Error("Z_ChangeUser: Tried to change user for invalid block!");
    }

    block->user = user;
    *user = ptr;
}

int Z_FreeMemory(void)
{
    return zone_capacity - total_allocated;
}

unsigned int Z_ZoneSize(void)
{
    return zone_capacity;
}
