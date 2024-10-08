#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>
#include <math.h>
#include <limits.h>

#define ADDRESS_BITS 48

typedef enum {
    LRU = 1,
    FIFO = 2
} ReplacementPolicy;

typedef struct {
    unsigned long tag;
    bool valid;
    int lastUsed;  // Timestamp for LRU or sequence ID for FIFO
} CacheLine;

typedef struct {
    CacheLine* lines;
    int capacity;
    int count;  // Index for FIFO policy
} CacheSet;

typedef struct {
    CacheSet* sets;
    int numOfSets;
    int associativity;
    ReplacementPolicy policy;
    int blockOffsetBits;
    int indexBits;
    long long memReads;
    long long memWrites;
    long long cacheHits;
    long long cacheMisses;
    long long globalCounter;
} Cache;

// Helper functions
uint64_t hexTo64Bit(const char* hex) {
    uint64_t address;
    sscanf(hex, "%" SCNx64, &address);
    return address;
}

uint64_t zeroExtendTo48Bits(uint64_t address) {
    return address & ((1ULL << ADDRESS_BITS) - 1);
}

void accessCacheLine(CacheLine *line) {
    static int globalAccessCounter = 0; // This counter should be accessible across all cache operations
    line->lastUsed = globalAccessCounter++;
}

// Create a cache
Cache* createCache(int cacheSize, int blockSize, int associativity, ReplacementPolicy policy) {
    Cache* cache = malloc(sizeof(Cache));
    if (!cache) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    cache->numOfSets = cacheSize / (blockSize * associativity);
    cache->associativity = associativity;
    cache->policy = policy;
    cache->blockOffsetBits = log2(blockSize);
    cache->indexBits = log2(cache->numOfSets);
    cache->sets = malloc(cache->numOfSets * sizeof(CacheSet));
    if (!cache->sets) {
        free(cache);
        return NULL;
    }

    for (int i = 0; i < cache->numOfSets; i++) {
        cache->sets[i].lines = malloc(associativity * sizeof(CacheLine));
        if (!cache->sets[i].lines) {
            for (int j = 0; j < i; j++) {
                free(cache->sets[j].lines);
            }
            free(cache->sets);
            free(cache);
            return NULL;
        }
        cache->sets[i].capacity = associativity;
        cache->sets[i].count = 0;  // Initialize FIFO index
        for (int j = 0; j < associativity; j++) {
            cache->sets[i].lines[j].valid = false;
            cache->sets[i].lines[j].tag = 0;
            cache->sets[i].lines[j].lastUsed = -1;
        }
    }
    return cache;
}

// Load a block to cache
void loadBlockToCache(Cache* cache, int setIndex, int lineIndex, uint64_t tag) {
    CacheSet* set = &cache->sets[setIndex];
    set->lines[lineIndex].tag = tag;
    set->lines[lineIndex].valid = true;
    if (cache->policy == LRU) {
        set->lines[lineIndex].lastUsed = cache->globalCounter++;  // Use the global counter to mark last used
    }
}

// Find tag in cache
bool findTagInCache(Cache* cache, uint64_t address, int* lineIndex) {
    uint64_t setIndex = (address >> cache->blockOffsetBits) & ((1ULL << cache->indexBits) - 1);
    uint64_t tag = address >> (cache->blockOffsetBits + cache->indexBits);
    CacheSet* set = &cache->sets[setIndex];
    int leastRecentlyUsedIndex = -1;
    int oldestTime = INT_MAX;

    for (int i = 0; i < set->capacity; i++) {
        if (set->lines[i].valid && set->lines[i].tag == tag) {
            *lineIndex = i;
            if (cache->policy == LRU) {
                set->lines[i].lastUsed = cache->globalCounter++;  // Correctly update time for LRU
            }
            return true;
        }
        if (set->lines[i].lastUsed < oldestTime) {
            oldestTime = set->lines[i].lastUsed;
            leastRecentlyUsedIndex = i;
        }
    }

    *lineIndex = (cache->policy == FIFO) ? set->count : leastRecentlyUsedIndex;
    if (cache->policy == FIFO) {
        set->count = (set->count + 1) % set->capacity;  // Move FIFO index
    }
    return false;
}

// Move block from L2 to L1

int findEmptyOrReplaceableLine(Cache* cache, int setIndex) {
    CacheSet* set = &cache->sets[setIndex];
    int emptyIndex = -1, replacementIndex = -1, oldestTime = INT_MAX;

    for (int i = 0; i < set->capacity; i++) {
        if (!set->lines[i].valid && emptyIndex == -1) {
            emptyIndex = i;  // Find the first empty line
        }
        if (cache->policy == LRU && set->lines[i].lastUsed < oldestTime) {
            oldestTime = set->lines[i].lastUsed;
            replacementIndex = i;  
        }
    }

    if (cache->policy == FIFO) {
        replacementIndex = set->count;  // FIFO logic to select the next line to evict
        set->count = (set->count + 1) % set->capacity;  // Update the FIFO index
    }

    return (emptyIndex != -1) ? emptyIndex : replacementIndex; 
}


void moveBlockToL2(Cache* l1, Cache* l2, int l1Index, uint64_t address) {
    uint64_t l1SetIndex = (address >> l1->blockOffsetBits) & ((1ULL << l1->indexBits) - 1);
    uint64_t l2SetIndex = (address >> l2->blockOffsetBits) & ((1ULL << l2->indexBits) - 1);
    uint64_t tag = l1->sets[l1SetIndex].lines[l1Index].tag; 

    int l2ReplaceIndex = findEmptyOrReplaceableLine(l2, l2SetIndex);

  

    // Move the block from L1 to L2
    l2->sets[l2SetIndex].lines[l2ReplaceIndex].tag = tag;
    l2->sets[l2SetIndex].lines[l2ReplaceIndex].valid = true;
    if (l2->policy == LRU) {
        l2->sets[l2SetIndex].lines[l2ReplaceIndex].lastUsed = l2->globalCounter++;
    }

    // Invalidate the block in L1
    l1->sets[l1SetIndex].lines[l1Index].valid = false;
}


void moveBlockFromL2toL1(Cache* l1, Cache* l2, int l1Index, int l2Index, uint64_t address) {
    uint64_t setIndexL1 = (address >> l1->blockOffsetBits) & ((1ULL << l1->indexBits) - 1);
    uint64_t setIndexL2 = (address >> l2->blockOffsetBits) & ((1ULL << l2->indexBits) - 1);
    uint64_t tag = address >> (l1->blockOffsetBits + l1->indexBits);

    // Check if L1 index is valid, if not find a replacement line
    if (!l1->sets[setIndexL1].lines[l1Index].valid) {
        l1Index = findEmptyOrReplaceableLine(l1, setIndexL1);
    }

    // If the target line in L1 is already valid, check if it needs to be moved to L2
    if (l1->sets[setIndexL1].lines[l1Index].valid) {
        // Move the evicted block from L1 to L2 before overwriting it
        moveBlockToL2(l1, l2, l1Index, address);
    }

    // Place the L2 block into the L1 cache
    l1->sets[setIndexL1].lines[l1Index].tag = tag;
    l1->sets[setIndexL1].lines[l1Index].valid = true;
    if (l1->policy == LRU) {
        l1->sets[setIndexL1].lines[l1Index].lastUsed = ++l1->globalCounter;
    }

    // Invalidate the moved block in L2
    l2->sets[setIndexL2].lines[l2Index].valid = false;
}
void accessCache(Cache* l1, Cache* l2, uint64_t address, char accessType) {
    int l1Index, l2Index;
    bool l1Hit = findTagInCache(l1, address, &l1Index);
    bool l2Hit = false;

    static int globalAccessCounter = 0; // Global access counter for LRU policy

    if (l1Hit) {
        l1->cacheHits++;
        if (l1->policy == LRU) {
            l1->sets[(address >> l1->blockOffsetBits) & ((1ULL << l1->indexBits) - 1)].lines[l1Index].lastUsed = globalAccessCounter++;
        }
        if (accessType == 'W') {
            l1->memWrites++; // Write-through: also write to memory
        }
    } else {
        l1->cacheMisses++;
        l2Hit = findTagInCache(l2, address, &l2Index);
        if (l2Hit) {
            moveBlockFromL2toL1(l1, l2, l1Index, l2Index, address);
            l2->cacheHits++;
            if (l2->policy == LRU) {
                l2->sets[(address >> l2->blockOffsetBits) & ((1ULL << l2->indexBits) - 1)].lines[l2Index].lastUsed = globalAccessCounter++;
            }
            if (accessType == 'W') {
                l1->memWrites++;  // Write-through
            }
        } else {
            l2->cacheMisses++;
            l1->memReads++;  // Read from main memory to fill L1
            int replaceIndex = findEmptyOrReplaceableLine(l1, (address >> l1->blockOffsetBits) & ((1ULL << l1->indexBits) - 1));
            loadBlockToCache(l1, (address >> l1->blockOffsetBits) & ((1ULL << l1->indexBits) - 1), replaceIndex, address);
            if (l1->policy == LRU) {
                l1->sets[(address >> l1->blockOffsetBits) & ((1ULL << l1->indexBits) - 1)].lines[replaceIndex].lastUsed = globalAccessCounter++;
            }
            if (accessType == 'W') {
                l1->memWrites++;  // Write-through
            }
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 9) {
        fprintf(stderr, "Usage: %s <L1 cacheSize> <L1 associativity> <L1 policy> <L1 blockSize> <L2 cacheSize> <L2 associativity> <L2 policy> <traceFile>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int l1CacheSize = atoi(argv[1]);
    int l1Associativity;
    sscanf(argv[2], "assoc:%d",&l1Associativity);
    ReplacementPolicy l1Policy = (strcmp(argv[3], "lru") == 0) ? LRU : FIFO;
    int l1BlockSize = atoi(argv[4]);
    int l2CacheSize = atoi(argv[5]);
    int l2Associativity; 
    sscanf(argv[6], "assoc:%d", &l2Associativity);

    ReplacementPolicy l2Policy = (strcmp(argv[7], "lru") == 0) ? LRU : FIFO;
    char *traceFile = argv[8];

    Cache* l1Cache = createCache(l1CacheSize, l1BlockSize, l1Associativity, l1Policy);
    Cache* l2Cache = createCache(l2CacheSize, l1BlockSize, l2Associativity, l2Policy);
    if (!l1Cache || !l2Cache) {
        fprintf(stderr, "Cache initialization failed.\n");
        return EXIT_FAILURE;
    }

    FILE *file = fopen(traceFile, "r");
    if (!file) {
        fprintf(stderr, "Error opening trace file: %s\n", traceFile);
        return EXIT_FAILURE;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        char *ptr;
        if (line[0] == 'R' || line[0] == 'W') {
            ptr = strchr(line, ' ');
            if (ptr) {
                uint64_t address = hexTo64Bit(ptr + 1);
                address = zeroExtendTo48Bits(address);
                accessCache(l1Cache, l2Cache, address, line[0]);
            }
        }
    }

    fclose(file);

    printf("memread:%llu\n", l1Cache->memReads + l2Cache->memReads);
    printf("memwrite:%llu\n", l1Cache->memWrites + l2Cache->memWrites);
    printf("l1cachehit:%llu\n", l1Cache->cacheHits);
    printf("l1cachemiss:%llu\n", l1Cache->cacheMisses);
    printf("l2cachehit:%llu\n", l2Cache->cacheHits);
    printf("l2cachemiss:%llu\n", l2Cache->cacheMisses);

    // Cleanup
    for (int i = 0; i < l1Cache->numOfSets; i++) {
        free(l1Cache->sets[i].lines);
    }
    free(l1Cache->sets);
    free(l1Cache);

    for (int i = 0; i < l2Cache->numOfSets; i++) {
        free(l2Cache->sets[i].lines);
    }
    free(l2Cache->sets);
    free(l2Cache);

    return 0;
}
