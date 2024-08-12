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
    int lastUsed;  // For LRU policy
} CacheLine;

typedef struct {
    CacheLine* lines;
    int capacity;
    int count;  // For FIFO policy
} CacheSet;

typedef struct {
    CacheSet* sets;
    int numOfSets;
    int associativity;
    ReplacementPolicy policy;
    int blockOffsetBits;
    int indexBits;
    int memReads;
    int memWrites;
    int cacheHits;
    int cacheMisses;
} Cache;


uint64_t hexTo64Bit(const char* hex) {
    uint64_t address;
    sscanf(hex, "%" SCNx64, &address);
    return address;
}

uint64_t zeroExtendTo48Bits(uint64_t address) {
    return address & ((1ULL << ADDRESS_BITS) - 1);
}

Cache* createCache(int cacheSize, int blockSize, int associativity, ReplacementPolicy policy) {
    if (blockSize <= 0 || associativity <= 0 || blockSize * associativity > cacheSize) {
        fprintf(stderr, "Invalid cache configuration: blockSize=%d, associativity=%d, cacheSize=%d\n", blockSize, associativity, cacheSize);
        return NULL;
    }
   
    Cache* cache = malloc(sizeof(Cache));
    if (!cache) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    cache->numOfSets = cacheSize / (blockSize * associativity);
    cache->associativity = associativity;
    cache->policy = policy;
    cache->blockOffsetBits = (int)log2(blockSize);
    cache->indexBits = (int)log2(cache->numOfSets);
    cache->sets = malloc(cache->numOfSets * sizeof(CacheSet));
    cache->memReads = 0;
    cache->memWrites = 0;
    cache->cacheHits = 0;
    cache->cacheMisses = 0;

    for (int i = 0; i < cache->numOfSets; i++) {
        cache->sets[i].lines = malloc(associativity * sizeof(CacheLine));
        if (!cache->sets[i].lines) {
            fprintf(stderr, "Memory allocation failed\n");
            return NULL;
        }
        cache->sets[i].capacity = associativity;
        cache->sets[i].count = 0;
        for (int j = 0; j < associativity; j++) {
            cache->sets[i].lines[j].valid = false;
            cache->sets[i].lines[j].tag = 0;
            cache->sets[i].lines[j].lastUsed = 0;
        }
    }
    return cache;
}

void accessCache(Cache* cache, uint64_t address, char accessType) {
    uint64_t setIndex = (address >> cache->blockOffsetBits) & ((1ULL << cache->indexBits) - 1);
    uint64_t tag = address >> (cache->blockOffsetBits + cache->indexBits);
    CacheSet* set = &cache->sets[setIndex];
    bool hit = false;
    int lineIndex;

    if (cache->policy == FIFO) {
        for (int i = 0; i < set->capacity; i++) {
            if (set->lines[i].valid && set->lines[i].tag == tag) {
                hit = true;
                cache->cacheHits++;
                break;
            }
        }
        if (!hit) {
            cache->cacheMisses++;
            cache->memReads++;
            lineIndex = set->count;
            set->lines[lineIndex].tag = tag;
            set->lines[lineIndex].valid = true;
            set->lines[lineIndex].lastUsed = cache->cacheMisses;
            set->count = (set->count + 1) % set->capacity;  
        }
    } else if (cache->policy == LRU) {
        int leastUsedIndex = 0;
        int oldestTime = INT_MAX;

        for (int i = 0; i < set->capacity; i++) {
            if (set->lines[i].valid && set->lines[i].tag == tag) {
                hit = true;
                cache->cacheHits++;
                lineIndex = i;
                break;
            }
            if (set->lines[i].lastUsed < oldestTime) {
                oldestTime = set->lines[i].lastUsed;
                leastUsedIndex = i;
            }
        }

        if (!hit) {
            cache->cacheMisses++;
            cache->memReads++;
            lineIndex = leastUsedIndex;
            set->lines[lineIndex].tag = tag;
            set->lines[lineIndex].valid = true;
        }

        set->lines[lineIndex].lastUsed = cache->cacheMisses; // Update the last used time
    }

    if (accessType == 'W') {
        cache->memWrites++;
    }
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <cacheSize> <associativity> <blockSize> <policy> <traceFile>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int cacheSize = atoi(argv[1]);
    char * associativityStr = argv[2];
    ReplacementPolicy policy = (strcmp(argv[3], "lru") == 0) ? LRU : FIFO;
    int blockSize = atoi(argv[4]);
    char *number = &associativityStr[6];
    int associativity = atoi(number);
    char *traceFile = argv[5];

    Cache* cache = createCache(cacheSize, blockSize, associativity, policy);
    if (!cache) {
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
                accessCache(cache, address, line[0]);
            }
        }
    }

    fclose(file);

    printf("memread:%d\n", cache->memReads);
    printf("memwrite:%d\n", cache->memWrites);
    printf("cachehit:%d\n", cache->cacheHits);
    printf("cachemiss:%d\n", cache->cacheMisses);

    // Cleanup
    for (int i = 0; i < cache->numOfSets; i++) {
        free(cache->sets[i].lines);
    }
    free(cache->sets);
    free(cache);

    return 0;
}


