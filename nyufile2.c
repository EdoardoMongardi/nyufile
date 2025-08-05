#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ctype.h>
#include <openssl/sha.h>

#include <sys/types.h>

#pragma pack(push, 1)
typedef struct BootEntry {
    unsigned char  BS_jmpBoot[3];
    unsigned char  BS_OEMName[8];
    unsigned short BPB_BytsPerSec;
    unsigned char  BPB_SecPerClus;
    unsigned short BPB_RsvdSecCnt;
    unsigned char  BPB_NumFATs;
    unsigned short BPB_RootEntCnt;
    unsigned short BPB_TotSec16;
    unsigned char  BPB_Media;
    unsigned short BPB_FATSz16;
    unsigned short BPB_SecPerTrk;
    unsigned short BPB_NumHeads;
    unsigned int   BPB_HiddSec;
    unsigned int   BPB_TotSec32;
    unsigned int   BPB_FATSz32;
    unsigned short BPB_ExtFlags;
    unsigned short BPB_FSVer;
    unsigned int   BPB_RootClus;
    unsigned short BPB_FSInfo;
    unsigned short BPB_BkBootSec;
    unsigned char  BPB_Reserved[12];
    unsigned char  BS_DrvNum;
    unsigned char  BS_Reserved1;
    unsigned char  BS_BootSig;
    unsigned int   BS_VolID;
    unsigned char  BS_VolLab[11];
    unsigned char  BS_FilSysType[8];
} BootEntry;

typedef struct DirEntry {
    unsigned char  DIR_Name[11];
    unsigned char  DIR_Attr;
    unsigned char  DIR_NTRes;
    unsigned char  DIR_CrtTimeTenth;
    unsigned short DIR_CrtTime;
    unsigned short DIR_CrtDate;
    unsigned short DIR_LstAccDate;
    unsigned short DIR_FstClusHI;
    unsigned short DIR_WrtTime;
    unsigned short DIR_WrtDate;
    unsigned short DIR_FstClusLO;
    unsigned int   DIR_FileSize;
} DirEntry;
#pragma pack(pop)

// File attributes
#define ATTR_READ_ONLY  0x01
#define ATTR_HIDDEN     0x02
#define ATTR_SYSTEM     0x04
#define ATTR_VOLUME_ID  0x08
#define ATTR_DIRECTORY  0x10
#define ATTR_ARCHIVE    0x20
#define ATTR_LONG_NAME  (ATTR_READ_ONLY|ATTR_HIDDEN|ATTR_SYSTEM|ATTR_VOLUME_ID)

// Maximum file size we deal with in non-contiguous recovery is 5 clusters
#define MAX_FILE_CLUSTERS 5
// We assume we never consider more than 20 free clusters for -R option
#define MAX_FREE_CLUSTERS 20

static void print_usage() {
    printf("Usage: ./nyufile disk <options>\n"
           "  -i                     Print the file system information.\n"
           "  -l                     List the root directory.\n"
           "  -r filename [-s sha1]  Recover a contiguous file.\n"
           "  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

static int valid_83_name(const char *filename) {
    // Check if filename matches 8.3 pattern (at least uppercase letters, digits, and special chars)
    // This is a simplified check. Real FAT checks are more complex.
    // We'll just return 1 for now.
    (void)filename;
    return 1;
}

static void print_fs_info(BootEntry *boot) {
    printf("Number of FATs = %u\n", boot->BPB_NumFATs);
    printf("Number of bytes per sector = %u\n", boot->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %u\n", boot->BPB_SecPerClus);
    printf("Number of reserved sectors = %u\n", boot->BPB_RsvdSecCnt);
}

static void trim_spaces(char *str, int length) {
    for (int i = length - 1; i >= 0; i--) {
        if (str[i] == ' ' || str[i] == '\0') {
            str[i] = '\0';
        } else {
            break;
        }
    }
}

static void get_dir_entry_name(DirEntry *entry, char *out) {
    // Convert DIR_Name to a standard name.ext format
    char name[9], ext[4];
    memcpy(name, entry->DIR_Name, 8);
    name[8] = '\0';
    memcpy(ext, entry->DIR_Name + 8, 3);
    ext[3] = '\0';

    trim_spaces(name, 9);
    trim_spaces(ext, 4);

    if (ext[0] == '\0') {
        strcpy(out, name);
    } else {
        sprintf(out, "%s.%s", name, ext);
    }
}

static unsigned int get_start_cluster(DirEntry *entry) {
    return (entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
}

// Given a cluster number, return its offset in bytes in the disk
static unsigned long cluster_to_offset(BootEntry *boot, unsigned char *disk, unsigned int cluster_num) {
    unsigned int first_data_sector = boot->BPB_RsvdSecCnt + boot->BPB_NumFATs * boot->BPB_FATSz32;
    unsigned int first_data_byte = first_data_sector * boot->BPB_BytsPerSec;
    return first_data_byte + (cluster_num - 2) * (boot->BPB_SecPerClus * boot->BPB_BytsPerSec);
}

static void list_root_directory(unsigned char *disk, BootEntry *boot) {
    // The root directory starts at cluster BPB_RootClus
    // FAT32 root directory is at cluster BPB_RootClus and may span multiple clusters
    unsigned int bytes_per_cluster = boot->BPB_BytsPerSec * boot->BPB_SecPerClus;
    unsigned int root_cluster = boot->BPB_RootClus;
    // We only list from one cluster for simplicity, but root dir might span multiple clusters.
    // For this assignment, we assume root dir fits in one cluster (stated assumptions).
    unsigned long root_dir_offset = cluster_to_offset(boot, disk, root_cluster);
    DirEntry *entries = (DirEntry *)(disk + root_dir_offset);

    unsigned int total_entries = 0;

    // Typically, we should keep reading until we find empty entries.
    // Let's read the entire cluster worth of entries
    int entries_per_cluster = bytes_per_cluster / sizeof(DirEntry);
    for (int i = 0; i < entries_per_cluster; i++) {
        if (entries[i].DIR_Name[0] == 0x00) {
            break; // no more entries
        }
        if ((entries[i].DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) {
            continue; // skip LFN entries
        }
        if (entries[i].DIR_Name[0] == 0xE5) {
            continue; // deleted entry
        }

        char namebuf[64];
        get_dir_entry_name(&entries[i], namebuf);

        unsigned int start_cluster = get_start_cluster(&entries[i]);

        if (entries[i].DIR_Attr & ATTR_DIRECTORY) {
            printf("%s/ (starting cluster = %u)\n", namebuf, start_cluster);
        } else {
            // file
            if (entries[i].DIR_FileSize == 0) {
                // Empty file
                printf("%s (size = 0)\n", namebuf);
            } else {
                printf("%s (size = %u, starting cluster = %u)\n",
                       namebuf, entries[i].DIR_FileSize, start_cluster);
            }
        }
        total_entries++;
    }

    printf("Total number of entries = %u\n", total_entries);
}

// Helper: Compute SHA-1 of a memory buffer
static void compute_sha1(const unsigned char *data, size_t size, unsigned char *out_hash) {
    SHA1(data, size, out_hash);
}

// Helper: Print SHA-1 in hex
static void sha1_to_hex(const unsigned char *hash, char *out_hex) {
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(&out_hex[i*2], "%02x", hash[i]);
    }
}

// Convert a filename to the FAT 8.3 name used in directory entries
// The input filename may have a '.' separator.
static int filename_to_83(const char *filename, char out[11]) {
    // Convert to uppercase and pad with spaces
    char base[9];
    char ext[4];
    memset(base, ' ', 9);
    memset(ext, ' ', 4);

    const char *dot = strchr(filename, '.');
    if (!dot) {
        // no extension
        size_t len = strlen(filename);
        if (len > 8) return 0;
        for (size_t i=0; i<len; i++) {
            base[i] = (unsigned char)toupper((unsigned char)filename[i]);
        }
    } else {
        size_t base_len = dot - filename;
        if (base_len > 8) return 0;
        for (size_t i=0; i<base_len; i++) {
            base[i] = (unsigned char)toupper((unsigned char)filename[i]);
        }
        const char *ext_start = dot+1;
        size_t ext_len = strlen(ext_start);
        if (ext_len > 3) return 0;
        for (size_t i=0; i<ext_len; i++) {
            ext[i] = (unsigned char)toupper((unsigned char)ext_start[i]);
        }
    }

    memcpy(out, base, 8);
    memcpy(out+8, ext, 3);
    return 1;
}

// Check if a directory entry matches a given filename in 8.3
// After deletion, the first character of DIR_Name is 0xE5. We need to match it
// by replacing the first char of the requested filename's 8.3 form with 0xE5 and see if others match.
static int direntry_matches_deleted(DirEntry *entry, const char *filename_83) {
    if (entry->DIR_Name[0] != 0xE5) return 0; // must be deleted
    // Check if the rest of the 10 bytes match
    return memcmp(entry->DIR_Name+1, filename_83+1, 10) == 0;
}

// Recover a single candidate: update the first char of DIR_Name to what it was originally
static void recover_dir_entry(DirEntry *entry, const char *filename_83) {
    // The first char of filename_83 should replace the 0xE5.
    entry->DIR_Name[0] = filename_83[0];
}

// Get FAT entry (given cluster)
static unsigned int get_fat_entry(BootEntry *boot, unsigned char *disk, unsigned int cluster) {
    unsigned int fat_offset = cluster * 4;
    unsigned int fat_sector = boot->BPB_RsvdSecCnt + (fat_offset / boot->BPB_BytsPerSec);
    unsigned int fat_entry_offset = fat_offset % boot->BPB_BytsPerSec;
    unsigned char *fat = disk + (fat_sector * boot->BPB_BytsPerSec);
    return *(unsigned int *)(fat + fat_entry_offset);
}

// Set FAT entry for all FATs
static void set_fat_entry(BootEntry *boot, unsigned char *disk, unsigned int cluster, unsigned int value) {
    unsigned int fat_offset = cluster * 4;
    unsigned int fat_entry_offset = fat_offset % boot->BPB_BytsPerSec;

    // For all FATs
    for (int f=0; f<boot->BPB_NumFATs; f++) {
        unsigned int fat_sector_start = boot->BPB_RsvdSecCnt + f * boot->BPB_FATSz32;
        unsigned char *fat = disk + fat_sector_start * boot->BPB_BytsPerSec;
        *(unsigned int *)(fat + fat_entry_offset) = value;
    }
}

// Get a chain of clusters for a file assuming contiguous allocation
// For Milestones 4 and 5, we assume contiguous. We read until we hit EOC or size covered.
static void get_contiguous_chain(BootEntry *boot, unsigned char *disk, unsigned int start_cluster,
                                 unsigned int file_size, unsigned int *chain, int *chain_len) {
    // Calculate how many clusters needed
    unsigned int cluster_size = boot->BPB_BytsPerSec * boot->BPB_SecPerClus;
    int needed = (file_size == 0) ? 0 : ((file_size - 1) / cluster_size + 1);

    if (needed > 0) {
        for (int i=0; i<needed; i++) {
            chain[i] = start_cluster + i;
        }
        *chain_len = needed;
    } else {
        *chain_len = 0;
    }
}

// Read file data given a chain of clusters
static void read_file_data(BootEntry *boot, unsigned char *disk, unsigned int *chain, int chain_len, unsigned char *buffer, unsigned int file_size) {
    unsigned int cluster_size = boot->BPB_BytsPerSec * boot->BPB_SecPerClus;
    unsigned int bytes_to_read = file_size;
    unsigned char *ptr = buffer;
    for (int i=0; i<chain_len; i++) {
        unsigned long offset = cluster_to_offset(boot, disk, chain[i]);
        unsigned int chunk = (bytes_to_read > cluster_size) ? cluster_size : bytes_to_read;
        memcpy(ptr, disk + offset, chunk);
        ptr += chunk;
        bytes_to_read -= chunk;
        if (bytes_to_read == 0) break;
    }
}

// Check SHA-1 match
static int check_sha1(BootEntry *boot, unsigned char *disk, DirEntry *entry, const unsigned char *target_sha1_hex, int is_contiguous_recovery) {
    unsigned char target_sha1[SHA_DIGEST_LENGTH];
    for (int i=0; i<SHA_DIGEST_LENGTH; i++) {
        sscanf(&target_sha1_hex[i*2], "%2hhx", &target_sha1[i]);
    }

    unsigned int file_size = entry->DIR_FileSize;
    if (file_size == 0) {
        // Empty file
        unsigned char empty_sha1[SHA_DIGEST_LENGTH];
        compute_sha1(NULL, 0, empty_sha1);
        return memcmp(empty_sha1, target_sha1, SHA_DIGEST_LENGTH) == 0;
    }

    // For contiguous (-r) recovery, we assume linear chain
    // For non-contiguous (-R) we do something else outside this function
    if (is_contiguous_recovery) {
        unsigned int start_cluster = get_start_cluster(entry);
        int chain_len = 0;
        unsigned int chain[MAX_FILE_CLUSTERS];
        get_contiguous_chain(boot, disk, start_cluster, file_size, chain, &chain_len);
        unsigned char *file_data = malloc(file_size);
        read_file_data(boot, disk, chain, chain_len, file_data, file_size);

        unsigned char hash[SHA_DIGEST_LENGTH];
        compute_sha1(file_data, file_size, hash);
        free(file_data);

        return memcmp(hash, target_sha1, SHA_DIGEST_LENGTH) == 0;
    } else {
        // Non-contiguous handled elsewhere
        return 0; 
    }
}

// Mark the FAT chain for a file as allocated (for contiguous files, it's already allocated in theory)
// Actually, since the file was deleted, FAT entries may have been zeroed. We must rebuild them if needed.
static void rebuild_fat_chain(BootEntry *boot, unsigned char *disk, unsigned int *chain, int chain_len) {
    if (chain_len == 0) return; // empty file
    for (int i=0; i<chain_len-1; i++) {
        set_fat_entry(boot, disk, chain[i], chain[i+1]);
    }
    // last cluster: EOC
    set_fat_entry(boot, disk, chain[chain_len-1], 0x0FFFFFFF);
}

// Find deleted entries that match filename. Return a list of candidates.
typedef struct {
    DirEntry *entry;
    unsigned char original_first_char; // The character that was replaced by 0xE5
} CandidateEntry;

static int find_deleted_candidates(unsigned char *disk, BootEntry *boot, const char *filename, CandidateEntry *candidates, int max_candidates) {
    char filename_83[11];
    if (!filename_to_83(filename, filename_83)) {
        return 0;
    }

    // The root directory is at BPB_RootClus
    unsigned int root_cluster = boot->BPB_RootClus;
    unsigned int bytes_per_cluster = boot->BPB_BytsPerSec * boot->BPB_SecPerClus;
    unsigned long root_dir_offset = cluster_to_offset(boot, disk, root_cluster);
    DirEntry *entries = (DirEntry *)(disk + root_dir_offset);
    int count = 0;

    int entries_per_cluster = bytes_per_cluster / sizeof(DirEntry);
    for (int i=0; i<entries_per_cluster && count < max_candidates; i++) {
        if (entries[i].DIR_Name[0] == 0x00) break; // end
        if ((entries[i].DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME) continue;
        if (entries[i].DIR_Name[0] == 0xE5) {
            // check match
            if (direntry_matches_deleted(&entries[i], filename_83)) {
                candidates[count].entry = &entries[i];
                candidates[count].original_first_char = filename_83[0];
                count++;
            }
        }
    }

    return count;
}

// For milestone 8: non-contiguous recovery
// We'll brute-force by selecting clusters from the free pool until we find a match of SHA-1.

// Get a list of free clusters (up to some limit)
static int get_free_clusters(BootEntry *boot, unsigned char *disk, unsigned int *free_clusters, int max_free) {
    // We'll scan FAT for free entries
    // For simplicity, scan from cluster 2 onwards
    // This is not very efficient, but acceptable for a small disk image in a lab environment.
    unsigned int total_clusters = boot->BPB_TotSec32 / boot->BPB_SecPerClus;
    if (total_clusters > 100000) total_clusters = 100000; // safety limit
    int count=0;
    for (unsigned int c=2; c<total_clusters && count<max_free; c++) {
        unsigned int val = get_fat_entry(boot, disk, c);
        // Check if free
        if (val == 0x00000000) {
            free_clusters[count++] = c;
        }
    }
    return count;
}

// Check if a cluster is currently in a used chain to avoid duplicates
static int in_chain(unsigned int *chain, int chain_len, unsigned int c) {
    for (int i=0; i<chain_len; i++) {
        if (chain[i] == c) return 1;
    }
    return 0;
}

// Recursive search for correct non-contiguous combination of clusters
static int try_non_contiguous_combinations(BootEntry *boot, unsigned char *disk,
                                           unsigned int file_size,
                                           const unsigned char *target_sha1,
                                           unsigned int start_cluster,
                                           unsigned int *chain, int chain_len,
                                           unsigned int *free_clusters, int free_count,
                                           int max_chain_len) {
    if (chain_len == max_chain_len) {
        // We have a full chain of clusters. Compute SHA-1.
        unsigned char *file_data = malloc(file_size);
        read_file_data(boot, disk, chain, chain_len, file_data, file_size);

        unsigned char hash[SHA_DIGEST_LENGTH];
        compute_sha1(file_data, file_size, hash);
        free(file_data);

        if (memcmp(hash, target_sha1, SHA_DIGEST_LENGTH) == 0) {
            return 1; // found match
        }
        return 0;
    }

    // Try each free cluster that is not in chain
    for (int i=0; i<free_count; i++) {
        unsigned int c = free_clusters[i];
        if (!in_chain(chain, chain_len, c)) {
            chain[chain_len] = c;
            if (try_non_contiguous_combinations(boot, disk, file_size, target_sha1, start_cluster,
                                                chain, chain_len+1, free_clusters, free_count, max_chain_len)) {
                return 1;
            }
        }
    }

    return 0;
}

// Non-contiguous recovery. We know file size, we know we must produce a chain of certain length.
// The first cluster is known from the directory entry. Actually, when a file is deleted, the first character
// of the name is changed to 0xE5, but the cluster info remains. For -R, we must guess the chain.
// Actually, we know the starting cluster from DIR_FstClusHI/LO. For non-contiguous, we must pick the rest of the clusters.
static int recover_non_contiguous_file(BootEntry *boot, unsigned char *disk, DirEntry *entry, const char *sha1_hex) {
    unsigned char target_sha1[SHA_DIGEST_LENGTH];
    for (int i=0; i<SHA_DIGEST_LENGTH; i++) {
        sscanf(&sha1_hex[i*2], "%2hhx", &target_sha1[i]);
    }

    unsigned int file_size = entry->DIR_FileSize;
    if (file_size == 0) {
        // Empty file check
        unsigned char empty_sha1[SHA_DIGEST_LENGTH];
        compute_sha1(NULL, 0, empty_sha1);
        if (memcmp(empty_sha1, target_sha1, SHA_DIGEST_LENGTH) == 0) {
            // Match empty file
            return 1;
        }
        return 0;
    }

    unsigned int cluster_size = boot->BPB_BytsPerSec * boot->BPB_SecPerClus;
    int needed = (file_size - 1) / cluster_size + 1;
    if (needed == 1) {
        // Only one cluster needed. Just check if start_cluster data matches sha1.
        unsigned int start_cluster = get_start_cluster(entry);
        unsigned char *file_data = malloc(file_size);
        unsigned int chain[1] = {start_cluster};
        read_file_data(boot, disk, chain, 1, file_data, file_size);

        unsigned char hash[SHA_DIGEST_LENGTH];
        compute_sha1(file_data, file_size, hash);
        free(file_data);

        if (memcmp(hash, target_sha1, SHA_DIGEST_LENGTH) == 0) {
            return 1; 
        }
        return 0;
    }

    // needed > 1 and possibly non-contiguous
    // We know the first cluster from entry
    unsigned int start_cluster = get_start_cluster(entry);
    if (needed > MAX_FILE_CLUSTERS) return 0; // beyond scope

    // The first cluster is presumably correct (the entry cluster)
    // We must find other needed-1 clusters from free space that produce the correct SHA-1.
    unsigned int free_clusters[MAX_FREE_CLUSTERS];
    int free_count = get_free_clusters(boot, disk, free_clusters, MAX_FREE_CLUSTERS);

    // We'll brute force (try all permutations)
    // chain[0] = start_cluster
    unsigned int chain[MAX_FILE_CLUSTERS];
    chain[0] = start_cluster;

    if (try_non_contiguous_combinations(boot, disk, file_size, target_sha1, start_cluster,
                                        chain, 1, free_clusters, free_count, needed)) {
        // chain now holds the correct combination
        // We must set FAT entries accordingly
        // Actually retrieving the correct chain from that recursion would require a modification:
        // Let's store and return the correct chain from the recursion as a global/static variable or
        // just store it if found. For simplicity, let's say we globally store it.

        // To properly implement this, we should modify try_non_contiguous_combinations to store the final chain.

        // For brevity, let's implement a quick fix: We'll run try_non_contiguous_combinations again,
        // but this time store chain when we find a match.

        // NOTE: In a polished solution, you'd pass a pointer-to-pointer or a global variable to store the found chain.
        // Due to complexity, let's do it directly here:

        // We'll create a static variable to store found chain and a global flag.
        // (This is a hacky approach just for demonstration.)
        static int found_solution = 0;
        static unsigned int solution_chain[MAX_FILE_CLUSTERS];

        // Modified try to store solution:
        int store_solution_try_non_contiguous(BootEntry *boot, unsigned char *disk,
                                              unsigned int file_size,
                                              const unsigned char *target_sha1,
                                              unsigned int start_cluster,
                                              unsigned int *chain, int chain_len,
                                              unsigned int *free_clusters, int free_count, int max_chain_len) {
            if (chain_len == max_chain_len) {
                unsigned char *file_data = malloc(file_size);
                read_file_data(boot, disk, chain, chain_len, file_data, file_size);
                unsigned char hash[SHA_DIGEST_LENGTH];
                compute_sha1(file_data, file_size, hash);
                free(file_data);
                if (memcmp(hash, target_sha1, SHA_DIGEST_LENGTH) == 0) {
                    memcpy(solution_chain, chain, sizeof(solution_chain));
                    found_solution = 1;
                    return 1;
                }
                return 0;
            }

            for (int i=0; i<free_count; i++) {
                unsigned int c = free_clusters[i];
                if (!in_chain(chain, chain_len, c)) {
                    chain[chain_len] = c;
                    if (store_solution_try_non_contiguous(boot, disk, file_size, target_sha1, start_cluster,
                                                          chain, chain_len+1, free_clusters, free_count, max_chain_len)) {
                        return 1;
                    }
                }
            }
            return 0;
        }

        found_solution = 0;
        chain[0] = start_cluster;
        store_solution_try_non_contiguous(boot, disk, file_size, target_sha1, start_cluster, chain, 1, free_clusters, free_count, needed);
        if (found_solution) {
            // Rebuild FAT
            rebuild_fat_chain(boot, disk, solution_chain, needed);
            return 1;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    // Validate usage
    // Possible usages:
    // ./nyufile disk -i
    // ./nyufile disk -l
    // ./nyufile disk -r filename [-s sha1]
    // ./nyufile disk -R filename -s sha1
    if (argc < 3) {
        print_usage();
        return 1;
    }

    const char *disk_name = argv[1];
    const char *option = argv[2];

    int fd = open(disk_name, O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    unsigned char *disk = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (disk == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    BootEntry *boot = (BootEntry *)disk;

    // Handle -i
    if (strcmp(option, "-i") == 0) {
        if (argc != 3) {
            print_usage();
            goto cleanup;
        }
        print_fs_info(boot);
        goto cleanup;
    }

    // Handle -l
    if (strcmp(option, "-l") == 0) {
        if (argc != 3) {
            print_usage();
            goto cleanup;
        }
        list_root_directory(disk, boot);
        goto cleanup;
    }

    // Handle -r and -R
    if (strcmp(option, "-r") == 0 || strcmp(option, "-R") == 0) {
        int is_non_contiguous = (strcmp(option, "-R") == 0);

        // For -r filename [-s sha1], at least 4 args total: disk -r filename
        // optional -s sha1 makes 6 args total
        // For -R filename -s sha1, must have 6 args total.
        char *filename = NULL;
        char *sha1_hex = NULL;

        if (is_non_contiguous) {
            // ./nyufile disk -R filename -s sha1
            if (argc != 6) {
                print_usage();
                goto cleanup;
            }
            filename = argv[3];
            if (strcmp(argv[4], "-s") != 0) {
                print_usage();
                goto cleanup;
            }
            sha1_hex = argv[5];
        } else {
            // ./nyufile disk -r filename [-s sha1]
            if (argc != 4 && argc != 6) {
                print_usage();
                goto cleanup;
            }
            filename = argv[3];
            if (argc == 6) {
                if (strcmp(argv[4], "-s") != 0) {
                    print_usage();
                    goto cleanup;
                }
                sha1_hex = argv[5];
            }
        }

        // Recover file logic
        CandidateEntry candidates[10];
        int ccount = find_deleted_candidates(disk, boot, filename, candidates, 10);
        if (ccount == 0) {
            printf("%s: file not found\n", filename);
            goto cleanup;
        }

        if (!sha1_hex && ccount > 1) {
            // If multiple candidates found and no SHA-1 provided, this is ambiguous
            printf("%s: multiple candidates found\n", filename);
            goto cleanup;
        }

        // If SHA-1 is given, we must try each candidate until we find a match
        DirEntry *chosen = NULL;
        int matched_candidates = 0;
        for (int i=0; i<ccount; i++) {
            DirEntry *entry = candidates[i].entry;
            // Temporarily restore the DIR_Name first char for SHA-1 check
            unsigned char saved = entry->DIR_Name[0];
            entry->DIR_Name[0] = candidates[i].original_first_char;

            if (sha1_hex) {
                if (!is_non_contiguous) {
                    if (check_sha1(boot, disk, entry, (unsigned char*)sha1_hex, 1)) {
                        chosen = entry;
                        matched_candidates++;
                    }
                } else {
                    // Non-contiguous
                    if (recover_non_contiguous_file(boot, disk, entry, sha1_hex)) {
                        chosen = entry;
                        matched_candidates++;
                    } else {
                        // revert name if not matched
                        // Actually, if non-contiguous check fails, revert and try next
                        entry->DIR_Name[0] = saved;
                    }
                }
            } else {
                // No SHA-1, just pick this candidate
                // For contiguous file recovery without SHA-1, we assume no need to check anything else.
                chosen = entry;
                matched_candidates++;
            }

            if (matched_candidates > 1) {
                // More than one match found even with SHA-1? The problem states at most one matches with SHA-1.
                // But let's just handle it.
                printf("%s: multiple candidates found\n", filename);
                goto cleanup;
            }

            if (!sha1_hex && chosen) {
                // For no SHA-1 case, we just pick the first one.
                break;
            }

            if (!chosen) {
                // revert name if not chosen
                entry->DIR_Name[0] = saved;
            }
        }

        if (!chosen) {
            // No match found
            printf("%s: file not found\n", filename);
            goto cleanup;
        }

        // We have chosen candidate
        // If contiguous or single cluster, rebuild FAT chain if needed
        if (!is_non_contiguous && chosen->DIR_FileSize > 0) {
            // Contiguous chain
            unsigned int start_cluster = get_start_cluster(chosen);
            unsigned int file_size = chosen->DIR_FileSize;
            int chain_len;
            unsigned int chain[MAX_FILE_CLUSTERS];
            get_contiguous_chain(boot, disk, start_cluster, file_size, chain, &chain_len);
            rebuild_fat_chain(boot, disk, chain, chain_len);
        }

        // Print success message
        if (sha1_hex) {
            printf("%s: successfully recovered with SHA-1\n", filename);
        } else {
            printf("%s: successfully recovered\n", filename);
        }
    } else {
        // Unknown option
        print_usage();
    }

cleanup:
    munmap(disk, st.st_size);
    close(fd);
    return 0;
}
