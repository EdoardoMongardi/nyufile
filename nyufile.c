#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

#pragma pack(push,1)
typedef struct {
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

typedef struct {
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

#define ATTR_READ_ONLY  0x01
#define ATTR_HIDDEN     0x02
#define ATTR_SYSTEM     0x04
#define ATTR_VOLUME_ID  0x08
#define ATTR_DIRECTORY  0x10
#define ATTR_ARCHIVE    0x20
#define ATTR_LONG_NAME  (ATTR_READ_ONLY|ATTR_HIDDEN|ATTR_SYSTEM|ATTR_VOLUME_ID)
#define SHA_DIGEST_LENGTH 20

static unsigned char *disk = NULL;
static size_t disk_size = 0;
static BootEntry *boot = NULL;

static unsigned int bytes_per_sector;
static unsigned int sectors_per_cluster;
static unsigned int reserved_sectors;
static unsigned int num_fats;
static unsigned int fat_size; 
static unsigned int root_cluster;
static unsigned int fat_begin; 
static unsigned int cluster_begin; 
static unsigned int bytes_per_cluster;

static void print_usage() {
    printf("Usage: ./nyufile disk <options>\n"
           "  -i                     Print the file system information.\n"
           "  -l                     List the root directory.\n"
           "  -r filename [-s sha1]  Recover a contiguous file.\n"
           "  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
}

static unsigned int cluster_to_offset(unsigned int cluster) {
    return cluster_begin + (cluster - 2)*bytes_per_cluster;
}

static unsigned int get_fat_entry(unsigned int cluster) {
    unsigned int fat_offset = fat_begin + cluster*4;
    unsigned int val;
    memcpy(&val, disk + fat_offset, 4);
    return val & 0x0FFFFFFF; 
}

static void set_fat_entry(unsigned int cluster, unsigned int value) {
    for (int i=0; i<(int)num_fats; i++) {
        unsigned int fat_offset = fat_begin + i * fat_size * bytes_per_sector + cluster*4;
        unsigned int val = value & 0x0FFFFFFF;
        memcpy(disk + fat_offset, &val, 4);
    }
}

static void compute_sha1(const unsigned char *data, size_t size, unsigned char *out_digest) {
    SHA1(data, size, out_digest);
}

static int cmp_sha1_str(const unsigned char *digest, const char *sha1_str) {
    unsigned char expected[SHA_DIGEST_LENGTH];
    for (int i=0; i<SHA_DIGEST_LENGTH; i++) {
        char byte_str[3];
        byte_str[0] = sha1_str[i*2];
        byte_str[1] = sha1_str[i*2+1];
        byte_str[2] = '\0';
        unsigned int val;
        if (sscanf(byte_str, "%x", &val) != 1) return 0;
        expected[i] = (unsigned char)val;
    }
    return (memcmp(digest, expected, SHA_DIGEST_LENGTH)==0);
}

static int is_lfn_entry(const DirEntry *entry) {
    return ((entry->DIR_Attr & ATTR_LONG_NAME) == ATTR_LONG_NAME);
}

static int is_free_entry(const DirEntry *entry) {
    return (entry->DIR_Name[0] == 0x00);
}

static int is_deleted_entry(const DirEntry *entry) {
    return (entry->DIR_Name[0] == 0xE5);
}

static void get_filename(const DirEntry *entry, char *out) {
    char name[9];
    char ext[4];
    memcpy(name, entry->DIR_Name, 8);
    name[8] = '\0';
    memcpy(ext, entry->DIR_Name+8, 3);
    ext[3] = '\0';

    for (int i=7; i>=0 && name[i]==' '; i--) name[i]='\0';
    for (int i=2; i>=0 && ext[i]==' '; i--) ext[i]='\0';

    if (ext[0] == '\0')
        snprintf(out, 13, "%s", name);
    else
        snprintf(out, 13, "%s.%s", name, ext);
}

static unsigned char *read_file_data(unsigned int start_cluster, unsigned int file_size, int contig_only) {
    if (file_size == 0) {
        unsigned char *empty_buf = malloc(1);
        if (!empty_buf) return NULL;
        return empty_buf;
    }
    if (start_cluster == 0 && file_size > 0) {
        return NULL;
    }

    unsigned char *buf = malloc(file_size);
    if (!buf) return NULL;

    unsigned int cluster = start_cluster;
    unsigned int offset = 0;
    unsigned int cluster_bytes = bytes_per_cluster;
    unsigned int remaining = file_size;

    while (cluster < 0x0ffffff8 && remaining > 0) {
        unsigned int c_off = cluster_to_offset(cluster);
        unsigned int to_read = (remaining < cluster_bytes)? remaining: cluster_bytes;
        memcpy(buf+offset, disk+c_off, to_read);
        offset += to_read;
        remaining -= to_read;
        if (!contig_only) {
            cluster = get_fat_entry(cluster);
        } else {
            cluster++;
        }
    }

    if (remaining != 0) {
        free(buf);
        return NULL;
    }

    return buf;
}

static void list_root_directory() {
    unsigned int cluster = root_cluster;
    int count = 0;
    while (cluster < 0x0ffffff8) {
        unsigned int c_off = cluster_to_offset(cluster);
        int entries_per_cluster = bytes_per_cluster / 32;
        for (int i=0; i<entries_per_cluster; i++) {
            DirEntry *entry = (DirEntry *)(disk + c_off + i*32);
            if (is_free_entry(entry)) {
                continue;
            }
            if (is_lfn_entry(entry)) {
                continue;
            }
            if (is_deleted_entry(entry)) {
                continue;
            }

            if (entry->DIR_Attr & ATTR_VOLUME_ID) {
                continue;
            }

            char fname[13];
            get_filename(entry, fname);

            unsigned int start_cl = ((unsigned int)entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
            unsigned int size = entry->DIR_FileSize;

            if ((entry->DIR_Attr & ATTR_DIRECTORY) == ATTR_DIRECTORY) {
                printf("%s/ (starting cluster = %u)\n", fname, start_cl);
            } else {
                if (size == 0) {
                    printf("%s (size = 0)\n", fname);
                } else {
                    printf("%s (size = %u, starting cluster = %u)\n", fname, size, start_cl);
                }
            }
            count++;
        }
        cluster = get_fat_entry(cluster);
    }
    printf("Total number of entries = %d\n", count);
}

typedef struct {
    DirEntry entry;
    unsigned int cluster;
    int entry_index;
} DeletedCandidate;

static DeletedCandidate *find_deleted_candidates(const char *filename, int *count_out) {
    *count_out = 0;
    char name83[11];
    memset(name83, ' ', 11);

    {
        char *dot = strchr(filename, '.');
        char fname_part[9];
        char ext_part[4];
        memset(fname_part, ' ', 9);
        memset(ext_part, ' ', 4);

        if (dot) {
            int len_name = (int)(dot - filename);
            if (len_name > 8) len_name=8;
            for (int i=0; i<len_name; i++) fname_part[i] = (char)toupper((unsigned char)filename[i]);
            const char *e = dot+1;
            int len_ext = (int)strlen(e);
            if (len_ext > 3) len_ext=3;
            for (int i=0; i<len_ext; i++) ext_part[i] = (char)toupper((unsigned char)e[i]);
        } else {
            int len_name = (int)strlen(filename);
            if (len_name > 8) len_name=8;
            for (int i=0; i<len_name; i++) fname_part[i] = (char)toupper((unsigned char)filename[i]);
        }

        memcpy(name83, fname_part, 8);
        memcpy(name83+8, ext_part, 3);
    }

    DeletedCandidate *list = NULL;
    int capacity = 0;
    int count = 0;

    unsigned int cluster = root_cluster;
    while (cluster < 0x0ffffff8) {
        unsigned int c_off = cluster_to_offset(cluster);
        int entries_per_cluster = bytes_per_cluster/32;
        for (int i=0; i<entries_per_cluster; i++) {
            DirEntry *entry = (DirEntry *)(disk + c_off + i*32);
            if (is_free_entry(entry)) continue;
            if (is_lfn_entry(entry)) continue;
            if (!is_deleted_entry(entry)) continue;

            if (memcmp(entry->DIR_Name+1, name83+1, 10)==0) {
                if (capacity == count) {
                    capacity = (capacity==0)?4:capacity*2;
                    list = realloc(list, capacity*sizeof(DeletedCandidate));
                    if (!list) {
                        fprintf(stderr, "Memory allocation error.\n");
                        exit(1);
                    }
                }
                DeletedCandidate *cand = &list[count++];
                memcpy(&cand->entry, entry, sizeof(DirEntry));
                cand->cluster = cluster;
                cand->entry_index = i;
            }
        }
        cluster = get_fat_entry(cluster);
    }

    *count_out = count;
    return list;
}

static void restore_contiguous_file(DeletedCandidate *cand, const char *filename, const char *sha1_str, int use_sha1, int contig) {
    cand->entry.DIR_Name[0] = (unsigned char)toupper((unsigned char)filename[0]);

    unsigned int start_cl = ((unsigned int)cand->entry.DIR_FstClusHI <<16) | cand->entry.DIR_FstClusLO;
    unsigned int file_size = cand->entry.DIR_FileSize;

    if (file_size > 0 && start_cl == 0) {
        printf("%s: file not found\n", filename);
        return;
    }

    unsigned char *data = read_file_data(start_cl, file_size, contig);
    if (!data) {
        printf("%s: file not found\n", filename);
        return;
    }

    if (use_sha1) {
        unsigned char digest[SHA_DIGEST_LENGTH];
        compute_sha1(data, file_size, digest);
        if (!cmp_sha1_str(digest, sha1_str)) {
            free(data);
            printf("%s: file not found\n", filename);
            return;
        }
    }

    {
        unsigned int cluster_off = cluster_to_offset(cand->cluster);
        DirEntry *entry = (DirEntry *)(disk + cluster_off + cand->entry_index*32);
        memcpy(entry, &cand->entry, sizeof(DirEntry));
    }

    int cluster_count = (file_size == 0)?0:(file_size + bytes_per_cluster -1)/bytes_per_cluster;
    if (cluster_count == 0) {
        if (start_cl != 0) {
            set_fat_entry(start_cl, 0x0ffffff8);
        }
    } else {
        unsigned int c = start_cl;
        for (int i=1; i<cluster_count; i++) {
            unsigned int next = c+1;
            set_fat_entry(c, next);
            c = next;
        }
        set_fat_entry(c, 0x0ffffff8);
    }

    free(data);
    if (use_sha1)
        printf("%s: successfully recovered with SHA-1\n", filename);
    else
        printf("%s: successfully recovered\n", filename);
}

static int get_free_clusters(unsigned int *list, int max) {
    int count = 0;
    for (unsigned int c = 2; c < fat_size * bytes_per_sector / 4 && count < max; c++) {
        if (get_fat_entry(c) == 0x00000000) {
            list[count++] = c;
        }
    }
    return count;
}

static int try_noncont_permutations(
    unsigned int *free_clusters, int free_count, int needed,
    unsigned int start_cl, unsigned int file_size,
    const char *sha1_str,
    unsigned int *path, int depth, int start_idx, unsigned char *buf) {

    if (depth == needed || file_size == 0) {  // Check if we've reached the required depth OR the file size is 0
        unsigned int cluster_bytes = bytes_per_cluster;
        unsigned int remaining = file_size;
        unsigned int offset = 0;

        // Include start_cl in the chain
        unsigned int c_off = cluster_to_offset(start_cl);
        unsigned int to_read = (remaining < cluster_bytes) ? remaining : cluster_bytes;
        memcpy(buf + offset, disk + c_off, to_read);
        offset += to_read;
        remaining -= to_read;

        for (int i = 0; i < depth && remaining > 0; i++) {
            unsigned int c_off = cluster_to_offset(path[i]);
            unsigned int to_read = (remaining < cluster_bytes) ? remaining : cluster_bytes;
            memcpy(buf + offset, disk + c_off, to_read);
            offset += to_read;
            remaining -= to_read;
        }

        unsigned char digest[SHA_DIGEST_LENGTH];
        compute_sha1(buf, file_size, digest);
        return cmp_sha1_str(digest, sha1_str); 
    }

    for (int i = start_idx; i < free_count - (needed - depth) + 1; i++) {
        path[depth] = free_clusters[i];
        if (try_noncont_permutations(
                free_clusters, free_count, needed, start_cl, file_size, sha1_str,
                path, depth + 1, i + 1, buf)) {
            return 1; 
        }
    }
    return 0; 
}

static void finalize_noncontiguous_recovery(DeletedCandidate *cand, const char *filename,
                                            const char *sha1_str, unsigned int *chain, int chain_len) {
    cand->entry.DIR_Name[0] = (unsigned char)toupper((unsigned char)filename[0]);
    unsigned int start_cl = ((unsigned int)cand->entry.DIR_FstClusHI << 16) | cand->entry.DIR_FstClusLO;

    // Update directory entry
    unsigned int cluster_off = cluster_to_offset(cand->cluster);
    DirEntry *entry = (DirEntry *)(disk + cluster_off + cand->entry_index * 32);
    memcpy(entry, &cand->entry, sizeof(DirEntry));

    // Update FAT chain
    if (chain_len > 0) {
        set_fat_entry(start_cl, chain[0]); // Link the first cluster to the chain
        for (int i = 0; i < chain_len - 1; i++) {
            set_fat_entry(chain[i], chain[i + 1]);
        }
        set_fat_entry(chain[chain_len - 1], 0x0ffffff8); // Mark the end of the chain
    } else {
        // If chain_len is 0, it means the file fits in the first cluster
        set_fat_entry(start_cl, 0x0ffffff8); // Mark the end of the chain
    }

    printf("%s: successfully recovered with SHA-1\n", filename);
}

static void recover_noncontiguous_file(
    DeletedCandidate *candidates, int cand_count, const char *filename, const char *sha1_str) {

    if (cand_count == 0) {
        printf("%s: file not found\n", filename);
        return;
    }

    if (!sha1_str && cand_count > 1) {
        printf("%s: multiple candidates found\n", filename);
        return;
    }

    for (int i = 0; i < cand_count; i++) {
        DeletedCandidate *cand = &candidates[i];
        unsigned int start_cl = ((unsigned int)cand->entry.DIR_FstClusHI << 16) | cand->entry.DIR_FstClusLO;
        unsigned int file_size = cand->entry.DIR_FileSize;

        if (file_size > 0 && start_cl == 0) {
            continue;
        }

        int cluster_count = (file_size == 0) ? 0 : (file_size + bytes_per_cluster - 1) / bytes_per_cluster;

        unsigned int free_list[20];
        int free_count = get_free_clusters(free_list, 20);
        int needed = cluster_count - 1; // Subtract 1 to account for start_cl already being used
        if (free_count < needed) continue;

        unsigned char *buf = malloc(file_size);
        if (!buf) continue;

        unsigned int path[5];
        if (try_noncont_permutations(
                free_list, free_count, needed, start_cl, file_size, sha1_str,
                path, 0, 0, buf)) {
            finalize_noncontiguous_recovery(cand, filename, sha1_str, path, needed);
            free(buf);
            return;
        }
        free(buf);
    }

    printf("%s: file not found\n", filename);
}

static void recover_file(const char *filename, const char *sha1_str, int noncontig) {
    int cand_count=0;
    DeletedCandidate *candidates = find_deleted_candidates(filename, &cand_count);
    if (!candidates && cand_count>0) {
        printf("%s: file not found\n", filename);
        return;
    }

    if (cand_count==0) {
        printf("%s: file not found\n", filename);
        free(candidates);
        return;
    }

    if (!noncontig) {
        if (!sha1_str && cand_count>1) {
            printf("%s: multiple candidates found\n", filename);
            free(candidates);
            return;
        }

        if (!sha1_str) {
            restore_contiguous_file(&candidates[0], filename, NULL, 0, 1);
        } else {
            int matches=0;
            int match_idx=-1;
            for (int i=0; i<cand_count; i++) {
                DeletedCandidate *cand=&candidates[i];
                unsigned int start_cl=((unsigned int)cand->entry.DIR_FstClusHI<<16)|cand->entry.DIR_FstClusLO;
                unsigned int file_size=cand->entry.DIR_FileSize;
                if (file_size>0 && start_cl==0) {
                    continue;
                }
                unsigned char *data=read_file_data(start_cl, file_size, 1);
                if (!data) continue;
                unsigned char digest[SHA_DIGEST_LENGTH];
                compute_sha1(data, file_size, digest);
                free(data);
                if (cmp_sha1_str(digest, sha1_str)) {
                    matches++;
                    match_idx=i;
                }
            }
            if (matches==0) {
                printf("%s: file not found\n", filename);
            } else if (matches>1) {
                printf("%s: multiple candidates found\n", filename);
            } else {
                restore_contiguous_file(&candidates[match_idx], filename, sha1_str, 1, 1);
            }
        }
    } else {
        recover_noncontiguous_file(candidates, cand_count, filename, sha1_str);
    }

    free(candidates);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    const char *disk_name = argv[1];

    if (argc == 2) {
        print_usage();
        return 1;
    }

    int show_info=0, list_root_opt=0, recover_opt=0, recover_noncontig=0;
    char *recover_filename=NULL;
    char *sha1_str=NULL;

    int i=2;
    while (i<argc) {
        if (strcmp(argv[i], "-i")==0) {
            if (show_info || list_root_opt || recover_opt || recover_noncontig) {
                print_usage();
                return 1;
            }
            show_info=1;
            i++;
        } else if (strcmp(argv[i], "-l")==0) {
            if (show_info || list_root_opt || recover_opt || recover_noncontig) {
                print_usage();
                return 1;
            }
            list_root_opt=1;
            i++;
        } else if (strcmp(argv[i], "-r")==0) {
            if (show_info || list_root_opt || recover_opt || recover_noncontig) {
                print_usage();
                return 1;
            }
            if (i+1>=argc) {
                print_usage();
                return 1;
            }
            recover_opt=1;
            recover_filename=argv[i+1];
            i+=2;
            if (i<argc && strcmp(argv[i], "-s")==0) {
                if (i+1>=argc) {
                    print_usage();
                    return 1;
                }
                sha1_str=argv[i+1];
                i+=2;
            }
        } else if (strcmp(argv[i], "-R")==0) {
            if (show_info || list_root_opt || recover_opt || recover_noncontig) {
                print_usage();
                return 1;
            }
            if (i+1>=argc) {
                print_usage();
                return 1;
            }
            recover_noncontig=1;
            recover_filename=argv[i+1];
            i+=2;
            if (i>=argc || strcmp(argv[i], "-s")!=0) {
                print_usage();
                return 1;
            }
            if (i+1>=argc) {
                print_usage();
                return 1;
            }
            sha1_str=argv[i+1];
            i+=2;
        } else {
            print_usage();
            return 1;
        }
    }

    int ops = show_info + list_root_opt + recover_opt + recover_noncontig;
    if (ops != 1) {
        print_usage();
        return 1;
    }

    int fd = open(disk_name, O_RDWR);
    if (fd<0) {
        perror("open");
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st)<0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    disk_size=st.st_size;
    disk=mmap(NULL, disk_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (disk==MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }

    boot=(BootEntry *)disk;
    bytes_per_sector=boot->BPB_BytsPerSec;
    sectors_per_cluster=boot->BPB_SecPerClus;
    reserved_sectors=boot->BPB_RsvdSecCnt;
    num_fats=boot->BPB_NumFATs;
    fat_size=boot->BPB_FATSz32; 
    root_cluster=boot->BPB_RootClus;
    bytes_per_cluster=bytes_per_sector*sectors_per_cluster;
    fat_begin = reserved_sectors * bytes_per_sector;
    cluster_begin = (reserved_sectors + num_fats*fat_size)*bytes_per_sector;

    if (show_info) {
        printf("Number of FATs = %u\n", num_fats);
        printf("Number of bytes per sector = %u\n", bytes_per_sector);
        printf("Number of sectors per cluster = %u\n", sectors_per_cluster);
        printf("Number of reserved sectors = %u\n", reserved_sectors);
    } else if (list_root_opt) {
        list_root_directory();
    } else if (recover_opt) {
        recover_file(recover_filename, sha1_str, 0);
    } else if (recover_noncontig) {
        recover_file(recover_filename, sha1_str, 1);
    }

    munmap(disk, disk_size);
    close(fd);
    return 0;
}