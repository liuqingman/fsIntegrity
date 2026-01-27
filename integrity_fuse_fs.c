#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

char underlying[512];

// 根据文件路径生成 hash 文件路径（如 /xdata/config.txt -> /xdata/config.txt.hash）
void get_hash_file(const char *filepath, char *hashpath, size_t size) {
    snprintf(hashpath, size, "%s.hash", filepath);
}

// 计算文件SHA256
int file_sha256(const char *path, char *out_hex) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char buf[4096];
    SHA256_CTX ctx;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[file_sha256] fopen failed: %s (%s)\n", path, strerror(errno));
        return -1;
    }
    SHA256_Init(&ctx);
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        SHA256_Update(&ctx, buf, n);
    if (ferror(f)) {
        fprintf(stderr, "[file_sha256] fread error: %s (%s)\n", path, strerror(errno));
        fclose(f);
        return -1;
    }
    fclose(f);
    SHA256_Final(hash, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out_hex + i*2, "%02x", hash[i]);
    out_hex[64] = 0;
    return 0;
}

// 读取hash文件
int read_hash(const char *filepath, char *out_hex) {
    char hashpath[512];
    get_hash_file(filepath, hashpath, sizeof(hashpath));
    FILE *f = fopen(hashpath, "r");
    if (!f) {
        fprintf(stderr, "[read_hash] fopen failed: %s (%s)\n", hashpath, strerror(errno));
        return -1;
    }
    if (!fgets(out_hex, 65, f)) {
        fprintf(stderr, "[read_hash] fgets failed: %s\n", hashpath);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

int write_hash(const char *filepath, const char *hex) {
    char hashpath[512];
    get_hash_file(filepath, hashpath, sizeof(hashpath));
    FILE *f = fopen(hashpath, "w");
    if (!f) {
        fprintf(stderr, "[write_hash] fopen failed: %s (%s)\n", hashpath, strerror(errno));
        return -1;
    }
    if (fprintf(f, "%s\n", hex) < 0) {
        fprintf(stderr, "[write_hash] fprintf failed: %s (%s)\n", hashpath, strerror(errno));
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int integrity_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    char full[512];
    snprintf(full, sizeof(full), "%s%s", underlying, path);
    int ret = lstat(full, stbuf);
    if (ret != 0) {
        fprintf(stderr, "[getattr] lstat failed: %s (%s)\n", full, strerror(errno));
    }
    return ret;
}

static int integrity_open(const char *path, struct fuse_file_info *fi) {
    char full[512];
    snprintf(full, sizeof(full), "%s%s", underlying, path);
    if ((fi->flags & O_ACCMODE) == O_RDONLY) {
        char hash[65], cur[65];
        if (file_sha256(full, cur) != 0 || read_hash(full, hash) != 0) {
            fprintf(stderr, "[open] integrity check failed: %s\n", full);
            return -EIO;
        }
        if (strcmp(hash, cur) != 0) {
            fprintf(stderr, "[open] hash mismatch: %s\n", full);
            return -EACCES; // 校验失败
        }
    }
    int fd = open(full, fi->flags);
    if (fd == -1) {
        fprintf(stderr, "[open] open failed: %s (%s)\n", full, strerror(errno));
        return -errno;
    }
    fi->fh = fd;
    return 0;
}

static int integrity_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int res = pread(fi->fh, buf, size, offset);
    if (res == -1) {
        fprintf(stderr, "[read] pread failed: fd=%d (%s)\n", (int)fi->fh, strerror(errno));
        res = -errno;
    }
    return res;
}

static int integrity_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) {
        fprintf(stderr, "[write] pwrite failed: fd=%d (%s)\n", (int)fi->fh, strerror(errno));
        res = -errno;
    }
    return res;
}

static int integrity_flush(const char *path, struct fuse_file_info *fi) {
    // mmap 写入后，flush 时自动更新 hash
    char full[512], hash[65];
    snprintf(full, sizeof(full), "%s%s", underlying, path);
    if (file_sha256(full, hash) == 0) {
        if (write_hash(full, hash) != 0) {
            fprintf(stderr, "[flush] write_hash failed: %s\n", full);
        }
    } else {
        fprintf(stderr, "[flush] file_sha256 failed: %s\n", full);
    }
    return 0;
}

static int integrity_release(const char *path, struct fuse_file_info *fi) {
    // 关闭时也更新 hash
    char full[512], hash[65];
    snprintf(full, sizeof(full), "%s%s", underlying, path);
    if (file_sha256(full, hash) == 0) {
        if (write_hash(full, hash) != 0) {
            fprintf(stderr, "[release] write_hash failed: %s\n", full);
        }
    } else {
        fprintf(stderr, "[release] file_sha256 failed: %s\n", full);
    }
    close(fi->fh);
    return 0;
}

static int integrity_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    if (fsync(fi->fh) == -1) {
        fprintf(stderr, "[fsync] fsync failed: fd=%d (%s)\n", (int)fi->fh, strerror(errno));
        return -errno;
    }
    return 0;
}

// 支持 ls 挂载点目录
static int integrity_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                             off_t offset, struct fuse_file_info *fi,
                             enum fuse_readdir_flags flags) {
    char full[512];
    snprintf(full, sizeof(full), "%s%s", underlying, path);
    DIR *dp = opendir(full);
    if (!dp) {
        fprintf(stderr, "[readdir] opendir failed: %s (%s)\n", full, strerror(errno));
        return -errno;
    }
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (filler(buf, de->d_name, NULL, 0, 0))
            break;
    }
    closedir(dp);
    return 0;
}

static struct fuse_operations ops = {
    .getattr = integrity_getattr,
    .open = integrity_open,
    .read = integrity_read,
    .write = integrity_write,
    .flush = integrity_flush,
    .fsync = integrity_fsync,
    .release = integrity_release,
    .readdir = integrity_readdir,
};

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "用法: %s <底层目录> <挂载点> [FUSE参数]\n", argv[0]);
        return 1;
    }
    strncpy(underlying, argv[1], sizeof(underlying)-1);
    underlying[sizeof(underlying)-1] = '\0';
    // 构造新的 argv，跳过前一个参数
    int new_argc = argc - 1;
    char **new_argv = argv;
    new_argv[1] = argv[2]; // 挂载点
    return fuse_main(new_argc, new_argv, &ops, NULL);
}

