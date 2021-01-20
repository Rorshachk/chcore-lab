#include "tmpfs.h"

#include <defs.h>
#include <syscall.h>
#include <string.h>
#include <cpio.h>
#include <launcher.h>

static struct inode *tmpfs_root;

/*
 * Helper functions to calucate hash value of string
 */
static inline u64 hash_chars(const char *str, ssize_t len)
{
	u64 seed = 131;		/* 31 131 1313 13131 131313 etc.. */
	u64 hash = 0;
	int i;

	if (len < 0) {
		while (*str) {
			hash = (hash * seed) + *str;
			str++;
		}
	} else {
		for (i = 0; i < len; ++i)
			hash = (hash * seed) + str[i];
	}

	return hash;
}

/* BKDR hash */
static inline u64 hash_string(struct string *s)
{
	return (s->hash = hash_chars(s->str, s->len));
}

static inline int init_string(struct string *s, const char *name, size_t len)
{
	int i;

	s->str = malloc(len + 1);
	if (!s->str)
		return -ENOMEM;
	s->len = len;

	for (i = 0; i < len; ++i)
		s->str[i] = name[i];
	s->str[len] = '\0';

	hash_string(s);
	return 0;
}

/*
 *  Helper functions to create instances of key structures
 */
static inline struct inode *new_inode(void)
{
    // printf("Before malloc\n");
	struct inode *inode = malloc(sizeof(*inode));
    // printf("After malloc: %x\n", (int)inode);

    // printf("type: %d\n", (int)inode->type);
    // printf("size: %d\n", (int)inode->size);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->type = 0;
	inode->size = 0;

	return inode;
}

static struct inode *new_dir(void)
{
	struct inode *inode;

	inode = new_inode();

    // printf("New node finished\n");

	if (IS_ERR(inode))
		return inode;
	inode->type = FS_DIR;
	init_htable(&inode->dentries, 1024);

	return inode;
}

static struct inode *new_reg(void)
{
	struct inode *inode;

	inode = new_inode();
	if (IS_ERR(inode))
		return inode;
	inode->type = FS_REG;
	init_radix_w_deleter(&inode->data, free);

	return inode;
}

static struct dentry *new_dent(struct inode *inode, const char *name,
			       size_t len)
{
	struct dentry *dent;
	int err;

	dent = malloc(sizeof(*dent));
	if (!dent)
		return ERR_PTR(-ENOMEM);
	err = init_string(&dent->name, name, len);
	if (err) {
		free(dent);
		return ERR_PTR(err);
	}
	dent->inode = inode;

	return dent;
}


// look up a file called `name` under the inode `dir` 
// and return the dentry of this file
static struct dentry *tfs_lookup(struct inode *dir, const char *name,
				 size_t len)
{
	u64 hash = hash_chars(name, len);


	struct dentry *dent;
	struct hlist_head *head;

	head = htable_get_bucket(&dir->dentries, (u32) hash);

	for_each_in_hlist(dent, node, head) {
        
        // if(strcmp(name, "dir") == 0)
        //   printf("dir name: %s\n", dent->name.str);

		if (dent->name.len == len && 0 == strcmp(dent->name.str, name))
			return dent;
	}
	return NULL;
}

// this function create a file (directory if `mkdir` == true, otherwise regular
// file) and its size is `len`. You should create an inode and corresponding 
// dentry, then add dentey to `dir`'s htable by `htable_add`.
// Assume that no separator ('/') in `name`.
static int tfs_mknod(struct inode *dir, const char *name, size_t len, int mkdir)
{
	struct inode *inode;
	struct dentry *dent;


    

	BUG_ON(!name);

	if (len == 0) {
		WARN("mknod with len of 0");
		return -ENOENT;
	}
	// TODO: write your code here


    // if(strcmp(name, "dir2") == 0){
    //     printf("Got here!\n");
    //     dent = tfs_lookup(tmpfs_root, "dir", 3);
    //     if(dent->inode != dir)
    //       printf("Directory error!\n");
    // }


    if(mkdir == true)
        inode = new_dir();
    else
        inode = new_reg();

    dent = new_dent(inode, name, len);
    init_hlist_node(&dent->node);
    htable_add(&dir->dentries, (u32)hash_chars(name, len), &dent->node);

    // if(strcmp(name, "file") == 0 && dir == tmpfs_root){
    //     printf("\ntfs make node for file\n");
    //     printf("hash value: %u\n", (u32)hash_chars(name, len));
    //     printf("file length: %d\n", len);
    //     dent = tfs_lookup(dir, name, len);
    //     if(dent == NULL);
    //       printf("mknod actually failed!!\n\n");
    // }

    // if(strcmp(name, "dir2") == 0){
    //     dent = tfs_lookup(dir, name, len);
    //     printf("check mknod.\n");
    //     if(dent == NULL)
    //       printf("mknod failed!\n");
    // }
	return 0;
}

int tfs_mkdir(struct inode *dir, const char *name, size_t len)
{
	return tfs_mknod(dir, name, len, 1 /* mkdir */ );
}

int tfs_creat(struct inode *dir, const char *name, size_t len)
{
	return tfs_mknod(dir, name, len, 0 /* mkdir */ );
}


// Walk the file system structure to locate a file with the pathname stored in `*name`
// and saves parent dir to `*dirat` and the filename to `*name`.
// If `mkdir_p` is true, you need to create intermediate directories when it missing.
// If the pathname `*name` starts with '/', then lookup starts from `tmpfs_root`, 
// else from `*dirat`.
// Note that when `*name` ends with '/', the inode of last component will be
// saved in `*dirat` regardless of its type (e.g., even when it's FS_REG) and
// `*name` will point to '\0'
int tfs_namex(struct inode **dirat, const char **name, int mkdir_p)
{
	BUG_ON(dirat == NULL);
	BUG_ON(name == NULL);
	BUG_ON(*name == NULL);

	char buff[MAX_FILENAME_LEN + 1];
    memset(buff, 0, sizeof(buff));
	int i;
	struct dentry *dent;
	int err;

	if (**name == '/') {
		*dirat = tmpfs_root;
		// make sure `name` starts with actual name
		while (**name && **name == '/')
			++(*name);
	} else {
		BUG_ON(*dirat == NULL);
		BUG_ON((*dirat)->type != FS_DIR);
	}

    // make sure a child name exists
	if (!**name)
		return -EINVAL;
    

    size_t len = 0;
    i = 0;

//    printf("NameX Start:\n");

    int flg = 0;
    if(strcmp(*name, "dir/dir2") == 0){
  //      printf("\n reach here \n");
        flg = 1;
    }

    while((*name)[i]){
//        printf("print *name i: %c\n", (*name)[i]);
        if((*name)[i] == '/'){

            // if(flg){
            //     buff[len] = '\0';
            //     printf("length: %d\n", len);
            //     printf("directory name: %s\n", buff);

            //     if(*dirat == tmpfs_root){
            //         printf("directory correct.\n");
            //     }
            //     else printf("directory incorrect!\n");
            //     printf("\n\n\n\n");
            // }

            dent = tfs_lookup(*dirat, buff, len);
            if(dent == NULL){
                if(!mkdir_p) return -ENOENT;

//                printf("Create directory %s\n", buff);
                tfs_mkdir(*dirat, buff, len);
                dent = tfs_lookup(*dirat, buff, len);
            }
            *dirat = dent->inode;
            *name += (i + 1);

//            printf("name after slash: %s\n", *name);
            len = 0;
            i = 0;
        }
        buff[len++] = (*name)[i++];
    }

    buff[len] = '\0';
    // if(flg && !mkdir_p){
    //     printf("Check final lookup.\n");
    //     dent = tfs_lookup(tmpfs_root, "dir", 3);
    //     if(dent->inode == *dirat)
    //       printf("directory correct.\n");
        

    //     printf("buf length: %d\n", strlen(buff));
    //     printf("leaf name: %s\n", buff);
    // }
    dent = tfs_lookup(*dirat, buff, len);
    if(dent == NULL){
        //Not sure what to do if the last component doesn't exist and mkdir_p is true
        return -ENOENT;
    }

	return 0;
}

int tfs_remove(struct inode *dir, const char *name, size_t len)
{
	u64 hash = hash_chars(name, len);
	struct dentry *dent, *target = NULL;
	struct hlist_head *head;

	BUG_ON(!name);

	if (len == 0) {
		WARN("mknod with len of 0");
		return -ENOENT;
	}

	head = htable_get_bucket(&dir->dentries, (u32) hash);

	for_each_in_hlist(dent, node, head) {
		if (dent->name.len == len && 0 == strcmp(dent->name.str, name)) {
			target = dent;
			break;
		}
	}

	if (!target)
		return -ENOENT;

	BUG_ON(!target->inode);

	// remove only when file is closed by all processes
	if (target->inode->type == FS_REG) {
		// free radix tree
		radix_free(&target->inode->data);
		// free inode
		free(target->inode);
		// remove dentry from parent
		htable_del(&target->node);
		// free dentry
		free(target);
	} else if (target->inode->type == FS_DIR) {
		if (!htable_empty(&target->inode->dentries))
			return -ENOTEMPTY;

		// free htable
		htable_free(&target->inode->dentries);
		// free inode
		free(target->inode);
		// remove dentry from parent
		htable_del(&target->node);
		// free dentry
		free(target);
	} else {
		BUG("inode type that shall not exist");
	}

	return 0;
}

int init_tmpfs(void)
{
    // printf("try making new node.\n");
	tmpfs_root = new_dir();

	return 0;
}

// write memory into `inode` at `offset` from `buf` for length is `size`
// it may resize the file
// `radix_get`, `radix_add` are used in this function
// You can use memory functions defined in libc
ssize_t tfs_file_write(struct inode * inode, off_t offset, const char *data,
		       size_t size)
{
	BUG_ON(inode->type != FS_REG);
	BUG_ON(offset > inode->size);

	u64 page_no, page_off;
	u64 cur_off = offset;
	size_t to_write;
	void *page;

	// TODO: write your code here

    size_t st = offset, ed = offset + size;
    int ret;
    
    //printf("Start writing:\n");
    
    while(st < ed){
        size_t cur_page_st = ROUND_DOWN(st, PAGE_SIZE);
        size_t cur_page_ed = cur_page_st + PAGE_SIZE;

        if(cur_page_ed >= inode->size){
            page = malloc(PAGE_SIZE);
            if(!page)  return -ENOENT;
            
            // printf("Allocated address: %llx\n", (u64)page);
            
            if(ret = radix_add(&inode->data, cur_page_st, page) < 0)
              return ret;
            
            inode->size = cur_page_ed;
            
            // printf("Allocate address successfully.\n");
        }

        page = radix_get(&inode->data, cur_page_st);
        to_write = MIN(cur_page_ed - st, ed - st);

    //    printf("Write %x bytes to address %x\n", to_write, (int)page);

        memcpy(page + st - cur_page_st, data, to_write);
        st += to_write;
        data += to_write;
    }

    // if(offset == 0 && size == 2 * PAGE_SIZE){
    //     printf("File size After Writing: %d\n", inode->size);
    // }


	return st - offset;
}

// read memory from `inode` at `offset` in to `buf` for length is `size`, do not
// exceed the file size
// `radix_get` is used in this function
// You can use memory functions defined in libc
ssize_t tfs_file_read(struct inode * inode, off_t offset, char *buff,
		      size_t size)
{
	BUG_ON(inode->type != FS_REG);
	BUG_ON(offset > inode->size);

	u64 page_no, page_off;
	u64 cur_off = offset;
	size_t to_read;
	void *page;

    size_t st = offset;
    size_t ed = MIN(inode->size, offset + size);

    // printf("Read start: %d, End: %d\n", st, ed);

    while(st < ed){
        size_t cur_page_st = ROUND_DOWN(st, PAGE_SIZE);
        size_t cur_page_ed = cur_page_st + PAGE_SIZE;
        page = radix_get(&inode->data, cur_page_st);
        to_read = MIN(cur_page_ed - st, ed - st);
        memcpy(buff, page + st - cur_page_st, to_read);
        st += to_read;
        buff += to_read;
    }

	return st - offset;
}

// load the cpio archive into tmpfs with the begin address as `start` in memory
// You need to create directories and files if necessary. You also need to write
// the data into the tmpfs.
int tfs_load_image(const char *start)
{

// See https://www.systutorials.com/docs/linux/man/5-cpio/
#define CPIO_MASK_BIT 0170000
#define CPIO_DIR 0040000
#define CPIO_REG 0100000

	struct cpio_file *f;
	struct inode *dirat;
	struct dentry *dent;
	const char *leaf;
	size_t len;
	int err;
	ssize_t write_count;

	BUG_ON(start == NULL);

	cpio_init_g_files();
	cpio_extract(start, "/");

	for (f = g_files.head.next; f; f = f->next) {
		// TODO: Lab5: your code is here
        dirat = tmpfs_root;
        leaf = f->name;
        
    //    printf("CPIO File: %s\n", leaf);
        
        err = tfs_namex(&dirat, &leaf, 1);
        if(err < 0 && err != -ENOENT) return err;
        u64 f_type = f->header.c_mode & CPIO_MASK_BIT;
        
        // printf("namex status: %d\n", err);
        // printf("CPIO File After namex: \n");
        // printf("File: %s\n", leaf);
        // printf("File cmoode: %o\n", f->header.c_mode);
        // printf("File type: %o\n", f_type);
        
        
        if(err == -ENOENT){
            if(f_type == CPIO_DIR){
                tfs_mkdir(dirat, leaf, strlen(leaf));
            }

            else if(f_type == CPIO_REG){
                tfs_creat(dirat, leaf, strlen(leaf));
            }
            else return -EINVAL;
            // printf("successfully create directory or file\n");    
        }

        // if(dirat == tmpfs_root)
        //   printf("dirat is the root\n");
        // printf("%s\n", leaf);
        dent = tfs_lookup(dirat, leaf, strlen(leaf));
        
        // if(dent == NULL){
        //     printf("Can't find dentry!\n");
        // }

        if(f_type == CPIO_REG){
            // printf("before write:\n");
            err = tfs_file_write(dent->inode, 0, f->data, f->header.c_filesize);
            if(err < 0) return err;
            // printf("Write successful!\n");
        }
        // printf("\n");
	}

//    printf("reach here!\n");
	return 0;
}

static int dirent_filler(void **dirpp, void *end, char *name, off_t off,
			 unsigned char type, ino_t ino)
{
	struct dirent *dirp = *(struct dirent **)dirpp;
	void *p = dirp;
	unsigned short len = strlen(name) + 1 +
	    sizeof(dirp->d_ino) +
	    sizeof(dirp->d_off) + sizeof(dirp->d_reclen) + sizeof(dirp->d_type);
	p += len;
	if (p > end)
		return -EAGAIN;
	dirp->d_ino = ino;
	dirp->d_off = off;
	dirp->d_reclen = len;
	dirp->d_type = type;
	strcpy(dirp->d_name, name);
	*dirpp = p;
	return len;
}

int tfs_scan(struct inode *dir, unsigned int start, void *buf, void *end)
{
	s64 cnt = 0;
	int b;
	int ret;
	ino_t ino;
	void *p = buf;
	unsigned char type;
	struct dentry *iter;

	for_each_in_htable(iter, b, node, &dir->dentries) {
		if (cnt >= start) {
			type = iter->inode->type;
			ino = iter->inode->size;
			ret = dirent_filler(&p, end, iter->name.str,
					    cnt, type, ino);
			if (ret <= 0) {
				return cnt - start;
			}
		}
		cnt++;
	}
	return cnt - start;

}

/* path[0] must be '/' */
struct inode *tfs_open_path(const char *path)
{
	struct inode *dirat = NULL;
	const char *leaf = path;
	struct dentry *dent;
	int err;

	if (*path == '/' && !*(path + 1))
		return tmpfs_root;

	err = tfs_namex(&dirat, &leaf, 0);
	if (err)
		return NULL;

	dent = tfs_lookup(dirat, leaf, strlen(leaf));
	return dent ? dent->inode : NULL;
}
