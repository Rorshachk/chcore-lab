#include "tmpfs_server.h"

#include <syscall.h>

// int fs_stat(const char *pathname, struct stat *statbuf);
// int fs_getdents(int fd, struct dirent *dirp, size_t count);

int fs_server_init(u64 cpio_start)
{
//    printf("Start init tmpfs\n");
	init_tmpfs();
//    printf("Start call usys_fs_load_cpio\n");
	usys_fs_load_cpio(cpio_start);
	return tfs_load_image((char *)cpio_start);
}

int fs_server_mkdir(const char *path)
{
	struct inode *dirat = NULL;
	const char *leaf = path;
	int err;

	BUG_ON(!path);
	BUG_ON(*path != '/');

	// TODO: your code here
    // int flg = 0;
    // if(strcmp(path, "/dir/dir2") == 0)
    //   flg = 1;

    err = tfs_namex(&dirat, &leaf, 1);
    if(err < 0 && err != -ENOENT) return err;

    // if(flg){
    //     printf("mkdir namex returns: \n");
    //     printf("leaf: %s\n", leaf);
    // }

    err = tfs_mkdir(dirat, leaf, strlen(leaf));
	return err;
}

int fs_server_creat(const char *path)
{
	struct inode *dirat = NULL;
	const char *leaf = path;
	int err;

	BUG_ON(!path);
	BUG_ON(*path != '/');

	// TODO: your code here
    err = tfs_namex(&dirat, &leaf, 0);
    if(err < 0 && err != -ENOENT) return err;
    // if(dirat == NULL)
    //   printf("Something went wrong on file %s!\n", leaf);

    // printf("Ready to create file %s\n", leaf);
    err = tfs_creat(dirat, leaf, strlen(leaf));


    if(err){
        printf("File create error!\n");
        return err;
    }
	return 0;
}

int fs_server_unlink(const char *path)
{
	struct inode *dirat = NULL;
	const char *leaf = path;
	int err;

	BUG_ON(!path);
	BUG_ON(*path != '/');

	// TODO: your code here
    err = tfs_namex(&dirat, &leaf, 0);
    if(err < 0) return err;
    err = tfs_remove(dirat, leaf, strlen(leaf));
	return err;
}

int fs_server_rmdir(const char *path)
{
    // printf("remove path: %s\n", path);

	struct inode *dirat = NULL;
	const char *leaf = path;
	int err;

	BUG_ON(!path);
	BUG_ON(*path != '/');

	// TODO: your code here
    err = tfs_namex(&dirat, &leaf, 0);
    // printf("remove leaf: %s\n", leaf);
    if(err < 0){
        printf("namex error!\n");
        return err;
    }
    err = tfs_remove(dirat, leaf, strlen(leaf));
	return err;
}

/* use absolute path, offset and count to read directly */
int fs_server_read(const char *path, off_t offset, void *buf, size_t count)
{
	struct inode *inode;
	int ret = -ENOENT;

	BUG_ON(!path);
	BUG_ON(*path != '/');

	// TODO: your code here
    inode = tfs_open_path(path);
    if(!inode) return ret;
    ret = tfs_file_read(inode, offset, buf, count);
	return ret;
}

/* use absolute path, offset and count to write directly */
int fs_server_write(const char *path, off_t offset, const void *buf,
		    size_t count)
{
	struct inode *inode;
	int ret = -ENOENT;

	BUG_ON(!path);
	BUG_ON(*path != '/');

	// TODO: your code here
    inode = tfs_open_path(path);

    if(!inode){
        printf("file open error!\n");
        return ret;
    }

    ret = tfs_file_write(inode, offset, buf, count);
	return ret;
}

ssize_t fs_server_get_size(const char *path)
{
	struct inode *inode;
	int ret = -ENOENT;

	BUG_ON(!path);
	BUG_ON(*path != '/');

	inode = tfs_open_path(path);
	if (inode)
		ret = inode->size;
	return ret;
}

/* Scan several dirent structures from the directory referred to by the path
 * into the buffer pointed by dirp. The argument count specifies the size of
 * that buffer.
 *
 * RETURN VALUE
 * On success, the number of items is returned. On end of directory, 0 is
 * returned. On error, -errno is returned.
 *
 * The caller should call this function over and over again until it returns 0
 * */
int fs_server_scan(const char *path, unsigned int start, void *buf,
		   unsigned int count)
{
	struct inode *inode;

	BUG_ON(!path);
	BUG_ON(*path != '/');

	inode = tfs_open_path(path);
	if (inode) {
		if (inode->type == FS_DIR)
			return tfs_scan(inode, start, buf, buf + count);
		return -ENOTDIR;
	}
	return -ENOENT;
}
