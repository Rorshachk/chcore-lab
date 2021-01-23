#include <print.h>
#include <syscall.h>
#include <launcher.h>
#include <defs.h>
#include <bug.h>
#include <fs_defs.h>
#include <ipc.h>
#include <string.h>
#include <proc.h>
#include <malloc.h>

#define SERVER_READY_FLAG(vaddr) (*(int *)(vaddr))
#define SERVER_EXIT_FLAG(vaddr)  (*(int *)((u64)vaddr+ 4))
#define READ_BUF_SIZE 0x100000      //1M for file read buf size

extern ipc_struct_t *tmpfs_ipc_struct;
static ipc_struct_t ipc_struct;
static int tmpfs_scan_pmo_cap, tmpfs_read_pmo_cap;

static char current_path[256] = {'/'};

/* fs_server_cap in current process; can be copied to others */
int fs_server_cap;

#define BUFLEN	4096

static int do_complement(char *buf, char *complement, int complement_time)
{
	int r = -1;
	// TODO: your code here

	return r;

}

extern char getch();

// read a command from stdin leading by `prompt`
// put the commond in `buf` and return `buf`
// What you typed should be displayed on the screen
char *readline(const char *prompt)
{
	static char buf[BUFLEN];

	int i = 0, j = 0;
	signed char c = 0;
	int ret = 0;
	char complement[BUFLEN];
	int complement_time = 0;

	if (prompt != NULL) {
		printf("%s", prompt);
	}

    memset(buf, 0, sizeof(buf));
	while (1) {
		c = getch();
		if (c < 0)
			return NULL;
		// TODO: your code here

        if(c == '\n' || c == '\r')   //seems the end of line is \r
          break;
        usys_putc(c);
        buf[i++] = c;
	}
    printf("\n");
	return buf;
}


int fs_getsize(char *path){
    struct fs_request fr;
    ipc_msg_t *ipc_msg;
    int ret;


    fr.req = FS_REQ_GET_SIZE;
    strcpy(fr.path, path);

    ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(fr), 0);
    ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(fr));
    ret = ipc_call(tmpfs_ipc_struct, ipc_msg);

    return ret;
}

int do_cd(char *cmdline)
{
    char path[BUFLEN];
    memset(path, 0, sizeof(path));
	cmdline += 2;
	while (*cmdline == ' ')
		cmdline++;
	if (*cmdline == '\0')
		return 0;
	if (*cmdline != '/') {
//        printf("current: %s\n", current_path);
        strcat(path, current_path);
	}
    strcat(path, cmdline);
    int ret = fs_getsize(path);

    if(ret == -ENOENT)
        printf("No such directory!\n");
    
    else strcpy(current_path, path);
	return 0;
}

int do_top()
{
	// TODO: your code here
	return 0;
}

void fs_scan(char *path)
{
	// TODO: your code here
   // printf("start fs_scan\n");
    struct fs_request fr;
    ipc_msg_t *ipc_msg;
    int ret;


    fr.req = FS_REQ_SCAN;
    fr.offset = 0;
    fr.count = 4096;
    fr.buff = NULL;
    strcpy(fr.path, path);

  //  printf("fr path: %s\n", fr.path);

    ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(fr), 0);
    ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(fr));
    ret = ipc_call(tmpfs_ipc_struct, ipc_msg);

    return ;
}

int do_ls(char *cmdline)
{
	char pathbuf[BUFLEN];

	pathbuf[0] = '\0';
	cmdline += 2;
	while (*cmdline == ' ')
		cmdline++;
    if(cmdline != '/'){
        strcat(pathbuf, current_path);
    }
	strcat(pathbuf, cmdline);
	fs_scan(pathbuf);
	return 0;
}

int do_cat(char *cmdline)
{
	char pathbuf[BUFLEN];

	pathbuf[0] = '\0';
	cmdline += 3;
	while (*cmdline == ' ')
		cmdline++;

    if(cmdline != '/')
      strcat(pathbuf, current_path);
	strcat(pathbuf, cmdline);
	// fs_scan(pathbuf);

    // //send read request
    int ret;
    struct fs_request fr;
    ipc_msg_t *ipc_msg;


    // fr.req = FS_REQ_READ;
    // fr.offset = 0;
    // fr.count = 100000000; //set to INF, so it will read until the end
    // strcpy(fr.path, pathbuf);

    // ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(fr), 0);
    // ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(fr));
    // ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
    
    ipc_msg = ipc_create_msg(tmpfs_ipc_struct,
				 sizeof(struct fs_request), 1);
	fr.req = FS_REQ_GET_SIZE;
	strcpy((void *)fr.path, pathbuf);
	ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(struct fs_request));
	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);

	fr.req = FS_REQ_READ;
	strcpy((void *)fr.path, pathbuf);
	fr.offset = 0;
	fr.buff = (char *)TMPFS_READ_BUF_VADDR;
	fr.count = ret;
	fr.req = FS_REQ_READ;
	ipc_set_msg_data(ipc_msg, (char *)&fr, 0, sizeof(struct fs_request));
	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);

    if(ret < 0)
      printf("No such file!");


	//printf("apple banana This is a test file.\n");
	return 0;
}

int do_echo(char *cmdline)
{
	cmdline += 4;
	while (*cmdline == ' ')
		cmdline++;
	printf("%s\n", cmdline);
	return 0;
}

void do_clear(void)
{
	usys_putc(12);
	usys_putc(27);
	usys_putc('[');
	usys_putc('2');
	usys_putc('J');
}

int builtin_cmd(char *cmdline)
{
	int ret, i;
	char cmd[BUFLEN];
	for (i = 0; cmdline[i] != ' ' && cmdline[i] != '\0'; i++)
		cmd[i] = cmdline[i];
	cmd[i] = '\0';
	if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit"))
		usys_exit(0);
	if (!strcmp(cmd, "cd")) {
		ret = do_cd(cmdline);
		return !ret ? 1 : -1;
	}
	if (!strcmp(cmd, "ls")) {
		ret = do_ls(cmdline);
		return !ret ? 1 : -1;
	}
	if (!strcmp(cmd, "echo")) {
		ret = do_echo(cmdline);
		return !ret ? 1 : -1;
	}
	if (!strcmp(cmd, "cat")) {
		ret = do_cat(cmdline);
		return !ret ? 1 : -1;
	}
	if (!strcmp(cmd, "clear")) {
		do_clear();
		return 1;
	}
	if (!strcmp(cmd, "top")) {
		ret = do_top();
		return !ret ? 1 : -1;
	}
	return 0;
}

int run_cmd(char *cmdline)
{
	char pathbuf[BUFLEN];
	struct user_elf user_elf;
	int ret;
	int caps[1];

	pathbuf[0] = '\0';
	while (*cmdline == ' ')
		cmdline++;
	if (*cmdline == '\0') {
		return -1;
	} else if (*cmdline != '/') {
		strcpy(pathbuf, "/");
	}
	strcat(pathbuf, cmdline);

	ret = readelf_from_fs(pathbuf, &user_elf);
	if (ret < 0) {
		printf("[Shell] No such binary\n");
		return ret;
	}

	caps[0] = fs_server_cap;
	return launch_process_with_pmos_caps(&user_elf, NULL, NULL,
					     NULL, 0, caps, 1, 0);
}

static int
run_cmd_from_kernel_cpio(const char *filename, int *new_thread_cap,
			 struct pmo_map_request *pmo_map_reqs,
			 int nr_pmo_map_reqs)
{
	struct user_elf user_elf;
	int ret;

	ret = readelf_from_kernel_cpio(filename, &user_elf);
	if (ret < 0) {
		printf("[Shell] No such binary in kernel cpio\n");
		return ret;
	}
	return launch_process_with_pmos_caps(&user_elf, NULL, new_thread_cap,
					     pmo_map_reqs, nr_pmo_map_reqs,
					     NULL, 0, 0);
}

void boot_fs(void)
{
	int ret = 0;
	int info_pmo_cap;
	int tmpfs_main_thread_cap;
	struct pmo_map_request pmo_map_requests[1];

	/* create a new process */
	printf("Booting fs...\n");
	/* prepare the info_page (transfer init info) for the new process */
	info_pmo_cap = usys_create_pmo(PAGE_SIZE, PMO_DATA);
	fail_cond(info_pmo_cap < 0, "usys_create_ret ret %d\n", info_pmo_cap);

	ret = usys_map_pmo(SELF_CAP,
			   info_pmo_cap, TMPFS_INFO_VADDR, VM_READ | VM_WRITE);
	fail_cond(ret < 0, "usys_map_pmo ret %d\n", ret);

	SERVER_READY_FLAG(TMPFS_INFO_VADDR) = 0;
	SERVER_EXIT_FLAG(TMPFS_INFO_VADDR) = 0;

	/* We also pass the info page to the new process  */
	pmo_map_requests[0].pmo_cap = info_pmo_cap;
	pmo_map_requests[0].addr = TMPFS_INFO_VADDR;
	pmo_map_requests[0].perm = VM_READ | VM_WRITE;
	ret = run_cmd_from_kernel_cpio("/tmpfs.srv", &tmpfs_main_thread_cap,
				       pmo_map_requests, 1);
	fail_cond(ret != 0, "create_process returns %d\n", ret);

	fs_server_cap = tmpfs_main_thread_cap;
    // printf("Reach here? 1\n");

	while (SERVER_READY_FLAG(TMPFS_INFO_VADDR) != 1)
		usys_yield();

    // printf("Reach here? 2\n");

	/* register IPC client */
	tmpfs_ipc_struct = &ipc_struct;
	ret = ipc_register_client(tmpfs_main_thread_cap, tmpfs_ipc_struct);
	fail_cond(ret < 0, "ipc_register_client failed\n");

	tmpfs_scan_pmo_cap = usys_create_pmo(PAGE_SIZE, PMO_DATA);
	fail_cond(tmpfs_scan_pmo_cap < 0, "usys create_ret ret %d\n",
		  tmpfs_scan_pmo_cap);

	ret = usys_map_pmo(SELF_CAP,
			   tmpfs_scan_pmo_cap,
			   TMPFS_SCAN_BUF_VADDR, VM_READ | VM_WRITE);
	fail_cond(ret < 0, "usys_map_pmo ret %d\n", ret);

	printf("fs is UP.\n");

}
