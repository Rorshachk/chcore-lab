## Lab5

lab5开始就基本在写用户程序了。你写的tmpfs最后会接上tmpfs_test编译成fs_test.bin可执行文件，shell会编译成init.bin可执行文件，嵌入build/ramdisk。比较好的调试办法就是对于文件系统，你先make user然后再make run-fs_test或者make run-fs_test-gdb，shell同理，make user然后make run-init。

其中用户程序有个比较麻烦的就是malloc，malloc只会给你分配一个地址，而不会保证这个地址是可读/可写的。chcore的机制是对于malloc分配的地址，如果不可写的话则会进入exception，然后用page fault给该虚拟地址分配物理内存，每次分配一页。因此如果lab2/lab3的内存处理/缺页处理有bug却没在之前的测试测出来的话，很容易在malloc的时候挂掉。

还有一个比较奇怪的点就是，如果编译通过，压根没执行任何一行用户程序代码的情况下，如果你page fault失败在一个0xfffff...1的地址，那就是你用户程序里面有一处编译错误，多半是调用了未声明的函数，或者某个变量declare了多次，之类的。

### 文件系统

文件系统基于inode和dentry。每个文件inode有该文件的type，目录(DIR)或者常规文件(REG)，还有一个union成员，对于目录来说该成员是htable，用哈希表组织了在该目录下的所有文件的dentry；对于常规文件来说成员是Radix，用radix树组织了该文件的所有page。每个文件都有一个dentry，dentry中有该文件的inode和name，还有一个指针指向了所在目录中下一个文件的dentry。看懂了这些结构的话所有文件系统的函数都会非常的直观，唯一稍微麻烦的就是read/write注意要页对齐，namex实现仔细一点。

另外一个比较难的就是这个load image。chcore在运行的时候，初始文件的镜像存在CPIO文件中，该文件位于0x50000000这个位置。load image需要把这个镜像读进来，并且根据该镜像初始化整个文件系统。虽然大部分代码都给写好了，我们只需要对于每一个文件对象cpio_file，初始化对应的文件并将它加入文件系统。其中每个文件的元信息(type之类的)如何提取，可以看该[链接](https://www.systutorials.com/docs/linux/man/5-cpio/)，代码注释里的教程链接已经404了。

### shell和交互过程

shell各个命令的实现比较自由，比较关键的就是看懂shell进程和tmpfs server进程的交互过程。其中有三个共享地址非常核心，一个是TMPFS_INFO_VADDR，该地址存储了server状态的信息；一个TMPFS_SCAN_BUF_VADDR，该地址存储了每次fs_scan的结果；一个TMPFS_READ_BUF_VADDR，该地址存储了每次fs_read的结果。为了启用这三个共享地址，shell进程和server进程必须要在合适的时间对这三个地址map pmo创建capability(暂时将其称之为实体化)。

首先init_main中先launch一个新的process把tmpfs启动，通过TMPFS_INFO_VADDR上的值来得知tmpfs进程的状态。因此从代码中看出info的vaddr是要最早实体化的。shell进程先实体化info的vaddr，然后将对应的cap直接打包成pmo_map_request传给launch process，使其server进程创建完成之后就可以对info的地址进行读写，以通知shell tmpfs server已经创建完毕。如果server没创建完毕的话shell进程需要调用yield进行显式的阻塞。

当shell发现tmpfs server创建完毕后，会注册自己为client，然后实体化scan buf的vaddr来存储每次扫描的结果，因为该buf对于shell来说是固定不变的(最大一页大小)，所以对于shell来说只要在开头实体化一次即可。对于tmpfs server来说，你可以在开头的时候跟info vaddr一起打包进pmo map request，也可以让shell在每次发送scan请求的时候把scan buf cap打包进ipc_msg，然后server就可以从ipc_msg中将该capability提取出来然后用map将scan的vaddr实体化，将scan的结果写进去之后unmap掉，如果忘记unmap的话会造成overlap。

对于fs_read，我们查看lib_launcher.c，会发现里面已经为我们实现了fs_read函数。该函数先对server发一个get_size请求，拿到目标文件的长度，然后用这个长度动态创建read buf的pmo_cap。然后将该pmo打包进ipc_msg里面，当server接到read request的时候，我们需要将这个pmo_cap提取出来，并对read buf的vaddr实体化。当然server将read的结果放进这个地址的时候也要记得unmap。然后ipc return之后回到shell，shell实体化read buf的vaddr之后将上面的数据读进来，然后进行对应的处理(cat 或者 解析为elf然后执行)。

上面讲的是pmo读写共享内存buf的细节。对于总体的交互过程其实很显然，shell先创建空的ipc_msg，然后往ipc_msg里面写需要的capability和fr request。然后调用ipc call，server接到call之后运行dispatch，提取出fr request根据不同的request运行不同的函数。read request和scan request将ipc_msg里对应的capability拿出来实体化，然后往共享缓存上读写tfs_server_read和tfs_server_scan的结果。
