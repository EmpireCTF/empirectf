#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <memory.h>
int64_t gen_buf(char *key4, uint8_t *buf)
{
	int64_t v5; // rax
	int64_t v6; // r10
	int64_t i; // rax
	int64_t v8; // r9
	int64_t j; // r10
	uint8_t v10; // xmm0_1

	v5 = 0LL;
	v6 = 0x706050403020100LL;
	while ( v5 != 32 )
	{
		*(uint64_t*)&buf[8 * v5] = v6;
		v6 += 0x808080808080808LL;
		++v5;
	}
	i = 0LL;
	v8 = 0;
	j = 0LL;
	do
	{
		v10 = buf[i];
		v8 = (uint8_t)(key4[j] + buf[i] + v8);
		buf[i] = buf[v8];
		buf[v8] = v10;
		if ( 8 == ++j )
			j = 0LL;
		++i;
	}
	while ( (uint8_t)i );
	return i;
}

int64_t get_result(char *res, uint8_t *buf)
{
	int64_t i; // rax
	int64_t v7; // xmm0_8
	int64_t v8; // xmm1_8
	int64_t v9; // r11
	uint8_t v10; // r10
	int64_t v11; // r11
	uint8_t v12; // xmm3_1

	i = 0LL;
	v7 = 0;
	v8 = 0;
	while ( 0x30 != i )
	{
		v9 = (uint8_t)(v7 + 1);
		v7 = (uint8_t)(v7 + 1);
		v10 = buf[v9];
		v11 = (uint8_t)(v8 + v10);
		v8 = (uint8_t)(v8 + v10);
		v12 = buf[v11];
		buf[v7] = buf[v11];
		buf[v8] = v10;
		res[i] = res[i] ^ buf[(uint8_t)(v12 + v10)];
		++i;
	}
	return i;
}
uint8_t buf[0x100];
uint64_t ori_res[6] = {0x780E99031A722CF6,0x293769D068E990BD,0x7EF3FBD0E5F412F8,0x521244ED19796172,0x0B21F0D3614AAF9F5,0x3CEC9DDA6AF26B52};
uint64_t res[6];
uint64_t get_res(uint32_t input)
{
	uint32_t key4[2];
	key4[1] = 0x36395477;
	key4[0] = input;
	memcpy(res, ori_res, sizeof(res));
	// gen_buf((char*)key4, buf);
	// get_result((char*)res, buf);
	gen_buf((char*)key4, buf);
	get_result((char*)res, buf);
	return res[0];
}
uint64_t flag[4];
void get_flag(uint64_t res)
{
	flag[3] = (res ^ 0x115C28DA834FEFFD);
	flag[2] = flag[3] ^ 0x665F336B1A566B19;
	flag[1] = flag[2] ^ 0x393B415F5A590044;
	flag[0] = flag[1] ^ 0x3255557376F68;
}

int printable_flag(char* flag)
{
	for (int i = 0; i < 28; ++i)
	{
		if (!isprint(flag[i]))
			return 0;
	}
	return 1;
}

int main(int argc, char const *argv[])
{
	// // brute force the correct key
	// for (size_t i = 0; i < 0x100000000; ++i)
	// {
	// 	get_flag(0x115C28DA00000000+i);
	// 	if (printable_flag((char*)flag))
	// 		printf("%s\n", (char*)flag);
	// }
	// for (size_t i = 0; i < 0x100000000; ++i)
	// {
	// 	if (i % 0x1000000 == 0)
	// 		printf("%lx\n", i);
	// 	uint64_t res = get_res(i);
	// 	if ((uint32_t)res == 0xDA285C11)
	// 		printf("%lx\n", i);
	// }

	uint64_t ret = get_res(0x6d517259);
	uint64_t res = 0;
	for (int i = 0; i < 8; ++i)
	{
		res <<= 8;
		res |= ret & 0xff;
		ret >>= 8;
	}
	printf("%lx\n", res);
	get_flag(res);
	puts((char*)flag);

	return 0;
}