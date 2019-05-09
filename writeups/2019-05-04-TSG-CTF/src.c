#include <stdio.h>
#include <stdint.h>

int64_t mem[10000];

int main()
{
int p = 0;
int64_t reg = 10;
FILE* f = fopen("./dump.bin", "rb");
size_t ret = fread(mem, sizeof(int64_t), 10000, f);
if (ret != 10000) printf("fread error\n");
fclose(f);
++p;
while ( mem[p] )
{
	++p;
	++p;
	++p;
	reg = mem[p]; //field4
	--p;
	--p;
	--p;
	--p;
	mem[p] = (mem[p] + 0x10000) % 65537;
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 1) % 65537;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537;
	}//find first mem[p] == 1 for field0
	mem[p] = (mem[p] + 1) % 65537;//152
	++p;
	++p;
	mem[p] = reg; // field2
	--p;
	--p;
	++p;
	mem[p] = (mem[p] + 0x10000) % 65537;
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 1) % 65537;
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		mem[p] = (mem[p] + 0x10000) % 65537;
	}//switch to field1, find first mem[p] == 1
	mem[p] = (mem[p] + 1) % 65537;//0
	++p;
	++p;
	++p;
	++p;
	reg = mem[p]; //field5
	--p;
	--p;
	--p;
	--p;
	--p;//to field0
	mem[p] = (mem[p] + 0x10000) % 65537;
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 1) % 65537;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537;
	}
	mem[p] = (mem[p] + 1) % 65537;
	++p;
	++p;
	++p;
	mem[p] = reg; //field3
	--p;
	--p;
	--p;
	++p;
	mem[p] = (mem[p] + 0x10000) % 65537;
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 1) % 65537;
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		mem[p] = (mem[p] + 0x10000) % 65537;
	}
	mem[p] = (mem[p] + 1) % 65537;
	++p;
	++p;
	++p;
	++p;
	++p;
	reg = mem[p]; //field6
	--p;
	--p;
	--p;
	--p;
	--p;
	--p;
	mem[p] = (mem[p] + 0x10000) % 65537;
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 1) % 65537;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537;
	}
	mem[p] = (mem[p] + 1) % 65537;
	++p;
	++p;
	++p;
	++p;
	mem[p] = reg; //field4
	--p;
	--p;
	--p;
	--p;
	++p;
	mem[p] = mem[p] == mem[p + 1];//field1 == field2 0x00
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 0x10000) % 65537;
		++p;
		++p;
		reg = mem[p]; //lfield3
		--p;
		mem[p] = reg; //lfield2 = ifield5
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		reg = mem[p]; //2field3 for idx 1
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		mem[p] = reg; //lfield4 = [1].2field3
		++p;
		++p;
		++p;
		++p;
		reg = mem[p]; //2field3 for idx 0
		--p;
		--p;
		--p;
		--p;
		--p;
		mem[p] = reg; //lfield3 = [0].2field3
		--p;
		--p;
		mem[p] = mem[p] == mem[p + 1];
		while ( mem[p] ) //ifield5 == 0
		{
			mem[p] = (mem[p] + 0x10000) % 65537;
			++p;
			++p;
			mem[p] = (mem[p + 1] + mem[p]) % 65537; //lfield3 += lfield4
			--p;
			--p;
		}
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		--p;
		mem[p] = mem[p] == mem[p + 1];
		while ( mem[p] ) //ifield5 == 1
		{
			mem[p] = (mem[p] + 0x10000) % 65537;
			++p;
			++p;
			mem[p] = mem[p] * mem[p + 1] % 65537; //lfield3 *= lfield4
			--p;
			--p;
		}
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		--p;
		mem[p] = mem[p] == mem[p + 1];
		while ( mem[p] ) //ifield5 == 2
		{
			mem[p] = (mem[p] + 0x10000) % 65537;
			++p;
			++p;
			mem[p] = mem[p] == mem[p + 1]; //lfield3 = lfield3==lfield4
			--p;
			--p;
		}
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		--p;
		mem[p] = mem[p] == mem[p + 1];
		while ( mem[p] ) //ifield5 == 3
		{
			mem[p] = (mem[p] + 0x10000) % 65537;
			++p;
			++p;
			mem[p] = _IO_getc(stdin); //lfield3 = getchar()
			--p;
			--p;
		}
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		--p;
		mem[p] = mem[p] == mem[p + 1];
		while ( mem[p] ) //ifield5 == 4
		{
			mem[p] = (mem[p] + 0x10000) % 65537;
			++p;
			++p;
			putchar(mem[p]); //putchar(lfield3)
			fflush(stdout);
			--p;
			--p;
		}
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537; //lfield2--
		--p;
		++p;
		mem[p] = 0LL; //lfield2=0
		++p;
		reg = mem[p];
		++p;
		++p;
		++p;
		++p;
		++p;
		mem[p] = reg; //[0].2field3 = lfield3
		--p;
		--p;
		--p;
		--p;
		mem[p] = 0LL; //lfield4 = 0
		--p;
		mem[p] = 0LL; // lfield3 = 0
		--p;
		--p;
	}
	++p;
	mem[p] = (mem[p] + 0x10000) % 65537; //field2--
	--p;
	mem[p] = mem[p] == mem[p + 1]; //field1 == field2 0x01
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 0x10000) % 65537;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		++p;
		reg = mem[p]; //[0].2field3
		--p;
		--p;
		--p;
		--p;
		--p;
		mem[p] = reg; //lfield3 = [0].2field3
		while ( mem[p] )
		{
			--p;
			--p;
			mem[p] = (mem[p] + 0x10000) % 65537;
			while ( mem[p] )
			{
				mem[p] = (mem[p] + 1) % 65537;
				--p;
				--p;
				--p;
				--p;
				--p;
				--p;
				--p;
				mem[p] = (mem[p] + 0x10000) % 65537;
			}//find pc this
			mem[p] = (mem[p] + 1) % 65537;
			++p;
			++p;
			++p;
			++p;
			reg = mem[p]; //field5
			--p;
			--p;
			--p;
			mem[p] = reg; //field2 = field5
			++p;
			++p;
			++p;
			++p;
			reg = mem[p]; //field6
			--p;
			--p;
			--p;
			mem[p] = reg; //field3 = field6
			while ( mem[p] )
			{
				mem[p] = (mem[p] + 0x10000) % 65537;
				--p;
				while ( mem[p] ) //field2
				{
					mem[p] = (mem[p] + 0x10000) % 65537;
					reg = mem[p];
					--p;
					mem[p] = (mem[p] + 0x10000) % 65537;
					++p;
					++p;
					++p;
					++p;
					++p;
					++p;
					++p;
					++p;
					mem[p] = reg;
					--p;
					mem[p] = (mem[p] + 1) % 65537;
					++p;
				}//jump over `field2` instructions
				++p;
			}
			--p;
			while ( mem[p] ) //field2
			{
				mem[p] = (mem[p] + 0x10000) % 65537;
				reg = mem[p];
				--p;
				mem[p] = (mem[p] + 0x10000) % 65537;
				++p;
				--p;
				--p;
				--p;
				--p;
				--p;
				--p;
				--p;
				mem[p] = reg;
				--p;
				mem[p] = (mem[p] + 1) % 65537;
				++p;
			}
			--p;
			--p;
			mem[p] = (mem[p] + 0x10000) % 65537;
			while ( mem[p] )
			{
				mem[p] = (mem[p] + 1) % 65537;
				++p;
				++p;
				++p;
				++p;
				++p;
				++p;
				++p;
				mem[p] = (mem[p] + 0x10000) % 65537;
			}//back to last
			mem[p] = (mem[p] + 1) % 65537;
			++p;
			++p;
			++p;
			mem[p] = 0LL; //lfield3 = 0
		}
		--p;
		--p;
	}
	++p;
	mem[p] = (mem[p] + 0x10000) % 65537; //field2--
	--p;
	mem[p] = mem[p] == mem[p + 1]; //field1 == field2 0x02
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 0x10000) % 65537;
		++p;
		++p;
		reg = mem[p]; //lfield3
		++p;
		++p;
		++p;
		mem[p] = reg; //[0].2field1 = lfield3
		while ( mem[p] )
		{//4 => 3 2 1 0 0
			mem[p] = (mem[p] + 0x10000) % 65537;
			reg = mem[p];
			++p;
			++p;
			++p;
			++p;
			mem[p] = reg;
		}
		++p;
		++p;
		reg = mem[p]; //[lfield3].2field3
		--p;
		--p;
		--p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		while ( mem[p] )
		{
			mem[p] = (mem[p] + 1) % 65537;
			--p;
			--p;
			--p;
			--p;
			mem[p] = (mem[p] + 0x10000) % 65537;
		}//back to fst elem
		mem[p] = (mem[p] + 1) % 65537;
		--p;
		--p;
		mem[p] = reg; //lfield3 = [lfield3].2field3
		++p;
		reg = mem[p]; //lfield4
		++p;
		++p;
		mem[p] = reg;
		while ( mem[p] )
		{
			mem[p] = (mem[p] + 0x10000) % 65537;
			reg = mem[p];
			++p;
			++p;
			++p;
			++p;
			mem[p] = reg;
		}
		++p;
		++p;
		reg = mem[p]; //[lfield4].2field3
		--p;
		--p;
		--p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		while ( mem[p] )
		{
			mem[p] = (mem[p] + 1) % 65537;
			--p;
			--p;
			--p;
			--p;
			mem[p] = (mem[p] + 0x10000) % 65537;
		}
		mem[p] = (mem[p] + 1) % 65537;
		--p;
		mem[p] = reg; //lfield4 = [lfield4].2field3
		--p;
		--p;
		mem[p] = (mem[p] + 1) % 65537; //lfield2++, execute 0x03
		--p;
	}
	++p;
	mem[p] = (mem[p] + 0x10000) % 65537; //field2--
	--p;
	mem[p] = mem[p] == mem[p + 1]; //field1 == field2 0x03
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 0x10000) % 65537;
		++p;
		++p;
		reg = mem[p]; //field3
		++p;
		++p;
		++p;
		mem[p] = reg; //field6, 2field1
		while ( mem[p] )
		{// reg == 4 => 3 2 1 0 0
			mem[p] = (mem[p] + 0x10000) % 65537;
			reg = mem[p];
			++p;
			++p;
			++p;
			++p;
			mem[p] = reg;
		}
		++p;
		mem[p] = (mem[p] + 1) % 65537; // 2field2
		--p;
		--p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		while ( mem[p] )
		{
			mem[p] = (mem[p] + 1) % 65537;
			--p;
			--p;
			--p;
			--p;
			mem[p] = (mem[p] + 0x10000) % 65537;
		}//back to first
		mem[p] = (mem[p] + 1) % 65537;
		--p;
		reg = mem[p]; //fetch field4
		++p;
		++p;
		mem[p] = reg;
		while ( mem[p] ) //field6, 2field1
		{// n-1 n-2 .. 1 0 0
			mem[p] = (mem[p] + 0x10000) % 65537;
			reg = mem[p];
			++p;
			++p;
			++p;
			++p;
			mem[p] = reg;
		}
		++p;
		++p;
		reg = mem[p]; //2field3
		--p;
		--p;
		--p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		while ( mem[p] )
		{
			mem[p] = (mem[p] + 1) % 65537;
			--p;
			--p;
			--p;
			--p;
			mem[p] = (mem[p] + 0x10000) % 65537;
		}//back to first
		mem[p] = (mem[p] + 1) % 65537;
		++p;
		++p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		while ( mem[p] )
		{
			mem[p] = (mem[p] + 1) % 65537;
			++p;
			++p;
			++p;
			++p;
			mem[p] = (mem[p] + 0x10000) % 65537;
		}
		++p;
		mem[p] = reg;
		--p;
		--p;
		--p;
		mem[p] = (mem[p] + 0x10000) % 65537;
		while ( mem[p] )
		{
			mem[p] = (mem[p] + 1) % 65537;
			--p;
			--p;
			--p;
			--p;
			mem[p] = (mem[p] + 0x10000) % 65537;
		}//back to first elem
		mem[p] = (mem[p] + 1) % 65537;
		--p;
		--p;
		--p;
		--p; //back to field1
	}
	++p;
	mem[p] = (mem[p] + 0x10000) % 65537;
	--p;
	mem[p] = (mem[p] + 0x10000) % 65537;
	while ( mem[p] )
	{
		mem[p] = (mem[p] + 1) % 65537;
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		--p;
		mem[p] = (mem[p] + 0x10000) % 65537;
	}
	mem[p] = (mem[p] + 1) % 65537;
	mem[p] = (mem[p] + 0x10000) % 65537;
	++p;
	++p;
	++p;
	++p;
	++p;
	++p;
	++p;
	mem[p] = (mem[p] + 1) % 65537; //shift pc
}
}