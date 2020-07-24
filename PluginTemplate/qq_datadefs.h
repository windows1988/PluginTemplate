#pragma once
typedef struct
{
	void* vt;
	unsigned int ref_cnt;
	unsigned char* buff_ptr;
	unsigned int buff_len;
}qqsso_txbuff_t;