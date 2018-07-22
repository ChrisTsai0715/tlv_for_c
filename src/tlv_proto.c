#include "oray_tlv_proto.h"
#include <stdlib.h>
#include <string.h>
#include "crc_16.h"
#ifdef _NO_MALLOC_
static char mem_buffer[2048] = {0};
static size_t mem_offset = 0;
static void *proto_malloc(size_t size)
{
	void *addr = &mem_buffer[mem_offset];
	mem_offset += size;
	return addr;
}

static void proto_free(void *buffer)
{
	mem_offset = 0;
}

#else
#define proto_malloc malloc
#define proto_free free 
#endif

#define OFFSET(TYPE, MEMBER) ((unsigned long)(&(((TYPE *)0)->MEMBER)))
#define BUFFER_UNIT_SIZE 1024

tlv_proto_def *create_tlv_proto(uint32_t index, uint32_t session_id, uint64_t sn, uint16_t cmd, void *buffer)
{
	assert(proto != NULL && proto->buffer != NULL);
	tlv_proto_def *proto;
	if (buffer == NULL)
	{
		proto = (tlv_proto_def*)proto_malloc(BUFFER_UNIT_SIZE);
		proto->is_malloc = true;
	}
	else
	{	
		proto = (tlv_proto_def*)buffer;
		proto->is_malloc = false;
	}

	proto->size = 0;
	proto->index = index;
	proto->session_id = session_id;
	proto->cmd = cmd;
	proto->buffer = (char*)proto + sizeof(tlv_proto_def);

	*(uint16_t*)(proto->buffer) = 0;	//check_sum
	proto->size += sizeof(uint16_t);
	*(uint16_t*)(proto->buffer + proto->size) = htons(cmd);	//cmd
	proto->size += sizeof(uint16_t);
	*(uint32_t*)(proto->buffer + proto->size) = htonl(index);	//index
	proto->size += sizeof(uint32_t);
	*(uint32_t*)(proto->buffer + proto->size) = htonl(session_id);	//session_id
	proto->size += sizeof(uint32_t);

	add_tlv_uint64(proto, TLV_PROTO_TAG_SN, sn);
	return proto;
}

void add_tlv_obj(tlv_proto_def *proto, uint16_t tag, void *data, uint16_t length)
{
#ifndef _NO_MALLOC_
	uint16_t proto_size = proto->size + length + 2 * sizeof(uint16_t);
	if (proto->is_malloc &&  proto_size > (proto->size / BUFFER_UNIT_SIZE + 1) * BUFFER_UNIT_SIZE)
	{
		uint16_t re_size = (proto_size / BUFFER_UNIT_SIZE + 1) * BUFFER_UNIT_SIZE;
		proto = (tlv_proto_def*)realloc((void*)proto, re_size);
		proto->buffer = (char*)proto + sizeof(tlv_proto_def);
	}
#endif
	uint16_t n_tag = htons(tag);
	memcpy(proto->buffer + proto->size, &n_tag, sizeof(uint16_t));
	proto->size += sizeof(uint16_t);
	uint16_t n_length = htons(length);
	memcpy(proto->buffer + proto->size, &n_length, sizeof(uint16_t));
	proto->size += sizeof(uint16_t);
	memcpy(proto->buffer + proto->size, (char*)data, length);
	proto->size += length;
}

void add_tlv_int64(tlv_proto_def *proto, uint16_t tag, int64_t val)
{
	int32_t low = val & 0xFFFFFFFF;
	int32_t high = (val >> 32) & 0xFFFFFFFF;
	low = htonl(low);
	high = htonl(high);
	int64_t tmp_val = low;
	tmp_val <<= 32;
	tmp_val |= high;
	add_tlv_obj(proto, tag, &tmp_val, sizeof(int64_t));
}

void add_tlv_uint64(tlv_proto_def *proto, uint16_t tag, uint64_t val)
{
	uint32_t low = val & 0xFFFFFFFF;
	uint32_t high = (val >> 32) & 0xFFFFFFFF;
	low = htonl(low);
	high = htonl(high);
	uint64_t tmp_val = low;
	tmp_val <<= 32;
	tmp_val |= high;
	add_tlv_obj(proto, tag, &tmp_val, sizeof(uint64_t));
}

void add_tlv_int32(tlv_proto_def *proto, uint16_t tag, int32_t val)
{
	val = htonl(val);
	add_tlv_obj(proto, tag, &val, sizeof(int32_t));
}

void add_tlv_uint32(tlv_proto_def *proto, uint16_t tag, uint32_t val)
{
	val = htonl(val);
	add_tlv_obj(proto, tag, &val, sizeof(uint32_t));
}

void add_tlv_int16(tlv_proto_def *proto, uint16_t tag, int16_t val)
{
	val = htons(val);
	add_tlv_obj(proto, tag, &val, sizeof(int16_t));
}

void add_tlv_uint16(tlv_proto_def *proto, uint16_t tag, uint16_t val)
{
	val = htons(val);
	add_tlv_obj(proto, tag, &val, sizeof(uint16_t));
}

void add_tlv_int8(tlv_proto_def *proto, uint16_t tag, int8_t val)
{
	add_tlv_obj(proto, tag, &val, sizeof(uint8_t));
}

void add_tlv_uint8(tlv_proto_def *proto, uint16_t tag, uint8_t val)
{
	add_tlv_obj(proto, tag, &val, sizeof(uint8_t));
}

static void get_tlv_data(char *ret_buffer, struct tlv_obj_def *tlv_obj)
{
	if (tlv_obj != NULL)
	{
		uint16_t tmp_data = htons(tlv_obj->tag);
		memcpy(ret_buffer, &tmp_data, sizeof(uint16_t));
		ret_buffer += sizeof(uint16_t);

		tmp_data = htons(tlv_obj->length);
		memcpy(ret_buffer, &tmp_data, sizeof(uint16_t));
		ret_buffer += sizeof(uint16_t);

		memcpy(ret_buffer, tlv_obj->value, tlv_obj->length);
		ret_buffer += tlv_obj->length;

		get_tlv_data(ret_buffer, tlv_obj->next);
	}
}

char *serialize_proto_data(tlv_proto_def *proto)
{
//    assert(proto != NULL);
    uint16_t crc = crc_16(proto->buffer + sizeof(uint16_t),
						  proto->size - sizeof(uint16_t),
						  1 );
    *((uint16_t *)(proto->buffer)) = htons(crc);

	return proto->buffer;
}

tlv_proto_def *parse_tlv_proto(const void *data, uint16_t size)
{
	if (data == NULL || size == 0) return NULL;
    tlv_proto_def *proto = (tlv_proto_def*)proto_malloc(sizeof(tlv_proto_def) + size);
	proto->is_malloc = true;
	proto->buffer = (char*)proto + sizeof(tlv_proto_def);
	proto->size = size;
	uint16_t offset = 0;
	proto->check_sum = ntohs(*(uint16_t*)data);
	offset += sizeof(uint16_t);
	proto->cmd = ntohs(*(uint16_t*)((const char*)data + offset));
	offset += sizeof(uint16_t);
	uint16_t crc = crc_16((const char*)data + sizeof(uint16_t), proto->size - sizeof(uint16_t), 1);
	if (proto->check_sum != crc) return NULL;

    proto->index = ntohl(*(uint32_t*)((const char*)data + offset));
	offset += sizeof(uint32_t);
	proto->session_id = ntohl(*(uint32_t*)((const char*)data + offset));
	offset += sizeof(uint32_t);
	memcpy(proto->buffer, data, size);
	find_tag_in_proto_uint64(proto, TLV_PROTO_TLV_SN, &proto->sn);

	return proto;
}

static void *find_tag_in_tlv(tlv_proto_def *proto, uint16_t tag, uint16_t *size, uint16_t offset)
{
	if (offset == proto->size) return NULL;
	char *buffer = proto->buffer + offset;
	uint16_t proto_tag;
	memcpy(&proto_tag, buffer, sizeof(uint16_t));
	proto_tag = ntohs(proto_tag);
	uint16_t proto_length;
	memcpy(&proto_length, buffer + sizeof(uint16_t), sizeof(uint16_t));
	proto_length = ntohs(proto_length);
	if (proto_tag == tag)
	{
		if (size != NULL) *size = proto_length;
		return (buffer + 2 * sizeof(uint16_t));
	}
	else
	{
		return find_tag_in_tlv(proto, tag, size, offset + 2 * sizeof(uint16_t) + proto_length);
	}
}

void *find_tag_in_proto(tlv_proto_def *proto, uint16_t tag, uint16_t *size)
{
	return find_tag_in_tlv(proto, tag, size, 3 * sizeof(uint32_t));
}

bool find_tag_in_proto_int64(tlv_proto_def *proto, uint16_t tag, int64_t *val)
{
	uint16_t size;
	void *val_addr = find_tag_in_proto(proto, tag, &size);
	if (val_addr == NULL || size != sizeof(int64_t))
		return false;
	uint64_t tmp_val;
	memcpy(&tmp_val, val_addr, sizeof(uint64_t));

	int32_t low = tmp_val & 0xFFFFFFFF;
	int32_t high = (tmp_val >> 32) & 0xFFFFFFFF;
	low = ntohl(low);
	high = ntohl(high);

	*val = low;
	*val <<= 32;
	*val |= high;

	return true;
}

bool find_tag_in_proto_uint64(tlv_proto_def *proto, uint16_t tag, uint64_t *val)
{
	uint16_t size;
	void *val_addr = find_tag_in_proto(proto, tag, &size);
	if (val_addr == NULL || size != sizeof(uint64_t))
		return false;
	uint64_t tmp_val;
	memcpy(&tmp_val, val_addr, sizeof(uint64_t));

	uint32_t low = tmp_val & 0xFFFFFFFF;
	uint32_t high = (tmp_val >> 32) & 0xFFFFFFFF;
	low = ntohl(low);
	high = ntohl(high);

	*val = low;
	*val <<= 32;
	*val |= high;

	return true;
}

bool find_tag_in_proto_int32(tlv_proto_def *proto, uint16_t tag, int32_t *val)
{
	uint16_t size;
	void *tmp_val = find_tag_in_proto(proto, tag, &size);
	if (tmp_val == NULL || size != sizeof(int32_t))
		return false;
	memcpy(val, tmp_val, sizeof(int32_t));
	*val = ntohl(*val);

	return true;
}

bool find_tag_in_proto_uint32(tlv_proto_def *proto, uint16_t tag, uint32_t *val)
{
	uint16_t size;
	void *tmp_val = find_tag_in_proto(proto, tag, &size);
	if (tmp_val == NULL || size != sizeof(uint32_t))
		return false;
	memcpy(val, tmp_val, sizeof(uint32_t));
	*val = ntohl(*val);

	return true;
}

bool find_tag_in_proto_int16(tlv_proto_def *proto, uint16_t tag, int16_t *val)
{
	uint16_t size;
	void *tmp_val = find_tag_in_proto(proto, tag, &size);
	if (tmp_val == NULL || size != sizeof(int16_t))
		return false;
	memcpy(val, tmp_val, sizeof(int16_t));
	*val = ntohs(*val);

	return true;
}

bool find_tag_in_proto_uint16(tlv_proto_def *proto, uint16_t tag, uint16_t *val)
{
	uint16_t size;
	void *tmp_val = find_tag_in_proto(proto, tag, &size);
	if (tmp_val == NULL || size != sizeof(uint16_t))
		return false;
	memcpy(val, tmp_val, sizeof(uint16_t));
	*val = ntohs(*val);

	return true;
}

bool find_tag_in_proto_int8(tlv_proto_def *proto, uint16_t tag, int8_t *val)
{
	uint16_t size;
	int8_t *tmp_val = (int8_t*)find_tag_in_proto(proto, tag, &size);
	if (tmp_val == NULL || size != sizeof(int8_t))
		return false;
	*val = *tmp_val;

	return true;
}

bool find_tag_in_proto_uint8(tlv_proto_def *proto, uint16_t tag, uint8_t *val)
{
	uint16_t size;
	uint8_t *tmp_val = (uint8_t*)find_tag_in_proto(proto, tag, &size);
	if (tmp_val == NULL || size != sizeof(uint8_t))
		return false;
	*val = *tmp_val;

	return true;
}

void destroy_tlv_proto(tlv_proto_def *proto)
{
	if (proto == NULL || !proto->is_malloc) return ;	
	proto_free(proto);
}
