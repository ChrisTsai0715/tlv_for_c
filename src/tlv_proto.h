#ifndef _ORAY_TLV_H_
#define _ORAY_TLV_H_

#include <stdint.h>
#include <stdbool.h>
//#include <stdio.h>

#include "protocol_def.h"

struct tlv_obj_def 
{
    uint16_t tag;
    uint16_t length;
    char *value;
    struct tlv_obj_def *next;
};

typedef struct
{
    uint32_t index;
    uint32_t session_id; 
    uint32_t check_sum;

    uint64_t sn;
    uint16_t size;
    uint16_t cmd;
	bool is_malloc;
    char *buffer;
}tlv_proto_def;

//如果buffer为空，则函数内将申请内存,否则使用buffer所指向的内存
extern tlv_proto_def *create_tlv_proto(uint32_t index, uint32_t session_id, uint64_t sn, uint16_t cmd, void *buffer);
extern char *serialize_proto_data(tlv_proto_def *proto);
extern tlv_proto_def *parse_tlv_proto(const void *data, uint16_t size);
extern void destroy_tlv_proto(tlv_proto_def *proto);

extern void add_tlv_obj(tlv_proto_def *proto, uint16_t tag, void *data, uint16_t length);
extern void add_tlv_int64(tlv_proto_def *proto, uint16_t tag, int64_t val);
extern void add_tlv_uint64(tlv_proto_def *proto, uint16_t tag, uint64_t val);
extern void add_tlv_int32(tlv_proto_def *proto, uint16_t tag, int32_t val);
extern void add_tlv_uint32(tlv_proto_def *proto, uint16_t tag, uint32_t val);
extern void add_tlv_int16(tlv_proto_def *proto, uint16_t tag, int16_t val);
extern void add_tlv_uint16(tlv_proto_def *proto, uint16_t tag, uint16_t val);
extern void add_tlv_int8(tlv_proto_def *proto, uint16_t tag, int8_t val);
extern void add_tlv_uint8(tlv_proto_def *proto, uint16_t tag, uint8_t val);

extern void *find_tag_in_proto(tlv_proto_def *proto, uint16_t tag, uint16_t *size);
extern bool find_tag_in_proto_int64(tlv_proto_def *proto, uint16_t tag, int64_t *val);
extern bool find_tag_in_proto_uint64(tlv_proto_def *proto, uint16_t tag, uint64_t *val);
extern bool find_tag_in_proto_int32(tlv_proto_def *proto, uint16_t tag, int32_t *val);
extern bool find_tag_in_proto_uint32(tlv_proto_def *proto, uint16_t tag, uint32_t *val);
extern bool find_tag_in_proto_int16(tlv_proto_def *proto, uint16_t tag, int16_t *val);
extern bool find_tag_in_proto_uint16(tlv_proto_def *proto, uint16_t tag, uint16_t *val);
extern bool find_tag_in_proto_int8(tlv_proto_def *proto, uint16_t tag, int8_t *val);
extern bool find_tag_in_proto_uint8(tlv_proto_def *proto, uint16_t tag, uint8_t *val);

#endif
