//
// Created by erebe on 7/11/18.
//

#pragma once

#include <cstdint>
#include <string_view>
#include <netinet/in.h>

#include "enum.h"


namespace memcached {

/*
* https://github.com/memcached/memcached/wiki/BinaryProtocolRevamped#packet-structure
*/

enum class MSG_TYPE : uint8_t {
    Request = 0x80,
    Response = 0x81,
    OUT_OF_RANGE,
};

enum class COMMAND : uint8_t {
    Get                   = 0x00,
    Set                   = 0x01,
    Add                   = 0x02,
    Replace               = 0x03,
    Delete                = 0x04,
    Increment             = 0x05,
    Decrement             = 0x06,
    Quit                  = 0x07,
    Flush                 = 0x08,
    GetQ                  = 0x09,
    Noop                  = 0x0a,
    Version               = 0x0b,
    GetK                  = 0x0c,
    GetKQ                 = 0x0d,
    Append                = 0x0e,
    Prepend               = 0x0f,
    Stat                  = 0x10,
    SetQ                  = 0x11,
    AddQ                  = 0x12,
    ReplaceQ              = 0x13,
    DeleteQ               = 0x14,
    IncrementQ            = 0x15,
    DecrementQ            = 0x16,
    QuitQ                 = 0x17,
    FlushQ                = 0x18,
    AppendQ               = 0x19,
    PrependQ              = 0x1a,
    Verbosity             = 0x1b,
    Touch                 = 0x1c,
    GAT                   = 0x1d,
    GATQ                  = 0x1e,
    SASL_list_mechs       = 0x20,
    SASL_Auth             = 0x21,
    SASL_Step             = 0x22,
    RGet                  = 0x30,
    RSet                  = 0x31,
    RSetQ                 = 0x32,
    RAppend               = 0x33,
    RAppendQ              = 0x34,
    RPrepend              = 0x35,
    RPrependQ             = 0x36,
    RDelete               = 0x37,
    RDeleteQ              = 0x38,
    RIncr                 = 0x39,
    RIncrQ                = 0x3a,
    RDecr                 = 0x3b,
    RDecrQ                = 0x3c,
    Set_VBucket           = 0x3d,
    Get_VBucket           = 0x3e,
    Del_VBucket           = 0x3f,
    TAP_Connect           = 0x40,
    TAP_Mutation          = 0x41,
    TAP_Delete            = 0x42,
    TAP_Flush             = 0x43,
    TAP_Opaque            = 0x44,
    TAP_VBucket_Set       = 0x45,
    TAP_Checkpoint_Start  = 0x46,
    TAP_Checkpoint_End    = 0x47,
    OUT_OF_RANGE
};

BETTER_ENUM(COMMANDS, uint8_t,
            Get                   = 0x00,
            Set                   = 0x01,
            Add                   = 0x02,
            Replace               = 0x03,
            Delete                = 0x04,
            Increment             = 0x05,
            Decrement             = 0x06,
            Quit                  = 0x07,
            Flush                 = 0x08,
            GetQ                  = 0x09,
            Noop                  = 0x0a,
            Version               = 0x0b,
            GetK                  = 0x0c,
            GetKQ                 = 0x0d,
            Append                = 0x0e,
            Prepend               = 0x0f,
            Stat                  = 0x10,
            SetQ                  = 0x11,
            AddQ                  = 0x12,
            ReplaceQ              = 0x13,
            DeleteQ               = 0x14,
            IncrementQ            = 0x15,
            DecrementQ            = 0x16,
            QuitQ                 = 0x17,
            FlushQ                = 0x18,
            AppendQ               = 0x19,
            PrependQ              = 0x1a,
            Verbosity             = 0x1b,
            Touch                 = 0x1c,
            GAT                   = 0x1d,
            GATQ                  = 0x1e,
            SASL_list_mechs       = 0x20,
            SASL_Auth             = 0x21,
            SASL_Step             = 0x22,
            RGet                  = 0x30,
            RSet                  = 0x31,
            RSetQ                 = 0x32,
            RAppend               = 0x33,
            RAppendQ              = 0x34,
            RPrepend              = 0x35,
            RPrependQ             = 0x36,
            RDelete               = 0x37,
            RDeleteQ              = 0x38,
            RIncr                 = 0x39,
            RIncrQ                = 0x3a,
            RDecr                 = 0x3b,
            RDecrQ                = 0x3c,
            Set_VBucket           = 0x3d,
            Get_VBucket           = 0x3e,
            Del_VBucket           = 0x3f,
            TAP_Connect           = 0x40,
            TAP_Mutation          = 0x41,
            TAP_Delete            = 0x42,
            TAP_Flush             = 0x43,
            TAP_Opaque            = 0x44,
            TAP_VBucket_Set       = 0x45,
            TAP_Checkpoint_Start  = 0x46,
            TAP_Checkpoint_End    = 0x47
)

BETTER_ENUM(RSP_STATUS, uint16_t,
            No_error                              = 0x00,
            Key_not_found                         = 0x01,
            Key_exists                            = 0x02,
            Value_too_large                       = 0x03,
            Invalid_arguments                     = 0x04,
            Item_not_stored                       = 0x05,
            Incr_Decr_on_non_numeric_value        = 0x06,
            The_vbucket_belongs_to_another_server = 0x07,
            Authentication_error                  = 0x08,
            Authentication_continue               = 0x09,
            Unknown_command                       = 0x81,
            Out_of_memory                         = 0x82,
            Not_supported                         = 0x83,
            Internal_error                        = 0x84,
            Busy                                  = 0x85,
            Temporary_failure                     = 0x86
)

#pragma pack(push, 1)
struct header_t {
    MSG_TYPE magic;
    COMMAND opcode;
    uint16_t key_length;
    uint8_t extras_length;
    uint8_t data_type;
    uint16_t rsp_status; // or vbucket_id in request msg
    uint32_t body_length;
    uint32_t opaque;
    uint64_t cas;
};
static_assert(sizeof(header_t) == 24, "Memcached::header_t does not have a correct size, should be 24 bytes");


// For Get, Get Quietly, Get Key, Get Key Quietly
struct get_extra_t {
    uint32_t flags;
};
static_assert(sizeof(get_extra_t) == 4, "Memcached::get_extra_t does not have a correct size");


struct set_extra_t { // For Set, Add, Replace
    uint32_t flags;
    uint32_t expiration;
};
static_assert(sizeof(set_extra_t) == 8, "Memcached::set_extra_t does not have a correct size");


struct inc_dec_extra_t { // For Increment, Decrement
    uint32_t amount;
    uint32_t initial_value;
    uint32_t expiration;
};
static_assert(sizeof(inc_dec_extra_t) == 12, "Memcached::inc_dec_extra_t does not have a correct size");

struct flush_extra_t {
    uint32_t expiration;
};
static_assert(sizeof(flush_extra_t) == 4, "Memcached::inc_dec_extra_t does not have a correct size");

struct verbosity_extra_t {
    uint32_t verbosity;
};
static_assert(sizeof(verbosity_extra_t) == 4, "Memcached::inc_dec_extra_t does not have a correct size");

struct touch_extra_t { // For Touch, GAT and GATQ
    uint32_t expiration;
};
static_assert(sizeof(touch_extra_t) == 4, "Memcached::touch_extra_t does not have a correct size");

struct no_extra_t {};
#pragma pack(pop)



namespace impl {

template<MSG_TYPE T, COMMAND C>
auto get_extra(const header_t* header) { return (no_extra_t*)(header+1);}

template<> auto get_extra<MSG_TYPE::Request, COMMAND::Set>(const header_t *header) { return (set_extra_t*) (header + 1); }
template<> auto get_extra<MSG_TYPE::Request, COMMAND::Add>(const header_t *header) { return (set_extra_t*) (header + 1); }
template<> auto get_extra<MSG_TYPE::Request, COMMAND::Replace>(const header_t *header) { return (set_extra_t*) (header + 1); }

template<> auto get_extra<MSG_TYPE::Response, COMMAND::Get>(const header_t *header) { return (get_extra_t*) (header + 1); }
template<> auto get_extra<MSG_TYPE::Response, COMMAND::GetQ>(const header_t *header) { return (get_extra_t*) (header + 1); }
template<> auto get_extra<MSG_TYPE::Response, COMMAND::GetK>(const header_t *header) { return (get_extra_t*) (header + 1); }
template<> auto get_extra<MSG_TYPE::Response, COMMAND::GetKQ>(const header_t *header) { return (get_extra_t*) (header + 1); }

template<> auto get_extra<MSG_TYPE::Request, COMMAND::Increment>(const header_t *header) { return (inc_dec_extra_t*) (header + 1); }
template<> auto get_extra<MSG_TYPE::Request, COMMAND::Decrement>(const header_t *header) { return (inc_dec_extra_t*) (header + 1); }

template<> auto get_extra<MSG_TYPE::Request, COMMAND::Flush>(const header_t *header) { return (flush_extra_t*) (header + 1); }

template<> auto get_extra<MSG_TYPE::Request, COMMAND::Verbosity>(const header_t *header) { return (verbosity_extra_t*) (header + 1); }

template<> auto get_extra<MSG_TYPE::Request, COMMAND::Touch>(const header_t *header) { return (touch_extra_t*) (header + 1); }
template<> auto get_extra<MSG_TYPE::Request, COMMAND::GAT>(const header_t *header) { return (touch_extra_t*) (header + 1); }
template<> auto get_extra<MSG_TYPE::Request, COMMAND::GATQ>(const header_t *header) { return (touch_extra_t*) (header + 1); }
}

bool has_extra(const header_t& header) { return header.extras_length > 0; }
template<MSG_TYPE T, COMMAND C>
auto get_extra(const header_t* header) {
    return impl::get_extra<T, C>(header);

}

bool has_key(const header_t* header) {
    return (header->key_length > 0);
}

std::string_view get_key(const header_t* header) {
    return std::string_view((const char*) (header + 1) + header->extras_length, ntohs(header->key_length));
}

std::string_view get_value(const header_t* header) {
    const uint32_t offset = header->extras_length + ntohs(header->key_length);
    return std::string_view((const char*) (header + 1) + offset, ntohl(header->body_length) - offset);
}

bool is_valid_header(const header_t* header) {
    return ((header->magic == MSG_TYPE::Response || header->magic == MSG_TYPE::Request)
            && header->opcode < COMMAND::OUT_OF_RANGE
            && header->data_type == 0x00);
}
}
