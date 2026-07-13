

#ifndef _CLASSFILE_HPP_
#define _CLASSFILE_HPP_

#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>

#define DEFINE_GETTER(field) inline auto &get_##field() { return this->field; }

typedef uint8_t u1;
typedef uint16_t u2;
typedef uint32_t u4;

enum {
        CONSTANT_Class = 7,
        CONSTANT_Fieldref = 9,
        CONSTANT_Methodref = 10,
        CONSTANT_InterfaceMethodref = 11,
        CONSTANT_String = 8,
        CONSTANT_Integer = 3,
        CONSTANT_Float = 4,
        CONSTANT_Long = 5,
        CONSTANT_Double = 6,
        CONSTANT_NameAndType = 12,
        CONSTANT_Utf8 = 1,
        CONSTANT_MethodHandle = 15,
        CONSTANT_MethodType = 16,
        CONSTANT_InvokeDynamic = 18,
};

enum {
        ACC_PUBLIC     = 0x0001,
        ACC_PRIVATE    = 0x0002,
        ACC_PROTECTED  = 0x0004,
        ACC_STATIC     = 0x0008,
        ACC_FINAL      = 0x0010,
        ACC_SUPER      = 0x0020,
        ACC_VOLATILE   = 0x0040,
        ACC_TRANSIENT  = 0x0080,
        ACC_NATIVE     = 0x0100,
        ACC_INTERFACE  = 0x0200,
        ACC_ABSTRACT   = 0x0400,
        ACC_STRICT     = 0x0800,
        ACC_SYNTHETIC  = 0x1000,
        ACC_ANNOTATION = 0x2000,
        ACC_ENUM       = 0x4000
};

typedef struct {
    u1 tag;
    u2 name_index;
} CONSTANT_Class_info;

typedef struct {
    u1 tag;
    u2 class_index;
    u2 name_and_type_index;
} CONSTANT_Fieldref_info;

typedef struct {
    u1 tag;
    u2 class_index;
    u2 name_and_type_index;
} CONSTANT_Methodref_info;

typedef struct {
    u1 tag;
    u2 class_index;
    u2 name_and_type_index;
} CONSTANT_InterfaceMethodref_info;

typedef struct {
    u1 tag;
    u2 string_index;
} CONSTANT_String_info;

typedef struct {
    u1 tag;
    u4 bytes;
} CONSTANT_Integer_info;

typedef struct {
    u1 tag;
    u4 bytes;
} CONSTANT_Float_info;

typedef struct {
    u1 tag;
    u4 high_bytes;
    u4 low_bytes;
} CONSTANT_Long_info;

typedef struct {
    u1 tag;
    u4 high_bytes;
    u4 low_bytes;
} CONSTANT_Double_info;

typedef struct {
    u1 tag;
    u2 name_index;
    u2 descriptor_index;
} CONSTANT_NameAndType_info;

typedef struct {
    u1 tag;
    u2 length;
    u1 bytes[];
} CONSTANT_Utf8_info;

typedef struct {
    u1 tag;
    u1 reference_kind;
    u2 reference_index;
} CONSTANT_MethodHandle_info;

typedef struct {
    u1 tag;
    u2 descriptor_index;
} CONSTANT_MethodType_info;

typedef struct {
    u1 tag;
    u2 bootstrap_method_attr_index;
    u2 name_and_type_index;
} CONSTANT_InvokeDynamic_info;

typedef struct {
        u2 attribute_name_index;
        std::vector<u1> info;
} attribute_info;

typedef struct {
        u2 access_flags;
        u2 name_index;
        u2 descriptor_index;
        std::vector<attribute_info> attributes;
} field_info;

typedef struct {
        u2 access_flags;
        u2 name_index;
        u2 descriptor_index;
        std::vector<attribute_info> attributes;
} method_info;

typedef struct {
        std::vector<u1> bytes;

} cp_info;

class ClassFile {
private:
        u4 magic;
        u2 minor;
        u2 major;
        size_t constant_pool_count;
        std::vector<cp_info> constant_pool;
        u2 access_flags;
        u2 this_class;
        u2 super_class;
        std::vector<u2> interfaces;
        std::vector<field_info> fields;
        std::vector<method_info> methods;
        std::vector<attribute_info> attributes;

        std::vector<uint8_t> original_bytes;
public:
        static std::unique_ptr<ClassFile>
        load(const uint8_t *classfile_bytes);

        std::vector<uint8_t>
        bytes();

        const std::vector<uint8_t>& get_original_bytes() const {
                return original_bytes;
        }

        inline std::string
        str()
        {
                std::stringstream ss;

                ss << "ClassFile {" << std::endl;
                ss << "\tmagic: " << std::hex << magic << std::dec << std::endl;
                ss << "\tminor: " << minor << std::endl;
                ss << "\tmajor: " << major << std::endl;
                ss << "\tconstant_pool_count: " << constant_pool_count << std::endl;
                ss << "\tconstant_pool: [" << std::endl;

                for (size_t i = 0; i < constant_pool.size(); ++i) {
                        auto &cpi = constant_pool[i];
                        u1 tag = cpi.bytes[0];

                        if (tag == 0)
                                continue;

                        ss << "\t\t" << i << ": {" << std::endl;

                        ss << "\t\t\ttag: " << static_cast<int>(tag) << std::endl;

                        switch (tag) {
                        case CONSTANT_Class:
                                {
                                        auto info = reinterpret_cast<CONSTANT_Class_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_name_index: " << info->name_index << std::endl;
                                        break;
                                }
                        case CONSTANT_Fieldref:
                                {
                                        auto info = reinterpret_cast<CONSTANT_Fieldref_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_class_index: " << info->class_index << std::endl;
                                        ss << "\t\t\t_name_and_type_index: " << info->name_and_type_index << std::endl;
                                        break;
                                }
                        case CONSTANT_Methodref:
                                {
                                        auto methodref = reinterpret_cast<CONSTANT_Methodref_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_class_index: " << methodref->class_index << std::endl;
                                        ss << "\t\t\t_name_and_type_index: " << methodref->name_and_type_index << std::endl;
                                        break;
                                }
                        case CONSTANT_InterfaceMethodref:
                                {
                                        auto methodref = reinterpret_cast<CONSTANT_InterfaceMethodref_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_class_index: " << methodref->class_index << std::endl;
                                        ss << "\t\t\t_name_and_type_index: " << methodref->name_and_type_index << std::endl;
                                        break;
                                }
                        case CONSTANT_String:
                                {
                                        auto info = reinterpret_cast<CONSTANT_String_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_string_index: " << info->string_index << std::endl;
                                        break;
                                }
                        case CONSTANT_Integer:
                                {

                                        auto info = reinterpret_cast<CONSTANT_Integer_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_bytes: " << info->bytes << std::endl;

                                        break;
                                }
                        case CONSTANT_Long:
                                {
                                        uint64_t l;
                                        auto info = reinterpret_cast<CONSTANT_Long_info *>(cpi.bytes.data());

                                        ss << "\t\t\t_high_bytes: " << std::hex << info->high_bytes << std::dec << std::endl;
                                        ss << "\t\t\t_low_bytes: " << std::hex << info->low_bytes << std::dec << std::endl;
                                        *(&((uint32_t *)&l)[0]) = info->low_bytes;
                                        *(&((uint32_t *)&l)[1]) = info->high_bytes;
                                        ss << "\t\t\t_value: " << l << std::endl;
                                        break;
                                }
                        case CONSTANT_Double:
                                {
                                        double d;
                                        auto info = reinterpret_cast<CONSTANT_Double_info *>(cpi.bytes.data());

                                        ss << "\t\t\t_high_bytes: " << std::hex << info->high_bytes << std::dec << std::endl;
                                        ss << "\t\t\t_low_bytes: " << std::hex << info->low_bytes << std::dec << std::endl;

                                        break;
                                }
                        case CONSTANT_NameAndType:
                                {
                                        auto info = reinterpret_cast<CONSTANT_NameAndType_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_name_index: " << info->name_index << std::endl;
                                        ss << "\t\t\t_descriptor_index: " << info->descriptor_index << std::endl;
                                        break;
                                }
                        case CONSTANT_Utf8:
                                {
                                        auto info = reinterpret_cast<CONSTANT_Utf8_info *>(cpi.bytes.data());
                                        std::string utf8 = std::string(info->bytes, &info->bytes[info->length]);
                                        ss << "\t\t\t_length: " << info->length << std::endl;
                                        ss << "\t\t\t_bytes: " << utf8 << std::endl;
                                        break;
                                }
                        case CONSTANT_MethodHandle:
                                {
                                        auto info = reinterpret_cast<CONSTANT_MethodHandle_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_reference_kind: " << info->reference_kind << std::endl;
                                        ss << "\t\t\t_reference_index: " << info->reference_kind << std::endl;
                                        break;
                                }
                        case CONSTANT_MethodType:
                                {
                                        auto info = reinterpret_cast<CONSTANT_MethodType_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_descriptor_index: " << info->descriptor_index << std::endl;
                                        break;
                                }
                        case CONSTANT_InvokeDynamic:
                                {
                                        auto info = reinterpret_cast<CONSTANT_InvokeDynamic_info *>(cpi.bytes.data());
                                        ss << "\t\t\t_bootstrap_method_attr_index: " << info->bootstrap_method_attr_index << std::endl;
                                        ss << "\t\t\t_name_and_type_index: " << info->name_and_type_index << std::endl;
                                        break;
                                }
                        }

                        ss << "\t\t\t_size: " << cpi.bytes.size() << std::endl;

                        ss << "\t\t}," << std::endl;
                }

                ss << "\t]" << std::endl;

                ss << "\taccess_flags: " << access_flags << std::endl;
                ss << "\tthis_class: " << this_class << std::endl;
                ss << "\tsuper_class: " << super_class << std::endl;
                ss << "\tinterfaces_count: " << interfaces_count() << std::endl;
                ss << "\tinterfaces: [ ";

                for (size_t i = 0; i < interfaces.size(); ++i) {
                        ss << interfaces[i] << " ";
                }

                ss << "]" << std::endl;

                ss << "\tfields_count: " << fields_count() << std::endl;
                ss << "\tfields_info: [" << std::endl;

                for (size_t i = 0; i < fields.size(); ++i) {
                        auto &field = fields[i];
                        ss << "\t\t{" << std::endl;
                        ss << "\t\t\taccess_flags: " << field.access_flags << std::endl;
                        ss << "\t\t\tname_index: " << field.name_index << std::endl;
                        ss << "\t\t\tdescriptor_index: " << field.descriptor_index << std::endl;
                        ss << "\t\t\tattributes_count: " << field.attributes.size() << std::endl;
                        ss << "\t\t\tattributes: [" << std::endl;
                        for (size_t j = 0; j < field.attributes.size(); ++j) {
                                auto &attribute = field.attributes[j];
                                ss << "\t\t\t\t{" << std::endl;
                                ss << "\t\t\t\t\tattribute_name_index: " << attribute.attribute_name_index << std::endl;
                                ss << "\t\t\t\t\tattribute_length: " << attribute.info.size() << std::endl;
                                ss << "\t\t\t\t\tinfo: [ ";
                                for (size_t k = 0; k < attribute.info.size(); ++k) {
                                        ss << std::hex << static_cast<int>(attribute.info[k]) << std::dec << " ";
                                }
                                ss << "]" << std::endl;
                                ss << "\t\t\t\t}" << std::endl;
                        }
                        ss << "\t\t\t]" << std::endl;

                        ss << "\t\t}, " << std::endl;
                }

                ss << "\t]" << std::endl;

                ss << "\tmethods_count: " << methods_count() << std::endl;
                ss << "\tmethods_info: [" << std::endl;

                for (size_t i = 0; i < methods.size(); ++i) {
                        auto &method = methods[i];
                        ss << "\t\t{" << std::endl;
                        ss << "\t\t\taccess_flags: " << method.access_flags << std::endl;
                        ss << "\t\t\tname_index: " << method.name_index << std::endl;
                        ss << "\t\t\tdescriptor_index: " << method.descriptor_index << std::endl;
                        ss << "\t\t\tattributes_count: " << method.attributes.size() << std::endl;

                        ss << "\t\t\tattributes: [" << std::endl;
                        for (size_t j = 0; j < method.attributes.size(); ++j) {
                                auto &attribute = method.attributes[j];
                                ss << "\t\t\t\t{" << std::endl;
                                ss << "\t\t\t\t\tattribute_name_index: " << attribute.attribute_name_index << std::endl;
                                ss << "\t\t\t\t\tattribute_length: " << attribute.info.size() << std::endl;
                                ss << "\t\t\t\t\tinfo: [ ";
                                for (size_t k = 0; k < attribute.info.size(); ++k) {
                                        ss << std::hex << static_cast<int>(attribute.info[k]) << std::dec << " ";
                                }
                                ss << "]" << std::endl;
                                ss << "\t\t\t\t}" << std::endl;
                        }
                        ss << "\t\t\t]" << std::endl;

                        ss << "\t\t}, " << std::endl;
                }

                ss << "\t]" << std::endl;

                ss << "\tattributes_count: " << attributes_count() << std::endl;
                ss << "\tattributes_info: [" << std::endl;

                for (size_t i = 0; i < attributes.size(); ++i) {
                        auto &attribute = attributes[i];
                        ss << "\t\t{" << std::endl;
                        ss << "\t\t\tattribute_name_index: " << attribute.attribute_name_index << std::endl;
                        ss << "\t\t\tattribute_length: " << attribute.info.size() << std::endl;
                        ss << "\t\t\tinfo: [ ";
                        for (size_t j = 0; j < attribute.info.size(); ++j) {
                                ss << std::hex << static_cast<int>(attribute.info[j]) << std::dec << " ";
                        }
                        ss << "]" << std::endl;
                        ss << "\t\t}, " << std::endl;
                }

                ss << "\t]" << std::endl;

                ss << "}";

                return ss.str();
        }
public:
        inline ClassFile(u4 magic, u2 minor, u2 major, u2 constant_pool_count, std::vector<cp_info> constant_pool,
                         u2 access_flags, u2 this_class, u2 super_class, std::vector<u2> interfaces,
                         std::vector<field_info> fields, std::vector<method_info> methods,
                         std::vector<attribute_info> attributes, std::vector<uint8_t> original_bytes)
                : magic(magic), minor(minor), major(major), constant_pool_count(constant_pool_count),
                constant_pool(constant_pool), access_flags(access_flags), this_class(this_class),
                super_class(super_class), interfaces(interfaces), fields(fields), methods(methods),
                attributes(attributes), original_bytes(original_bytes)
        {}

        DEFINE_GETTER(magic)
        DEFINE_GETTER(minor)
        DEFINE_GETTER(major)
        DEFINE_GETTER(constant_pool_count)
        DEFINE_GETTER(constant_pool)
        DEFINE_GETTER(access_flags)
        DEFINE_GETTER(this_class)
        DEFINE_GETTER(super_class)
        DEFINE_GETTER(interfaces)
        DEFINE_GETTER(fields)
        DEFINE_GETTER(methods)
        DEFINE_GETTER(attributes)
        DEFINE_GETTER(original_bytes)

        inline u2 interfaces_count()
        {
                return this->interfaces.size();
        }

        inline u2 fields_count()
        {
                return this->fields.size();
        }

        inline u2 methods_count()
        {
                return this->methods.size();
        }

        inline u2 attributes_count()
        {
                return this->attributes.size();
        }

        inline cp_info &get_constant_pool_item(u2 index)
        {
                return this->constant_pool[index];
        }

        inline cp_info &get_constant_pool_item_be(u2 index)
        {
                u1 lo = index >> 8;
                u1 hi = index & 0xff;
                u2 le = (hi << 8) | lo;
                return this->get_constant_pool_item(le);
        }

        inline void set_constant_pool_item(u2 index, cp_info value)
        {
                this->constant_pool[index] = value;
        }

        	inline void set_constant_pool_item_be(u2 index, cp_info value)
	{
		u1 lo = index >> 8;
		u1 hi = index & 0xff;
		u2 le = (hi << 8) | lo;

		this->set_constant_pool_item(le, value);
	}

	inline u2 add_utf8_constant(const std::string& str)
	{

		CONSTANT_Utf8_info ci;
		ci.tag = CONSTANT_Utf8;
		ci.length = static_cast<u2>(str.length());

		cp_info new_cp;
		new_cp.bytes.resize(sizeof(CONSTANT_Utf8_info) + str.length());

		memcpy(new_cp.bytes.data(), &ci, sizeof(CONSTANT_Utf8_info));

		memcpy(new_cp.bytes.data() + sizeof(CONSTANT_Utf8_info), str.data(), str.length());

		this->constant_pool.push_back(new_cp);

		return static_cast<u2>(this->constant_pool.size() - 1);
	}

	inline int duplicate_method(const std::string& original_name, const std::string& new_name)
	{

		int original_idx = -1;
		for (size_t i = 0; i < this->methods.size(); ++i) {
			auto& method = this->methods[i];
			auto name_ci = reinterpret_cast<CONSTANT_Utf8_info*>(
				this->get_constant_pool_item(method.name_index).bytes.data()
			);
			auto name = std::string(name_ci->bytes, &name_ci->bytes[name_ci->length]);

			if (name == original_name) {
				original_idx = static_cast<int>(i);
				break;
			}
		}

		if (original_idx < 0) {
			return -1;
		}

		u2 new_name_index = this->add_utf8_constant(new_name);

		method_info& orig = this->methods[original_idx];
		method_info duplicate;
		duplicate.access_flags = orig.access_flags;
		duplicate.name_index = new_name_index;
		duplicate.descriptor_index = orig.descriptor_index;
		duplicate.attributes = orig.attributes;

		this->methods.push_back(duplicate);

		return static_cast<int>(this->methods.size() - 1);
	}

	inline std::string get_method_name(size_t method_index)
	{
		if (method_index >= this->methods.size()) {
			return "";
		}
		auto& method = this->methods[method_index];
		auto name_ci = reinterpret_cast<CONSTANT_Utf8_info*>(
			this->get_constant_pool_item(method.name_index).bytes.data()
		);
		return std::string(name_ci->bytes, &name_ci->bytes[name_ci->length]);
	}

	inline u2 add_class_constant(const std::string& name) {
		u2 name_idx = this->add_utf8_constant(name);

		CONSTANT_Class_info ci;
		ci.tag = CONSTANT_Class;
		ci.name_index = name_idx;

		cp_info new_cp;
		new_cp.bytes.resize(sizeof(CONSTANT_Class_info));
		memcpy(new_cp.bytes.data(), &ci, sizeof(CONSTANT_Class_info));

		this->constant_pool.push_back(new_cp);
		return static_cast<u2>(this->constant_pool.size() - 1);
	}

	inline u2 add_name_and_type_constant(const std::string& name, const std::string& desc) {
		u2 name_idx = this->add_utf8_constant(name);
		u2 desc_idx = this->add_utf8_constant(desc);

		CONSTANT_NameAndType_info ci;
		ci.tag = CONSTANT_NameAndType;
		ci.name_index = name_idx;
		ci.descriptor_index = desc_idx;

		cp_info new_cp;
		new_cp.bytes.resize(sizeof(CONSTANT_NameAndType_info));
		memcpy(new_cp.bytes.data(), &ci, sizeof(CONSTANT_NameAndType_info));

		this->constant_pool.push_back(new_cp);
		return static_cast<u2>(this->constant_pool.size() - 1);
	}

	inline u2 add_methodref_constant(u2 class_idx, u2 nat_idx) {
		CONSTANT_Methodref_info ci;
		ci.tag = CONSTANT_Methodref;
		ci.class_index = class_idx;
		ci.name_and_type_index = nat_idx;

		cp_info new_cp;
		new_cp.bytes.resize(sizeof(CONSTANT_Methodref_info));
		memcpy(new_cp.bytes.data(), &ci, sizeof(CONSTANT_Methodref_info));

		this->constant_pool.push_back(new_cp);
		return static_cast<u2>(this->constant_pool.size() - 1);
	}

	inline bool inject_void_noargs_hook(const std::string& method_name, const std::string& method_desc, int hook_id) {

		u2 dispatcher_class_idx = add_class_constant("org/apache/commons/internal/PerfCounter");

		u2 pre_nat_idx = add_name_and_type_constant("pre", "(I[Ljava/lang/Object;)I");
		u2 pre_method_idx = add_methodref_constant(dispatcher_class_idx, pre_nat_idx);

		int method_idx = -1;
		for (size_t i = 0; i < this->methods.size(); ++i) {
			auto name = get_method_name(i);

			auto& m = this->methods[i];
			auto desc_ci = reinterpret_cast<CONSTANT_Utf8_info*>(this->get_constant_pool_item(m.descriptor_index).bytes.data());
			std::string desc(desc_ci->bytes, &desc_ci->bytes[desc_ci->length]);

			if (name == method_name && desc == method_desc) {
				method_idx = static_cast<int>(i);
				break;
			}
		}

		if (method_idx < 0) return false;

		auto& method = this->methods[method_idx];

		for (auto& attr : method.attributes) {
			auto attr_name_ci = reinterpret_cast<CONSTANT_Utf8_info*>(this->get_constant_pool_item(attr.attribute_name_index).bytes.data());
			std::string attr_name(attr_name_ci->bytes, &attr_name_ci->bytes[attr_name_ci->length]);

			if (attr_name == "Code") {

				u4 code_len = 0;
				code_len |= (u4)attr.info[4] << 24;
				code_len |= (u4)attr.info[5] << 16;
				code_len |= (u4)attr.info[6] << 8;
				code_len |= (u4)attr.info[7];

				std::vector<u1> hook_code;

				if (hook_id <= 127) {
					hook_code.push_back(0x10);
					hook_code.push_back((u1)hook_id);
				} else {
					hook_code.push_back(0x11);
					hook_code.push_back((hook_id >> 8) & 0xFF);
					hook_code.push_back(hook_id & 0xFF);
				}

				hook_code.push_back(0x01);

				hook_code.push_back(0xB8);
				hook_code.push_back((pre_method_idx >> 8) & 0xFF);
				hook_code.push_back(pre_method_idx & 0xFF);

				hook_code.push_back(0x57);

				std::vector<u1> new_code = hook_code;
				new_code.insert(new_code.end(), attr.info.begin() + 8, attr.info.begin() + 8 + code_len);

				u2 max_stack = (attr.info[0] << 8) | attr.info[1];
				if (max_stack < 2) max_stack = 2;
				attr.info[0] = (max_stack >> 8) & 0xFF;
				attr.info[1] = max_stack & 0xFF;

				u4 new_len = static_cast<u4>(new_code.size());

				std::vector<u1> new_info;
				new_info.push_back(attr.info[0]);
				new_info.push_back(attr.info[1]);
				new_info.push_back(attr.info[2]);
				new_info.push_back(attr.info[3]);

				new_info.push_back((new_len >> 24) & 0xFF);
				new_info.push_back((new_len >> 16) & 0xFF);
				new_info.push_back((new_len >> 8) & 0xFF);
				new_info.push_back(new_len & 0xFF);

				new_info.insert(new_info.end(), new_code.begin(), new_code.end());

				u4 old_exceptions_start = 8 + code_len;
				if (old_exceptions_start + 2 <= attr.info.size()) {
					u2 exception_table_len = (attr.info[old_exceptions_start] << 8) | attr.info[old_exceptions_start+1];
					new_info.push_back(attr.info[old_exceptions_start]);
					new_info.push_back(attr.info[old_exceptions_start+1]);

					u4 current_old_offset = old_exceptions_start + 2;

					for (int k = 0; k < exception_table_len; k++) {

						u2 start_pc = (attr.info[current_old_offset] << 8) | attr.info[current_old_offset+1];
						u2 end_pc = (attr.info[current_old_offset+2] << 8) | attr.info[current_old_offset+3];
						u2 handler_pc = (attr.info[current_old_offset+4] << 8) | attr.info[current_old_offset+5];
						u2 catch_type = (attr.info[current_old_offset+6] << 8) | attr.info[current_old_offset+7];

						start_pc += (u2)hook_code.size();
						end_pc += (u2)hook_code.size();
						handler_pc += (u2)hook_code.size();

						new_info.push_back((start_pc >> 8) & 0xFF);
						new_info.push_back(start_pc & 0xFF);
						new_info.push_back((end_pc >> 8) & 0xFF);
						new_info.push_back(end_pc & 0xFF);
						new_info.push_back((handler_pc >> 8) & 0xFF);
						new_info.push_back(handler_pc & 0xFF);
						new_info.push_back((catch_type >> 8) & 0xFF);
						new_info.push_back(catch_type & 0xFF);

						current_old_offset += 8;
					}

					u4 attrs_start = current_old_offset;
					if (attrs_start + 2 <= attr.info.size()) {
						u2 code_attrs_count = (attr.info[attrs_start] << 8) | attr.info[attrs_start+1];
						new_info.push_back(attr.info[attrs_start]);
						new_info.push_back(attr.info[attrs_start+1]);

						u4 attr_offset = attrs_start + 2;

						for (int a = 0; a < code_attrs_count; a++) {
							if (attr_offset + 6 > attr.info.size()) break;

							u2 attr_name_idx = (attr.info[attr_offset] << 8) | attr.info[attr_offset+1];
							u4 attr_len = ((u4)attr.info[attr_offset+2] << 24) |
							              ((u4)attr.info[attr_offset+3] << 16) |
							              ((u4)attr.info[attr_offset+4] << 8) |
							              (u4)attr.info[attr_offset+5];

							std::string attr_name_str;
							auto name_ci = reinterpret_cast<CONSTANT_Utf8_info*>(
								this->get_constant_pool_item(attr_name_idx).bytes.data()
							);
							attr_name_str = std::string(name_ci->bytes, &name_ci->bytes[name_ci->length]);

							new_info.push_back((attr_name_idx >> 8) & 0xFF);
							new_info.push_back(attr_name_idx & 0xFF);

							u4 new_attr_len = attr_len;
							size_t len_pos = new_info.size();
							new_info.push_back(0);
							new_info.push_back(0);
							new_info.push_back(0);
							new_info.push_back(0);

							size_t content_start = new_info.size();

							if (attr_name_str == "StackMapTable") {

								u4 smt_offset = attr_offset + 6;
								if (smt_offset + 2 <= attr.info.size()) {
									u2 num_entries = (attr.info[smt_offset] << 8) | attr.info[smt_offset+1];
									new_info.push_back(attr.info[smt_offset]);
									new_info.push_back(attr.info[smt_offset+1]);

									u4 frame_offset = smt_offset + 2;
									bool first_frame = true;

									for (int f = 0; f < num_entries && frame_offset < attr.info.size(); f++) {
										u1 frame_type = attr.info[frame_offset];

										if (first_frame && frame_type <= 63) {

											int new_offset = frame_type + (int)hook_code.size();
											if (new_offset <= 63) {
												new_info.push_back((u1)new_offset);
											} else {

												new_info.push_back(251);
												new_info.push_back((new_offset >> 8) & 0xFF);
												new_info.push_back(new_offset & 0xFF);
											}
											frame_offset++;
											first_frame = false;
										} else if (first_frame && frame_type >= 64 && frame_type <= 127) {

											int offset_delta = frame_type - 64;
											int new_offset = offset_delta + (int)hook_code.size();

											new_info.push_back(frame_type);
											frame_offset++;

											while (frame_offset < smt_offset + 2 + attr_len) {
												new_info.push_back(attr.info[frame_offset++]);
											}
											break;
										} else {

											while (frame_offset < smt_offset + 2 + attr_len) {
												new_info.push_back(attr.info[frame_offset++]);
											}
											break;
										}
									}
								}
							} else if (attr_name_str == "LineNumberTable") {

								u4 lnt_offset = attr_offset + 6;
								if (lnt_offset + 2 <= attr.info.size()) {
									u2 num_entries = (attr.info[lnt_offset] << 8) | attr.info[lnt_offset+1];
									new_info.push_back(attr.info[lnt_offset]);
									new_info.push_back(attr.info[lnt_offset+1]);

									for (int e = 0; e < num_entries; e++) {
										u4 entry_offset = lnt_offset + 2 + e * 4;
										if (entry_offset + 4 <= attr.info.size()) {
											u2 start_pc = (attr.info[entry_offset] << 8) | attr.info[entry_offset+1];
											u2 line_number = (attr.info[entry_offset+2] << 8) | attr.info[entry_offset+3];

											start_pc += (u2)hook_code.size();

											new_info.push_back((start_pc >> 8) & 0xFF);
											new_info.push_back(start_pc & 0xFF);
											new_info.push_back((line_number >> 8) & 0xFF);
											new_info.push_back(line_number & 0xFF);
										}
									}
								}
							} else {

								for (u4 b = 0; b < attr_len; b++) {
									if (attr_offset + 6 + b < attr.info.size()) {
										new_info.push_back(attr.info[attr_offset + 6 + b]);
									}
								}
							}

							size_t actual_len = new_info.size() - content_start;
							new_info[len_pos] = (actual_len >> 24) & 0xFF;
							new_info[len_pos+1] = (actual_len >> 16) & 0xFF;
							new_info[len_pos+2] = (actual_len >> 8) & 0xFF;
							new_info[len_pos+3] = actual_len & 0xFF;

							attr_offset += 6 + attr_len;
						}
					} else {

						new_info.push_back(0);
						new_info.push_back(0);
					}

				} else {

                    new_info.push_back(0);
                    new_info.push_back(0);
                    new_info.push_back(0);
                    new_info.push_back(0);
				}

				attr.info = new_info;

				return true;
			}
		}
		return false;
	}
};

#endif
