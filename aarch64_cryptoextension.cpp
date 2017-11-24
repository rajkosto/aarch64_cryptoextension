#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>

#if (IDA_SDK_VERSION < 700) && defined(__X64__)
	#error Incompatible SDK version. Please use SDK 7.0 or higher
#elif (IDA_SDK_VERSION >= 700) && !defined(__X64__)
	#error Incompatible SDK version. Please use SDK 6.95 or lower
#endif

#if IDA_SDK_VERSION >= 700
	#define idaapi_hook_cb_ret_t	ssize_t 
	#define idaapi_get_dword		get_dword
	#define op_dtype				dtype
#else
	#define idaapi_hook_cb_ret_t	int 
	#define idaapi_get_dword		get_long
	#define op_dtype				dtyp
#endif

#ifndef __EA64__
#error This extension only makes sense in a 64bit context
#endif

#define MAGIC_ACTIVATED   333
#define MAGIC_DEACTIVATED 777

inline bool is_arm64_ea(ea_t ea)
{
	segment_t *seg = getseg(ea);
	return seg != NULL && seg->use64();
}

#define cond segpref

#define simd_sz specflag1

#define cAL 14

#define Q0 45
#define S0 93
#define V0 163

static size_t ana(insn_t* inst)
{
	uint32_t code = idaapi_get_dword(inst->ea);
	uint32_t Rn, Rd, Rm;

	if ((code & 0xFFFF0C00) == 0x4E280800) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rd += V0;
		Rn += V0;
		if ((code & 0xF000) == 0x5000) {
			inst->itype = ARM_aesd;
			inst->cond = cAL; 
			inst->Op1.type = o_reg;
			inst->Op1.simd_sz = 1;
			inst->Op1.reg = Rd;
			inst->Op1.op_dtype = dt_byte16;
			inst->Op2.type = o_reg;
			inst->Op2.simd_sz = 1;
			inst->Op2.reg = Rn;
			inst->Op2.op_dtype = dt_byte16;
			return 4;
		} else if ((code & 0xF000) == 0x4000) {
			inst->itype = ARM_aese;
			inst->cond = cAL; 
			inst->Op1.type = o_reg;
			inst->Op1.simd_sz = 1;
			inst->Op1.reg = Rd;
			inst->Op1.op_dtype = dt_byte16;
			inst->Op2.type = o_reg;
			inst->Op2.simd_sz = 1;
			inst->Op2.reg = Rn;
			inst->Op2.op_dtype = dt_byte16;
			return 4;
		} else if ((code & 0xF000) == 0x7000) {
			inst->itype = ARM_aesimc;
			inst->cond = cAL; 
			inst->Op1.type = o_reg;
			inst->Op1.simd_sz = 1;
			inst->Op1.reg = Rd;
			inst->Op1.op_dtype = dt_byte16;
			inst->Op2.type = o_reg;
			inst->Op2.simd_sz = 1;
			inst->Op2.reg = Rn;
			inst->Op2.op_dtype = dt_byte16;
			return 4;
		} else if ((code & 0xF000) == 0x6000) {
			inst->itype = ARM_aesmc;
			inst->cond = cAL; 
			inst->Op1.type = o_reg;
			inst->Op1.simd_sz = 1;
			inst->Op1.reg = Rd;
			inst->Op1.op_dtype = dt_byte16;
			inst->Op2.type = o_reg;
			inst->Op2.simd_sz = 1;
			inst->Op2.reg = Rn;
			inst->Op2.op_dtype = dt_byte16;
			return 4;
		}
	} else if ((code & 0xFFE0FC00) == 0x5E000000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += S0;
		Rm += V0;
		inst->itype = ARM_sha1c;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_dword;
		inst->Op3.type = o_reg;
		inst->Op3.simd_sz = 3;
		inst->Op3.reg = Rm;
		inst->Op3.op_dtype = dt_byte16;
		return 4;
	} else if ((code & 0xFFFFFC00) == 0x5E280800) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rd += S0;
		Rn += S0;
		inst->itype = ARM_sha1h;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.op_dtype = dt_dword;
		inst->Op2.type = o_reg;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_dword;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E002000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += S0;
		Rm += V0;
		inst->itype = ARM_sha1m;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_dword;
		inst->Op3.type = o_reg;
		inst->Op3.simd_sz = 3;
		inst->Op3.reg = Rm;
		inst->Op3.op_dtype = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E001000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += S0;
		Rm += V0;
		inst->itype = ARM_sha1p;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_dword;
		inst->Op3.type = o_reg;
		inst->Op3.simd_sz = 3;
		inst->Op3.reg = Rm;
		inst->Op3.op_dtype = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E003000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += V0;
		Rn += V0;
		Rm += V0;
		inst->itype = ARM_sha1su0;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.simd_sz = 3;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.simd_sz = 3;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_byte16;
		inst->Op3.type = o_reg;
		inst->Op3.simd_sz = 3;
		inst->Op3.reg = Rm;
		inst->Op3.op_dtype = dt_byte16;
		return 4;
	} else if ((code & 0xFFFFFC00) == 0x5E281800) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rd += V0;
		Rn += V0;
		inst->itype = ARM_sha1su1;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.simd_sz = 3;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.simd_sz = 3;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E005000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += Q0;
		Rm += V0;
		inst->itype = ARM_sha256h2;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_byte16;
		inst->Op3.type = o_reg;
		inst->Op3.simd_sz = 3;
		inst->Op3.reg = Rm;
		inst->Op3.op_dtype = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E004000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += Q0;
		Rn += Q0;
		Rm += V0;
		inst->itype = ARM_sha256h;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_byte16;
		inst->Op3.type = o_reg;
		inst->Op3.simd_sz = 3;
		inst->Op3.reg = Rm;
		inst->Op3.op_dtype = dt_byte16;
		return 4;
	} else if ((code & 0xFFFFFC00) == 0x5E282800) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rd += V0;
		Rn += V0;
		inst->itype = ARM_sha256su0;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.simd_sz = 3;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.simd_sz = 3;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_byte16;
		return 4;
	} else if ((code & 0xFFE0FC00) == 0x5E006000) {
		Rn = (code >> 5) & 31;
		Rd = (code) & 31;
		Rm = (code >> 16) & 31;
		Rd += V0;
		Rn += V0;
		Rm += V0;
		inst->itype = ARM_sha256su1;
		inst->cond = cAL; 
		inst->Op1.type = o_reg;
		inst->Op1.reg = Rd;
		inst->Op1.simd_sz = 3;
		inst->Op1.op_dtype = dt_byte16;
		inst->Op2.type = o_reg;
		inst->Op2.simd_sz = 3;
		inst->Op2.reg = Rn;
		inst->Op2.op_dtype = dt_byte16;
		inst->Op3.type = o_reg;
		inst->Op3.simd_sz = 3;
		inst->Op3.reg = Rm;
		inst->Op3.op_dtype = dt_byte16;
		return 4;
	}
	return 0;
}

static idaapi_hook_cb_ret_t idaapi aarch64_extension_callback(void * user_data, int event_id, va_list va)
{
	switch (event_id)
	{
		case processor_t::ev_ana_insn:
		{
		#if IDA_SDK_VERSION >= 700
			#define ret		inst->size
			insn_t* inst = va_arg(va, insn_t *);
		#else
			#define ret		2
			insn_t* inst = &cmd;
		#endif

			if (is_arm64_ea(inst->ea)) {
				size_t length = ana(inst);
				if (length)
				{
					inst->size = (uint16)length;
					return ret;
				}
			}
		}
		break;
	}
	return 0;
}

static bool enabled = false;
static netnode aarch64_node;
static const char node_name[] = "$ AArch64 crypto extension processor extender parameters";

int idaapi init(void)
{
	if (ph.id != PLFM_ARM) return PLUGIN_SKIP;
	aarch64_node.create(node_name);
	enabled = aarch64_node.altval(0) != MAGIC_DEACTIVATED;
	if (enabled)
	{
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
		msg("AArch64 crypto extension processor extender is enabled\n");
		return PLUGIN_KEEP;
	}
	return PLUGIN_OK;
}


void idaapi term(void)
{
	unhook_from_notification_point(HT_IDP, aarch64_extension_callback);
}

#if IDA_SDK_VERSION >= 700
bool idaapi run(size_t /*arg*/)
#else
void idaapi run(int /*arg*/)
#endif
{
	if (enabled) {
		unhook_from_notification_point(HT_IDP, aarch64_extension_callback);
	} else {
		hook_to_notification_point(HT_IDP, aarch64_extension_callback, NULL);
	}
	enabled = !enabled;
	aarch64_node.create(node_name);
	aarch64_node.altset(0, enabled ? MAGIC_ACTIVATED : MAGIC_DEACTIVATED);
	info("AUTOHIDE NONE\n" "AArch64 crypto extension processor extender now is %s", enabled ? "enabled" : "disabled");

#if IDA_SDK_VERSION >= 700
	return true;
#endif
}

//--------------------------------------------------------------------------
static const char comment[] = "AArch64 crypto extension processor extender";
static const char help[] = "This module adds support for AArch64 crypto extension instructions to IDA.\n";

static const char wanted_name[] = "AArch64 crypto extension processor extender";

static const char wanted_hotkey[] = "";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	init,
	term,
	run,
	comment,
	help,
	wanted_name,
	wanted_hotkey
};
