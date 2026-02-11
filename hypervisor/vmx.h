#pragma once
#include <intrin.h>
#include <ntifs.h>
#include "memory.h"
#include "ia32.h"

#define CPUID_VMX_SUPPORT_BIT 5 
#define CR4_VMXE_BIT 13
#define BIT(n) (1ULL << (n))

#define MSR_IA32_VMX_BASIC              0x480
#define MSR_IA32_VMX_PINBASED_CTLS      0x481
#define MSR_IA32_VMX_PROCBASED_CTLS     0x482
#define MSR_IA32_VMX_EXIT_CTLS          0x483
#define MSR_IA32_VMX_ENTRY_CTLS         0x484
#define MSR_IA32_VMX_MISC               0x485

#define MSR_IA32_VMX_CR0_FIXED0         0x486
#define MSR_IA32_VMX_CR0_FIXED1         0x487
#define MSR_IA32_VMX_CR4_FIXED0         0x488
#define MSR_IA32_VMX_CR4_FIXED1         0x489
#define MSR_IA32_VMX_VMCS_ENUM          0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2    0x48B
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS 0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS     0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS    0x490

#define CPU_BASED_ACTIVATE_MSR_BITMAP           (1 << 28)
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   (1 << 31)

#define SECONDARY_EXEC_ENABLE_RDTSCP    (1 << 3)
#define SECONDARY_EXEC_ENABLE_INVPCID   (1 << 12)
#define SECONDARY_EXEC_XSAVES           (1 << 20)

#define VM_EXIT_ACK_INTR_ON_EXIT        (1 << 15)
#define VM_EXIT_HOST_ADDR_SPACE_SIZE    (1 << 9)
#define VM_EXIT_SAVE_IA32_EFER          (1 << 20)
#define VM_EXIT_LOAD_IA32_EFER          (1 << 21)

#define VM_ENTRY_IA32E_MODE             (1 << 9)
#define VM_ENTRY_LOAD_IA32_EFER         (1 << 15)

#define KERNEL_STACK_SIZE 0x6000

#include "vmx_structs.h"

typedef struct vmx_region
{
    unsigned long revision_id;
    unsigned char data[PAGE_SIZE - sizeof(unsigned long)];
} vmx_region;

typedef struct dtr_t
{
    unsigned short limit;
    unsigned long long base;
} dtr_t;

extern "C"
{
    std::uint64_t get_gdt_base(void);
    std::uint16_t get_gdt_limit(void);
    std::uint64_t get_idt_base(void);
    std::uint16_t get_idt_limit(void);
    std::uint16_t get_cs(void);
    std::uint16_t get_ds(void);
    std::uint16_t get_es(void);
    std::uint16_t get_ss(void);
    std::uint16_t get_gs(void);
    std::uint16_t get_ldtr(void);
    std::uint16_t get_tr(void);
    std::uint16_t get_fs(void);
    std::uint64_t get_rflags(void);
    std::uint64_t capture_context(void);

    void asm_sgdt(void* gdtr);
    void asm_sidt(KDESCRIPTOR* idtr);
}

enum vmx_state
{
    VMX_STATE_OFF = 0,
    VMX_STATE_TRANSITION = 1,
    VMX_STATE_ON = 2
};

typedef struct vmx_capabilities
{
    UINT64 vmx_basic;
    UINT64 pinbased_ctls;
    UINT64 procbased_ctls;
    UINT64 exit_ctls;
    UINT64 entry_ctls;
    UINT64 misc;
    UINT64 cr0_fixed0;
    UINT64 cr0_fixed1;
    UINT64 cr4_fixed0;
    UINT64 cr4_fixed1;
    UINT64 vmcs_enum;
    UINT64 procbased_ctls2;
    UINT64 true_pinbased_ctls;
    UINT64 true_procbased_ctls;
    UINT64 true_exit_ctls;
    UINT64 true_entry_ctls;
} vmx_capabilities;

typedef struct vcpu_data
{
    PHYSICAL_ADDRESS vmxon_region_physical;
    PHYSICAL_ADDRESS vmcs_region_physical;

    vmx_region* vmxon_region;
    vmx_region* vmcs_region;

    void* host_stack;
    bool vmx_enabled;

    void* msr_bitmap;
    PHYSICAL_ADDRESS physical_msr_bitmap;

    vmx_capabilities caps;

    CONTEXT ctx_frame;
    special_registers_t special_registers;

    volatile vmx_state vmx_state;
} vcpu_data;

vcpu_data* g_cpu_data[256] = { 0 };
ULONG g_core_count = 0;

typedef struct vmx_init_context
{
    volatile long cores_completed;
    volatile long cores_success;
    vcpu_data* cpu_data[256];
} vmx_init_context;

vmx_init_context g_init_context = { 0 };

struct segment_descriptor
{
    unsigned short selector;
    unsigned long long base;
    unsigned long limit;
    unsigned long access_rights;
};

namespace vmx
{
    extern "C" void vm_restore_context(CONTEXT* ctx);

    unsigned long get_vmx_revision_id()
    {
        auto vmx_basic = __readmsr(MSR_IA32_VMX_BASIC);
        unsigned long revision_id = vmx_basic & 0x7FFFFFFF;
        DbgPrint("vmx revision id 0x%X\n", revision_id);
        return revision_id;
    }

    bool check_vmx_support()
    {
        auto vmx_basic = __readmsr(MSR_IA32_VMX_BASIC);

        UINT64 vmcs_size = (vmx_basic >> 32) & 0x1FFF;
        if (vmcs_size > PAGE_SIZE)
        {
            DbgPrint("vmcs size %lld exceeds page size\n", vmcs_size);
            return false;
        }

        UINT64 mem_type = (vmx_basic >> 50) & 0xF;
        if (mem_type != 6)
        {
            DbgPrint("unsupported memory type %lld\n", mem_type);
            return false;
        }

        return true;
    }

    bool is_vmx_supported()
    {
        int cpu[4];

        __cpuid(cpu, 1);
        if (!(cpu[2] & BIT(CPUID_VMX_SUPPORT_BIT)))
        {
            DbgPrint("vmx not supported by cpu\n");
            return false;
        }

        unsigned long long feature_control = __readmsr(0x3A);

        if (!(feature_control & BIT(0)))
        {
            __writemsr(0x3A, feature_control | BIT(0) | BIT(2));
            DbgPrint("enabled feature control lock\n");
        }
        else if (!(feature_control & BIT(2)))
        {
            DbgPrint("vmx locked and disabled in bios\n");
            return false;
        }

        if (!check_vmx_support())
        {
            return false;
        }

        DbgPrint("vmx is supported\n");
        return true;
    }

    bool is_vmx_enabled()
    {
        unsigned long long cr4 = __readcr4();
        return (cr4 & BIT(CR4_VMXE_BIT)) != 0;
    }

    bool enable_vmx()
    {
        if (is_vmx_enabled())
        {
            DbgPrint("vmx already enabled\n");
            return true;
        }

        ULONG_PTR cr4 = __readcr4();
        __writecr4(cr4 | BIT(CR4_VMXE_BIT));
        DbgPrint("enabled vmx in cr4\n");
        return true;
    }

    UINT64 vmx_read(UINT32 field)
    {
        SIZE_T value;
        __vmx_vmread(field, &value);
        return value;
    }

    void vmx_write(UINT32 field, UINT64 value)
    {
        __vmx_vmwrite(field, value);
    }

    unsigned long adjust_controls(unsigned long requested, std::uint64_t msr_value)
    {
        requested |= (msr_value & 0xFFFFFFFF);
        requested &= (msr_value >> 32);
        return requested;
    }

    extern "C"
    {
        void capture_ctx(CONTEXT* context);
        DECLSPEC_NORETURN void restore_ctx(CONTEXT* context);
        void vmexit_handler();
        DECLSPEC_NORETURN void vmentry_handler(PCONTEXT context);
    }

    void vmx_resume()
    {
        __vmx_vmresume();

        ULONG64 error = 0;
        __vmx_vmread(VM_INSTRUCTION_ERROR, &error);
        DbgPrint("vmresume failed with error 0x%llx\n", error);
        __debugbreak();
    }

    void vmx_handle_cpuid(vp_state* vp_state)
    {
        INT32 cpu_info[4];

        if ((vp_state->vp_regs->Rax == 0x41414141) &&
            (vp_state->vp_regs->Rcx == 0x42424242) &&
            ((vmx_read(GUEST_CS_SELECTOR) & RPL_MASK) == DPL_SYSTEM))
        {
            vp_state->exit_vm = TRUE;
            return;
        }

        __cpuidex(cpu_info, (INT32)vp_state->vp_regs->Rax, (INT32)vp_state->vp_regs->Rcx);

        if (vp_state->vp_regs->Rax == 1)
        {
            cpu_info[2] |= (1 << 31);
        }

        vp_state->vp_regs->Rax = cpu_info[0];
        vp_state->vp_regs->Rbx = cpu_info[1];
        vp_state->vp_regs->Rcx = cpu_info[2];
        vp_state->vp_regs->Rdx = cpu_info[3];
    }

    void vmx_handle_invd(vp_state* vp_state)
    {
        __wbinvd();
    }

    void vmx_handle_xsetbv(vp_state* vp_state)
    {
        _xsetbv((UINT32)vp_state->vp_regs->Rcx,
            ((UINT64)vp_state->vp_regs->Rdx << 32) | (UINT32)vp_state->vp_regs->Rax);
    }

    void vmx_handle_vmcall(vp_state* vp_state)
    {
        ULONG32 hypercall_number = (ULONG32)(vp_state->vp_regs->Rcx & 0xFFFF);

        switch (hypercall_number)
        {
        case 0x1337:
            vp_state->exit_vm = TRUE;
            break;
        default:
            DbgPrint("unknown hypercall 0x%x\n", hypercall_number);
            break;
        }
    }

    void vmx_handle_cr_access(vp_state* vp_state)
    {
        UINT64 exit_qual = vp_state->exit_qualification;
        UINT64 cr_num = (exit_qual >> 0) & 0xF;
        UINT64 access_type = (exit_qual >> 4) & 0x3;
        UINT64 reg_num = (exit_qual >> 8) & 0xF;

        PULONG64 reg_ptr = (PULONG64)&vp_state->vp_regs->Rax + reg_num;

        switch (access_type)
        {
        case 0:
            switch (cr_num)
            {
            case 0:
                vmx_write(GUEST_CR0, *reg_ptr);
                vmx_write(CR0_READ_SHADOW, *reg_ptr);
                break;
            case 3:
                vmx_write(GUEST_CR3, *reg_ptr);
                break;
            case 4:
                vmx_write(GUEST_CR4, *reg_ptr);
                vmx_write(CR4_READ_SHADOW, *reg_ptr);
                break;
            }
            break;

        case 1:
            switch (cr_num)
            {
            case 0:
                *reg_ptr = vmx_read(GUEST_CR0);
                break;
            case 3:
                *reg_ptr = vmx_read(GUEST_CR3);
                break;
            case 4:
                *reg_ptr = vmx_read(GUEST_CR4);
                break;
            }
            break;
        }
    }

    void vmx_handle_msr_read(vp_state* vp_state)
    {
        UINT32 msr = (UINT32)vp_state->vp_regs->Rcx;
        UINT64 msr_value = __readmsr(msr);

        vp_state->vp_regs->Rax = msr_value & 0xFFFFFFFF;
        vp_state->vp_regs->Rdx = msr_value >> 32;
    }

    void vmx_handle_msr_write(vp_state* vp_state)
    {
        UINT32 msr = (UINT32)vp_state->vp_regs->Rcx;
        UINT64 msr_value = ((UINT64)vp_state->vp_regs->Rdx << 32) | (UINT32)vp_state->vp_regs->Rax;

        __writemsr(msr, msr_value);
    }

    void vmx_handle_rdtsc(vp_state* vp_state)
    {
        UINT64 tsc = __rdtsc();
        vp_state->vp_regs->Rax = tsc & 0xFFFFFFFF;
        vp_state->vp_regs->Rdx = tsc >> 32;
    }

    void vmx_handle_rdtscp(vp_state* vp_state)
    {
        UINT32 aux;
        UINT64 tsc = __rdtscp(&aux);
        vp_state->vp_regs->Rax = tsc & 0xFFFFFFFF;
        vp_state->vp_regs->Rdx = tsc >> 32;
        vp_state->vp_regs->Rcx = aux;
    }


    void handle_exit(vp_state* vpstate)
    {
        switch (vpstate->exit_reason)
        {
        case EXIT_REASON_CPUID:
        {
            vmx_handle_cpuid(vpstate);
            break;
        }
        case EXIT_REASON_RDTSCP:
        {
            vmx_handle_rdtscp(vpstate);
            break;
        }
        case EXIT_REASON_RDTSC:
        {
            vmx_handle_rdtsc(vpstate);
            break;
        }
        case EXIT_REASON_VMCALL:
        {
            vmx_handle_vmcall(vpstate);
            break;
        }
        case EXIT_REASON_XSETBV:
        {
            vmx_handle_xsetbv(vpstate);
            break;
        }
        case EXIT_REASON_INVPCID:
        {
            vmx_handle_invd(vpstate);
            break;
        }
        case EXIT_REASON_HLT:
        {
            __halt();
            break;
        }
        case EXIT_REASON_VMWRITE:
        {
            //inject #ud here
            break;
        }
        case EXIT_REASON_CR_ACCESS:
        {
            vmx_handle_cr_access(vpstate);
            break;
        }
        case EXIT_REASON_MSR_READ:
        {
            vmx_handle_msr_read(vpstate);
            break;
        }
        case EXIT_REASON_MSR_WRITE:
        {
            vmx_handle_msr_write(vpstate);
            break;
        }
        //todo: inject ud in any VM instruction (vmcall, vmwrite, vmxon) 
        default:
            KeBugCheck(INVALID_DRIVER_HANDLE); 
            break;
        }

        vpstate->guest_rip += vmx_read(VM_EXIT_INSTRUCTION_LEN);
        __vmx_vmwrite(GUEST_RIP, vpstate->guest_rip);
    }

    extern "C" void vmentry_handler_cpp(PCONTEXT context)
    {

        context->Rcx = *reinterpret_cast<UINT64*>(reinterpret_cast<ULONG64>(context) - sizeof(context->Rcx));
        const vcpu_data* vcpu = reinterpret_cast<vcpu_data*>(reinterpret_cast<ULONG64>(context + 1) - KERNEL_STACK_SIZE);
        vp_state guest_ctx;
        guest_ctx.guest_eflags = vmx_read(GUEST_RFLAGS);
        guest_ctx.guest_rip = vmx_read(GUEST_RIP);
        guest_ctx.guest_rsp = vmx_read(GUEST_RSP);
        guest_ctx.exit_reason = vmx_read(VM_EXIT_REASON) & 0xFFFF;
        guest_ctx.vp_regs = context;
        guest_ctx.exit_vm = false;


        handle_exit(&guest_ctx);

        context->Rsp += sizeof(context->Rcx);
        context->Rip = (UINT64)vmx_resume;

        vm_restore_context(context);
    }

    ULONG vmx_get_segment_access_rights(USHORT selector)
    {
        if (selector == 0)
            return 0x10000;

        ULONG_PTR gdt_base = get_gdt_base();

        struct segment_descriptor_entry
        {
            USHORT limit_low;
            USHORT base_low;
            UCHAR base_mid;
            UCHAR access;
            UCHAR granularity;
            UCHAR base_high;
        } *descriptor;

        descriptor = (segment_descriptor_entry*)(gdt_base + (selector & ~7));

        ULONG access_rights = descriptor->access;
        access_rights |= (descriptor->granularity & 0xF0) << 4;

        return access_rights;
    }

    void vmx_fill_segment_descriptor(segment_desc_t* desc, std::uint16_t selector)
    {
        if (!desc)
            return;

        desc->selector = selector;

        if (selector == 0)
        {
            desc->base = 0;
            desc->limit = 0;
            desc->access_rights = 0x10000;
            return;
        }

        KDESCRIPTOR gdtr;
        asm_sgdt(&gdtr);

        std::uint64_t desc_addr = reinterpret_cast<std::uint64_t>(gdtr.Base) + (selector & ~0x7);

        std::uint64_t desc_lo = *(std::uint64_t*)desc_addr;
        std::uint64_t desc_hi = 0;

        if (((desc_lo >> 40) & 0xF) >= 0x8 || ((desc_lo >> 44) & 1) == 0)
        {
            desc_hi = *(std::uint64_t*)(desc_addr + 8);
        }

        desc->base = ((desc_lo >> 16) & 0xFFFF) |
            (((desc_lo >> 32) & 0xFF) << 16) |
            (((desc_lo >> 56) & 0xFF) << 24) |
            (desc_hi << 32);

        desc->limit = (std::uint32_t)((desc_lo & 0xFFFF) | (((desc_lo >> 48) & 0xF) << 16));

        if ((desc_lo >> 55) & 1)
            desc->limit = (desc->limit << 12) | 0xFFF;

        desc->access_rights = vmx_get_segment_access_rights(selector);
    }

    void convert_gdt_entry(void* gdt_base, std::uint16_t selector, PVMX_GDTENTRY64 gdt_entry)
    {
        PKGDTENTRY64 gdt_entry_1;

        if ((selector == 0) || (selector & SELECTOR_TABLE_INDEX) != 0)
        {
            gdt_entry->Limit = gdt_entry->AccessRights = 0;
            gdt_entry->Base = 0;
            gdt_entry->Selector = 0;
            gdt_entry->Bits.Unusable = TRUE;
            return;
        }

        gdt_entry_1 = (PKGDTENTRY64)((uintptr_t)gdt_base + (selector & ~RPL_MASK));

        gdt_entry->Selector = selector;
        gdt_entry->Limit = __segmentlimit(selector);

        gdt_entry->Base = ((gdt_entry_1->Bytes.BaseHigh << 24) |
            (gdt_entry_1->Bytes.BaseMiddle << 16) |
            (gdt_entry_1->BaseLow)) & 0xFFFFFFFF;
        gdt_entry->Base |= ((gdt_entry_1->Bits.Type & 0x10) == 0) ?
            ((uintptr_t)gdt_entry_1->BaseUpper << 32) : 0;

        gdt_entry->AccessRights = 0;
        gdt_entry->Bytes.Flags1 = gdt_entry_1->Bytes.Flags1;
        gdt_entry->Bytes.Flags2 = gdt_entry_1->Bytes.Flags2;

        gdt_entry->Bits.Reserved = 0;
        gdt_entry->Bits.Unusable = !gdt_entry_1->Bits.Present;
    }

    void capture_registers(special_registers_t* special_registers)
    {
        special_registers->Cr0 = __readcr0();
        special_registers->Cr3 = __readcr3();
        special_registers->Cr4 = __readcr4();
        special_registers->DebugControl = __readmsr(MSR_DEBUG_CTL);
        special_registers->MsrGsBase = __readmsr(MSR_GS_BASE);
        special_registers->KernelDr7 = __readdr(7);
        asm_sgdt(&special_registers->Gdtr.Limit);
        __sidt(&special_registers->Idtr.Limit);
        special_registers->Tr = get_tr();
        special_registers->Ldtr = get_ldtr();
    }

    void read_vmx_capabilities(vmx_capabilities* caps)
    {
        caps->vmx_basic = __readmsr(MSR_IA32_VMX_BASIC);
        caps->pinbased_ctls = __readmsr(MSR_IA32_VMX_PINBASED_CTLS);
        caps->procbased_ctls = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS);
        caps->exit_ctls = __readmsr(MSR_IA32_VMX_EXIT_CTLS);
        caps->entry_ctls = __readmsr(MSR_IA32_VMX_ENTRY_CTLS);
        caps->misc = __readmsr(MSR_IA32_VMX_MISC);
        caps->cr0_fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
        caps->cr0_fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
        caps->cr4_fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
        caps->cr4_fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
        caps->vmcs_enum = __readmsr(MSR_IA32_VMX_VMCS_ENUM);
        caps->procbased_ctls2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);

        if (caps->vmx_basic & (1ULL << 55))
        {
            caps->true_pinbased_ctls = __readmsr(MSR_IA32_VMX_TRUE_PINBASED_CTLS);
            caps->true_procbased_ctls = __readmsr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
            caps->true_exit_ctls = __readmsr(MSR_IA32_VMX_TRUE_EXIT_CTLS);
            caps->true_entry_ctls = __readmsr(MSR_IA32_VMX_TRUE_ENTRY_CTLS);
        }
        else
        {
            caps->true_pinbased_ctls = caps->pinbased_ctls;
            caps->true_procbased_ctls = caps->procbased_ctls;
            caps->true_exit_ctls = caps->exit_ctls;
            caps->true_entry_ctls = caps->entry_ctls;
        }
    }

    bool setup_vmcs(vcpu_data* vcpu, CONTEXT* ctx)
    {
        if (!vcpu)
            return false;

        special_registers_t registers;
        capture_registers(&registers);

        read_vmx_capabilities(&vcpu->caps);

        registers.Cr0 &= vcpu->caps.cr0_fixed1;
        registers.Cr0 |= vcpu->caps.cr0_fixed0;
        registers.Cr4 &= vcpu->caps.cr4_fixed1;
        registers.Cr4 |= vcpu->caps.cr4_fixed0;

        __writecr0(registers.Cr0);
        __writecr4(registers.Cr4);

        vmx_write(VMCS_LINK_POINTER, ~0ULL);
        vmx_write(MSR_BITMAP, vcpu->physical_msr_bitmap.QuadPart);

        vmx_write(PIN_BASED_VM_EXEC_CONTROL,
            adjust_controls(0, vcpu->caps.true_pinbased_ctls));

        vmx_write(CPU_BASED_VM_EXEC_CONTROL,
            adjust_controls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
                vcpu->caps.true_procbased_ctls));
        //VMX_SECONDARY_EXEC_ENABLE_USER_WAIT_PAUSE   
        vmx_write(SECONDARY_VM_EXEC_CONTROL,
            adjust_controls(SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_EXEC_XSAVES | 0x04000000,
                vcpu->caps.procbased_ctls2));

        vmx_write(VM_EXIT_CONTROLS,
            adjust_controls(VM_EXIT_ACK_INTR_ON_EXIT | VM_EXIT_HOST_ADDR_SPACE_SIZE,
                vcpu->caps.true_exit_ctls));

        vmx_write(VM_ENTRY_CONTROLS,
            adjust_controls(VM_ENTRY_IA32E_MODE, vcpu->caps.true_entry_ctls));

        unsigned long exception_bitmap = 0;
        exception_bitmap |= 1 << 3;

        vmx_write(EXCEPTION_BITMAP, exception_bitmap);

        VMX_GDTENTRY64 vmx_gdt_entry;

        convert_gdt_entry(registers.Gdtr.Base, ctx->SegCs, &vmx_gdt_entry);
        vmx_write(GUEST_CS_SELECTOR, vmx_gdt_entry.Selector);
        vmx_write(GUEST_CS_LIMIT, vmx_gdt_entry.Limit);
        vmx_write(GUEST_CS_AR_BYTES, vmx_gdt_entry.AccessRights);
        vmx_write(GUEST_CS_BASE, vmx_gdt_entry.Base);

        convert_gdt_entry(registers.Gdtr.Base, ctx->SegSs, &vmx_gdt_entry);
        vmx_write(GUEST_SS_SELECTOR, vmx_gdt_entry.Selector);
        vmx_write(GUEST_SS_LIMIT, vmx_gdt_entry.Limit);
        vmx_write(GUEST_SS_AR_BYTES, vmx_gdt_entry.AccessRights);
        vmx_write(GUEST_SS_BASE, vmx_gdt_entry.Base);

        convert_gdt_entry(registers.Gdtr.Base, ctx->SegDs, &vmx_gdt_entry);
        vmx_write(GUEST_DS_SELECTOR, vmx_gdt_entry.Selector);
        vmx_write(GUEST_DS_LIMIT, vmx_gdt_entry.Limit);
        vmx_write(GUEST_DS_AR_BYTES, vmx_gdt_entry.AccessRights);
        vmx_write(GUEST_DS_BASE, vmx_gdt_entry.Base);

        convert_gdt_entry(registers.Gdtr.Base, ctx->SegEs, &vmx_gdt_entry);
        vmx_write(GUEST_ES_SELECTOR, vmx_gdt_entry.Selector);
        vmx_write(GUEST_ES_LIMIT, vmx_gdt_entry.Limit);
        vmx_write(GUEST_ES_AR_BYTES, vmx_gdt_entry.AccessRights);
        vmx_write(GUEST_ES_BASE, vmx_gdt_entry.Base);

        convert_gdt_entry(registers.Gdtr.Base, ctx->SegFs, &vmx_gdt_entry);
        vmx_write(GUEST_FS_SELECTOR, vmx_gdt_entry.Selector);
        vmx_write(GUEST_FS_LIMIT, vmx_gdt_entry.Limit);
        vmx_write(GUEST_FS_AR_BYTES, vmx_gdt_entry.AccessRights);
        vmx_write(GUEST_FS_BASE, vmx_gdt_entry.Base);

        convert_gdt_entry(registers.Gdtr.Base, ctx->SegGs, &vmx_gdt_entry);
        vmx_write(GUEST_GS_SELECTOR, vmx_gdt_entry.Selector);
        vmx_write(GUEST_GS_LIMIT, vmx_gdt_entry.Limit);
        vmx_write(GUEST_GS_AR_BYTES, vmx_gdt_entry.AccessRights);
        vmx_write(GUEST_GS_BASE, registers.MsrGsBase);

        convert_gdt_entry(registers.Gdtr.Base, registers.Tr, &vmx_gdt_entry);
        vmx_write(GUEST_TR_SELECTOR, vmx_gdt_entry.Selector);
        vmx_write(GUEST_TR_LIMIT, vmx_gdt_entry.Limit);
        vmx_write(GUEST_TR_AR_BYTES, vmx_gdt_entry.AccessRights);
        vmx_write(GUEST_TR_BASE, vmx_gdt_entry.Base);

        convert_gdt_entry(registers.Gdtr.Base, registers.Ldtr, &vmx_gdt_entry);
        vmx_write(GUEST_LDTR_SELECTOR, vmx_gdt_entry.Selector);
        vmx_write(GUEST_LDTR_LIMIT, vmx_gdt_entry.Limit);
        vmx_write(GUEST_LDTR_AR_BYTES, vmx_gdt_entry.AccessRights);
        vmx_write(GUEST_LDTR_BASE, vmx_gdt_entry.Base);

        vmx_write(GUEST_GDTR_BASE, (uintptr_t)registers.Gdtr.Base);
        vmx_write(GUEST_GDTR_LIMIT, registers.Gdtr.Limit);

        vmx_write(GUEST_IDTR_BASE, (uintptr_t)registers.Idtr.Base);
        vmx_write(GUEST_IDTR_LIMIT, registers.Idtr.Limit);

        vmx_write(CR0_READ_SHADOW, registers.Cr0);
        vmx_write(GUEST_CR0, registers.Cr0);

        vmx_write(GUEST_CR3, registers.Cr3);

        vmx_write(GUEST_CR4, registers.Cr4);
        vmx_write(CR4_READ_SHADOW, registers.Cr4 & ~0x2000);

        vmx_write(GUEST_IA32_DEBUGCTL, registers.DebugControl);
        vmx_write(GUEST_DR7, registers.KernelDr7);

        //vmx_write(GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
        //vmx_write(GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
        //vmx_write(GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));

        vmx_write(GUEST_RSP, ctx->Rsp);
        vmx_write(GUEST_RIP, ctx->Rip);
        vmx_write(GUEST_RFLAGS, ctx->EFlags);
        //vmx_write(GUEST_ACTIVITY_STATE, 0);
        //vmx_write(GUEST_INTERRUPTIBILITY_INFO, 0);
        //vmx_write(GUEST_PENDING_DBG_EXCEPTIONS, 0);

        vmx_write(HOST_CS_SELECTOR, ctx->SegCs & ~RPL_MASK);
        vmx_write(HOST_SS_SELECTOR, ctx->SegSs & ~RPL_MASK);
        vmx_write(HOST_DS_SELECTOR, ctx->SegDs & ~RPL_MASK);
        vmx_write(HOST_ES_SELECTOR, ctx->SegEs & ~RPL_MASK);
        vmx_write(HOST_FS_SELECTOR, ctx->SegFs & ~RPL_MASK);
        vmx_write(HOST_GS_SELECTOR, ctx->SegGs & ~RPL_MASK);
        vmx_write(HOST_TR_SELECTOR, registers.Tr & ~RPL_MASK);


        convert_gdt_entry(registers.Gdtr.Base, ctx->SegFs, &vmx_gdt_entry);
        vmx_write(HOST_FS_BASE, vmx_gdt_entry.Base);

        vmx_write(HOST_GS_BASE, registers.MsrGsBase);

        convert_gdt_entry(registers.Gdtr.Base, registers.Tr, &vmx_gdt_entry);
        vmx_write(HOST_TR_BASE, vmx_gdt_entry.Base);

        vmx_write(HOST_GDTR_BASE, (uintptr_t)registers.Gdtr.Base);
        vmx_write(HOST_IDTR_BASE, (uintptr_t)registers.Idtr.Base);

        vmx_write(HOST_CR0, registers.Cr0);
        vmx_write(HOST_CR3, registers.Cr3);
        vmx_write(HOST_CR4, registers.Cr4);


        //vmx_write(HOST_IA32_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));
        //vmx_write(HOST_IA32_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
        //vmx_write(HOST_IA32_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));

        C_ASSERT((KERNEL_STACK_SIZE - sizeof(CONTEXT)) % 16 == 0);
        vmx_write(HOST_RSP, (uintptr_t)vcpu->host_stack + KERNEL_STACK_SIZE - sizeof(CONTEXT));
        vmx_write(HOST_RIP, (uintptr_t)vmexit_handler);

        DbgPrint("vmcs setup completed on core %lu\n", KeGetCurrentProcessorNumber());
        return true;
    }

    vcpu_data* allocate_vmx_regions()
    {
        vcpu_data* cpu_data = reinterpret_cast<vcpu_data*>(
            ExAllocatePool(NonPagedPool, sizeof(vcpu_data)));

        if (!cpu_data)
        {
            DbgPrint("failed to allocate vcpu data\n");
            return nullptr;
        }

        RtlZeroMemory(cpu_data, sizeof(vcpu_data));

        cpu_data->vmxon_region = reinterpret_cast<vmx_region*>(
            memory::MmAllocateIndependentPages(PAGE_SIZE));

        if (!cpu_data->vmxon_region)
        {
            DbgPrint("failed to allocate vmxon region\n");
            ExFreePool(cpu_data);
            return nullptr;
        }

        cpu_data->vmcs_region = reinterpret_cast<vmx_region*>(
            memory::MmAllocateIndependentPages(PAGE_SIZE));

        if (!cpu_data->vmcs_region)
        {
            DbgPrint("failed to allocate vmcs region\n");
            memory::MmFreeIndependentPages(cpu_data->vmxon_region, PAGE_SIZE);
            ExFreePool(cpu_data);
            return nullptr;
        }

        cpu_data->host_stack = ExAllocatePool(NonPagedPool, KERNEL_STACK_SIZE);

        if (!cpu_data->host_stack)
        {
            DbgPrint("failed to allocate host stack\n");
            memory::MmFreeIndependentPages(cpu_data->vmxon_region, PAGE_SIZE);
            memory::MmFreeIndependentPages(cpu_data->vmcs_region, PAGE_SIZE);
            ExFreePool(cpu_data);
            return nullptr;
        }

        cpu_data->msr_bitmap = ExAllocatePool(NonPagedPool, PAGE_SIZE);

        if (!cpu_data->msr_bitmap)
        {
            DbgPrint("failed to allocate msr bitmap\n");
            ExFreePool(cpu_data->host_stack);
            memory::MmFreeIndependentPages(cpu_data->vmxon_region, PAGE_SIZE);
            memory::MmFreeIndependentPages(cpu_data->vmcs_region, PAGE_SIZE);
            ExFreePool(cpu_data);
            return nullptr;
        }

        RtlZeroMemory(cpu_data->vmxon_region, PAGE_SIZE);
        RtlZeroMemory(cpu_data->vmcs_region, PAGE_SIZE);
        RtlZeroMemory(cpu_data->host_stack, KERNEL_STACK_SIZE);
        RtlZeroMemory(cpu_data->msr_bitmap, PAGE_SIZE);

        cpu_data->vmxon_region_physical = MmGetPhysicalAddress(cpu_data->vmxon_region);
        cpu_data->vmcs_region_physical = MmGetPhysicalAddress(cpu_data->vmcs_region);
        cpu_data->physical_msr_bitmap = MmGetPhysicalAddress(cpu_data->msr_bitmap);

        unsigned long rev_id = get_vmx_revision_id();
        cpu_data->vmxon_region->revision_id = rev_id;
        cpu_data->vmcs_region->revision_id = rev_id;

        return cpu_data;
    }

    bool execute_vmclear(vcpu_data* cpu_data)
    {
        int status = __vmx_vmclear(reinterpret_cast<std::uint64_t*>(&cpu_data->vmcs_region_physical.QuadPart));

        if (status != 0)
        {
            DbgPrint("vmclear failed with status %d\n", status);
            return false;
        }

        return true;
    }

    bool execute_vmxon(vcpu_data* cpu_data)
    {
        ULONG64 cr0 = __readcr0();
        ULONG64 cr4 = __readcr4();

        ULONG64 cr0_fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
        ULONG64 cr0_fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
        ULONG64 cr4_fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
        ULONG64 cr4_fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

        cr0 &= cr0_fixed1;
        cr0 |= cr0_fixed0;
        cr4 &= cr4_fixed1;
        cr4 |= cr4_fixed0;

        __writecr0(cr0);
        __writecr4(cr4);

        unsigned char status = __vmx_on(
            (unsigned long long*) & cpu_data->vmxon_region_physical.QuadPart);

        if (status != 0)
        {
            DbgPrint("vmxon failed with status %d\n", status);
            return false;
        }

        cpu_data->vmx_enabled = true;
        return true;
    }

    bool execute_vmptrld(vcpu_data* cpu_data)
    {
        int status = __vmx_vmptrld(reinterpret_cast<std::uint64_t*>(&cpu_data->vmcs_region_physical.QuadPart));

        if (status != 0)
        {
            DbgPrint("vmptrld failed with status %d\n", status);
            __vmx_off();
            return false;
        }

        return true;
    }

    unsigned long long initialize_vmx_on_core(unsigned long long argument)
    {
        unsigned long core_id = KeGetCurrentProcessorNumber();


        vcpu_data* cpu_data = g_cpu_data[core_id];

        if (cpu_data == nullptr)
        {
            if (!vmx::enable_vmx())
            {
                DbgPrint("failed to enable vmx on core %lu\n", core_id);
                return 0;
            }

            cpu_data = vmx::allocate_vmx_regions();
            if (!cpu_data)
            {
                DbgPrint("failed to allocate vmx regions on core %lu\n", core_id);
                return 0;
            }

            cpu_data->vmx_state = VMX_STATE_OFF;

            if (!vmx::execute_vmxon(cpu_data))
            {
                DbgPrint("failed to execute vmxon on core %lu\n", core_id);
                return 0;
            }

            if (!vmx::execute_vmclear(cpu_data))
            {
                DbgPrint("failed to execute vmclear on core %lu\n", core_id);
                return 0;
            }

            if (!vmx::execute_vmptrld(cpu_data))
            {
                DbgPrint("failed to execute vmptrld on core %lu\n", core_id);
                return 0;
            }

            g_cpu_data[core_id] = cpu_data;
        }

        cpu_data->ctx_frame.ContextFlags = CONTEXT_ALL;
        RtlCaptureContext(&cpu_data->ctx_frame);

        if (cpu_data->vmx_state == VMX_STATE_OFF)
        {
            capture_registers(&cpu_data->special_registers);

            if (!vmx::setup_vmcs(cpu_data, &cpu_data->ctx_frame))
            {
                DbgPrint("failed to setup vmcs on core %lu\n", core_id);
                return 0;
            }

            cpu_data->vmx_state = VMX_STATE_TRANSITION;

            int status = __vmx_vmlaunch();

            cpu_data->vmx_state = VMX_STATE_OFF;

            ULONG64 error = 0;
            __vmx_vmread(VM_INSTRUCTION_ERROR, &error);
            DbgPrint("vmlaunch failed on core %lu with error 0x%llx\n", core_id, error);

            return 0;
        }
        else if (cpu_data->vmx_state == VMX_STATE_TRANSITION)
        {
            cpu_data->vmx_state = VMX_STATE_ON;

            DbgPrint("vmlaunch succeeded on core %lu\n", core_id);

            vm_restore_context(&cpu_data->ctx_frame);
        }
        return 0;
    }

    bool virtualise_all_cores()
    {
        if (!vmx::is_vmx_supported())
        {
            DbgPrint("vmx not supported\n");
            return false;
        }

        g_core_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        DbgPrint("initializing vmx on %lu cores\n", g_core_count);

        KeIpiGenericCall(initialize_vmx_on_core, 0);

        ULONG virtualized_cores = 0;
        for (ULONG i = 0; i < g_core_count; i++)
        {
            if (g_cpu_data[i] && g_cpu_data[i]->vmx_state == VMX_STATE_ON)
            {
                virtualized_cores++;
            }
        }

        if (virtualized_cores == g_core_count)
        {
            DbgPrint("successfully virtualized all %lu cores\n", g_core_count);
            return true;
        }
        else
        {
            DbgPrint("virtualized %lu out of %lu cores\n", virtualized_cores, g_core_count);
            return false;
        }
    }

    unsigned long long turn_off_vmx_on_core(unsigned long long argument)
    {
        unsigned long core_id = KeGetCurrentProcessorNumber();

        vcpu_data* cpu_data = g_cpu_data[core_id];
        if (cpu_data && cpu_data->vmx_enabled)
        {
            __vmx_off();
            cpu_data->vmx_enabled = false;
            cpu_data->vmx_state = VMX_STATE_OFF;
            DbgPrint("disabled vmx on core %lu\n", core_id);
        }

        return 0;
    }

    bool devirtualise_all_cores()
    {
        DbgPrint("disabling vmx on all cores\n");
        KeIpiGenericCall(turn_off_vmx_on_core, 0);

        for (ULONG i = 0; i < g_core_count; i++)
        {
            if (g_cpu_data[i])
            {
                if (g_cpu_data[i]->msr_bitmap)
                    ExFreePool(g_cpu_data[i]->msr_bitmap);
                if (g_cpu_data[i]->host_stack)
                    ExFreePool(g_cpu_data[i]->host_stack);
                if (g_cpu_data[i]->vmcs_region)
                    memory::MmFreeIndependentPages(g_cpu_data[i]->vmcs_region, PAGE_SIZE);
                if (g_cpu_data[i]->vmxon_region)
                    memory::MmFreeIndependentPages(g_cpu_data[i]->vmxon_region, PAGE_SIZE);

                ExFreePool(g_cpu_data[i]);
                g_cpu_data[i] = nullptr;
            }
        }

        return true;
    }
}