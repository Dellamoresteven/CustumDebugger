#ifndef MINIDBG_REGISTERS_HPP
#define MINIDBG_REGISTERS_HPP

#include <sys/user.h>
#include <algorithm>

namespace minidbg {
    /**
     * Holds all the register values on the x86-64 chip
     */
    enum class reg {
        rax, rbx, rcx, rdx,
        rdi, rsi, rbp, rsp,
        r8,  r9,  r10, r11,
        r12, r13, r14, r15,
        rip, rflags,    cs,
        orig_rax, fs_base,
        gs_base,
        fs, gs, ss, ds, es
    };

    /* Number of registers */
    constexpr std::size_t n_registers = 27;

    /* A struct to hold all registers descriptions */
    struct reg_descriptor {
        reg r;
        int dwarf_r;
        std::string name;
    };

    /* An array of all the register descriptor objects */
    static const std::array<reg_descriptor, n_registers> g_register_descriptors {{
            { reg::r15, 15, "r15" },
            { reg::r14, 14, "r14" },
            { reg::r13, 13, "r13" },
            { reg::r12, 12, "r12" },
            { reg::rbp, 6, "rbp" },
            { reg::rbx, 3, "rbx" },
            { reg::r11, 11, "r11" },
            { reg::r10, 10, "r10" },
            { reg::r9, 9, "r9" },
            { reg::r8, 8, "r8" },
            { reg::rax, 0, "rax" },
            { reg::rcx, 2, "rcx" },
            { reg::rdx, 1, "rdx" },
            { reg::rsi, 4, "rsi" },
            { reg::rdi, 5, "rdi" },
            { reg::orig_rax, -1, "orig_rax" },
            { reg::rip, -1, "rip" },
            { reg::cs, 51, "cs" },
            { reg::rflags, 49, "eflags" },
            { reg::rsp, 7, "rsp" },
            { reg::ss, 52, "ss" },
            { reg::fs_base, 58, "fs_base" },
            { reg::gs_base, 59, "gs_base" },
            { reg::ds, 53, "ds" },
            { reg::es, 50, "es" },
            { reg::fs, 54, "fs" },
            { reg::gs, 55, "gs" },
    }};

    /**
     * Returns the value of a register
     *
     * @param pid - pid of the process being asked about
     * @param r   - The register being asked for
     *
     * @return the value the register holds
     *
     * @example get_register_value(1234, reg::rsp)
     */
    uint64_t get_register_value(pid_t pid, reg r) {
        user_regs_struct regs; // A system created struct that holds all the registers
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs); // A call to PTRACE to GETREGS
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto&& rd) { return rd.r == r; }); // Gets the correct register value if it's there
        return *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors))); // unsafe cast to a uint64_t
    }

    /**
     * Returns a register from the dwarf registers 
     *
     * @param pid - the PID of the process being asked about
     * @param regnum - The number of the register being asked for
     *
     * @return the value of the register being asked for
     */
    uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned regnum) {
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [regnum](auto&& rd){return rd.dwarf_r == regnum;});
        if(it == end(g_register_descriptors)) {
            throw std::out_of_range("Unknown dwarf register");
        }
        return get_register_value(pid, it->r);
    }

    /**
     * Sets the value of a register
     *
     * @param pid - the PID of the process we are changing
     * @param r   - The register i.e reg::rsp
     * @param value - The value to change the register to
     */
    void set_register_value(pid_t pid, reg r, uint64_t value) {
        user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors), [r](auto &&rd) {return rd.r == r;});
        *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(g_register_descriptors))) = value;
        ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    }

    /**
     * Gets the string name of the register
     *
     * @param r - The register i.e reg::rsp
     *
     * @return The string name of the register
     */
    std::string get_register_name(reg r) {
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                               [r](auto&& rd) { return rd.r == r; });
        return it->name;
    }

    /**
     * Gets a register by its string name
     *
     * @param name - The string name of the register. i.e "rsp"
     *
     * @return The reg type of the register
     */
    reg get_register_from_name(const std::string& name) {
        auto it = std::find_if(begin(g_register_descriptors), end(g_register_descriptors),
                               [name](auto&& rd) { return rd.name == name; });
        return it->r;
    }
}

#endif
