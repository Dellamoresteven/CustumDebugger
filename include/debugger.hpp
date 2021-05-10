#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>
#include <fcntl.h>
#include <inttypes.h>

#include "breakpoint.h"
#include "elf/elf++.hh"
#include "dwarf/dwarf++.hh"

namespace minidbg {
    enum class symbol_type {
        notype,
        object,
        func,
        section,
        file,
    };

    std::string to_string(symbol_type st) {
        switch(st) {
            case symbol_type::notype: return "notype";
            case symbol_type::object: return "object";
            case symbol_type::func: return "func";
            case symbol_type::section: return "section";
            case symbol_type::file: return "file";
        }
    }

    struct symbol {
        symbol_type type;
        std::string name;
        std::uintptr_t addr;
    };

    symbol_type to_symbol_type(elf::stt sym) {
        switch (sym) {
            case elf::stt::notype: return symbol_type::notype;
            case elf::stt::object: return symbol_type::object;
            case elf::stt::func: return symbol_type::func;
            case elf::stt::section: return symbol_type::section;
            case elf::stt::file: return symbol_type::file;
            default: return symbol_type::notype;
        }
    }

    class debugger {
    public:
        debugger (std::string prog_name, pid_t pid)
            : m_prog_name{std::move(prog_name)}, m_pid{pid} {
                auto fd = open(m_prog_name.c_str(), O_RDONLY);

                m_elf = elf::elf{elf::create_mmap_loader(fd)};
                m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};

                set_program_base_address(m_pid);
                std::cout << "Debugger hooked to process " << pid << " on base address " << std::hex << m_base_addr << std::endl;
            }

        void run();
        void set_breakpoint_at_address(std::intptr_t addr);
        void dump_registers();
        uint64_t read_memory(uint64_t address);
        void write_memory(uint64_t address, uint64_t value);
        void step_over_breakpoint();
        void wait_for_signal();
        void set_program_base_address(pid_t pid);
        uint64_t offset_load_address(uint64_t addr);
        void print_source(const std::string &file_name, unsigned line, unsigned n_lines_context=2);
        siginfo_t get_signal_info();
        void handle_sigtrap(siginfo_t info);
        void single_step_instruction();
        void single_step_instruction_with_breakpoint_check();
        void remove_breakpoint(std::intptr_t addr);

        /* Stepping functions */
        void step_in();
        void step_over();
        void step_out();

        /* Program Counter (PC) setters/getters */
        uint64_t get_pc();
        void set_pc(uint64_t pc);
        uint64_t get_offset_pc();
        dwarf::die get_function_from_pc(uint64_t pc);
        dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);

        uint64_t offset_dwarf_address(uint64_t addr);
        void set_breakpoint_at_function(const std::string &name);
        void set_breakpoint_at_source_line(const std::string &file, unsigned line);
        std::vector<symbol> lookup_symbol(const std::string &name);
        void print_backtrace();
        void read_variables();
        std::vector<uint8_t> hexdump(uint64_t address, unsigned num);

        void print_prompt();
        void print_hexdump(std::vector<uint8_t> bytes, std::string print_format, uint64_t address, unsigned length);

    private:
        void handle_command(const std::string& line);
        void continue_execution();

        std::string m_prog_name;
        uint64_t m_base_addr;
        pid_t m_pid;
        dwarf::dwarf m_dwarf;
        elf::elf m_elf;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
    };
}

#endif
