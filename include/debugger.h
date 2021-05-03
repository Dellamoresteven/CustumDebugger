#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>

#include "breakpoint.h"

namespace minidbg {
    class debugger {
    public:
        debugger (std::string prog_name, pid_t pid)
            : m_prog_name{std::move(prog_name)}, m_pid{pid} {
                set_program_base_address(m_pid);
                std::cout << "Debugger hooked to process " << pid << " on base address " << std::hex << m_base_addr << std::endl;
            }

        void run();
        void set_breakpoint_at_address(std::intptr_t addr);
        void dump_registers();
        uint64_t read_memory(uint64_t address);
        void write_memory(uint64_t address, uint64_t value);
        uint64_t get_pc();
        void set_pc(uint64_t pc);
        void step_over_breakpoint();
        void wait_for_signal();
        void set_program_base_address(pid_t pid);

    private:
        void handle_command(const std::string& line);
        void continue_execution();

        std::string m_prog_name;
        intptr_t m_base_addr;
        pid_t m_pid;
        std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
    };
}

#endif
