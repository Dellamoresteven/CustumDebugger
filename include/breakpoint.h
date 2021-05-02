#ifndef MINIDBG_BREAKPOINT_HPP
#define MINIDBG_BREAKPOINT_HPP

#include <cstdint>
#include <sys/ptrace.h>
#include <unistd.h>

namespace minidbg {
    class breakpoint {
    public:
        // Default contor
        breakpoint() = default;

        /**
         * breakpoint Ctor
         *
         * @param pid - The pid of the process we are debugging
         * @param addr - The address to set the break point
         */
        breakpoint(pid_t pid, std::intptr_t addr)
            : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{}
        {}

        /**
         * Enables the breakpoint
         */
        void enable();

        /**
         * Disable the breakpoint
         */
        void disable();

        /**
         * Checks if the breakpoint is enabled
         * 
         * @return bool - true - breakpoint enabled
         *                false - breakpoint disabled
         */
        auto is_enabled() const->bool {return m_enabled;}
        
        /**
         * Gets the breakpoint address
         *
         * @return intptr_t - The address of the breakpoint
         */
        auto get_address() const->std::intptr_t {return m_addr;}

    private:
        /* PID where breakpoint is located */
        pid_t m_pid;
        /* Address of where breakpoint is located */
        std::intptr_t m_addr;
        /* If the breakpoint is enabled or disabled */
        bool m_enabled;
        /* Saved data that WAS in this address before we wrote over it */
        uint8_t m_saved_data;
    };
}

#endif
