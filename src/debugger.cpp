#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>

#include "linenoise.h"
#include "debugger.h"
#include "registers.h"

using std::string;
using std::vector;
using std::cerr;
using std::cout;
using std::endl;
using namespace minidbg;

vector<string> split(const string &s, const char delimiter);
bool is_prefix(const string &s, const string &of);
std::string exec(const char* cmd);

void debugger::run() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    char * line = nullptr;
    while((line = linenoise("minidbg > ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::handle_command(const string& line) {
    auto args = split(line, ' ');
    auto command = args[0];

    if(is_prefix(command, "continue")) {
        continue_execution();
    } else if(is_prefix(command, "breakpoint")) {
        string addr {args[1], 2};
        set_breakpoint_at_address(std::stol(addr,0,16));
    } else if(is_prefix(command, "register")) {
        if (is_prefix(args[1], "dump")) {
            dump_registers();
        }
        else if (is_prefix(args[1], "read")) {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2}; //assume 0xVAL
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    } else if(is_prefix(command, "memory")) {
        std::string addr{args[2], 2};
        if(is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        } else if(is_prefix(args[1], "write")) {
            std::string val{args[3], 2};
            write_memory(std::stol(addr,0,16), std::stol(val, 0, 16));
        }
    } else if(is_prefix(command, "stepi")) {
        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_pc(get_pc());
        print_source(line_entry->file->path, line_entry->line);
    } else if(is_prefix(command, "step")) {
        step_in();
    } else if(is_prefix(command, "next")) {
        step_over();
    } else if(is_prefix(command, "finish")) {
        step_out();
    } else {
        cerr << "Unknown Command\n";
    }
}

void debugger::continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void debugger::dump_registers() {
    for(const auto &rd : g_register_descriptors) {
        cout << rd.name << " 0x" << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << endl;
    }
}

uint64_t debugger::read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}

void debugger::step_over_breakpoint() {
    if(m_breakpoints.count(get_pc())) {
        auto &bp = m_breakpoints[get_pc()];
        if(bp.is_enabled()) {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    auto siginfo = get_signal_info();

    switch(siginfo.si_signo) {
        case SIGTRAP:
            handle_sigtrap(siginfo);
            break;
        case SIGSEGV:
            std::cout << "SEGFAULT: " << siginfo.si_code << std::endl;
            break;
        default:
            std::cout << "Got Signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

void debugger::set_program_base_address(pid_t pid) {
    string s = "cat /proc/" + std::to_string(pid) + "/maps";
    auto catRet = exec(s.c_str());
    std::string baseAddrStr = catRet.substr(0 , catRet.find("-" , 0));
    m_base_addr = std::stol(baseAddrStr,0,16);
}

dwarf::die debugger::get_function_from_pc(uint64_t pc) {
    for(auto &cu : m_dwarf.compilation_units()) {
        if(die_pc_range(cu.root()).contains(pc)) {
            for(const auto &die : cu.root()) {
                if(die.tag == dwarf::DW_TAG::subprogram) {
                    if(die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
    for(auto &cu : m_dwarf.compilation_units()) {
        if(die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if(it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            } else {
                return it;
            }
        }
    }
    throw std::out_of_range{"Cannot find line entry 1"};
}

uint64_t debugger::offset_load_address(uint64_t addr) {
    return addr-m_base_addr;
}

void debugger::print_source(const std::string &file_name, unsigned line, unsigned n_lines_context) {
    std::ifstream file{file_name};

    auto start_line = line <= n_lines_context ? 1 : n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context : 0) + 1;

    char c{};
    auto current_line = 1u;

    while(current_line != start_line && file.get(c)) {
        if(c == '\n') {
            ++current_line;
        }
    }

    std::cout << (current_line==line ? "> " : " ");

    while(current_line <= end_line && file.get(c)) {
        std::cout << c;
        if(c == '\n') {
            ++current_line;
            std::cout << (current_line==line ? "> " : " ");
        }
    }

    std::cout << std::endl;
}

siginfo_t debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

void debugger::handle_sigtrap(siginfo_t info) {
    switch(info.si_code) {
        case SI_KERNEL:
        case TRAP_BRKPT:
            {
                set_pc(get_pc()-1);
                std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
                auto offset_pc = offset_load_address(get_pc());

                auto line_entry = get_line_entry_from_pc(offset_pc);
                print_source(line_entry->file->path, line_entry->line);
                return;
            }
        case TRAP_TRACE:
            return;
        default:
            std::cout << "Unkown SIGTRAP code " << info.si_code << std::endl;
            return;
    }
}

void debugger::single_step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check() {
    if(m_breakpoints.count(get_pc())) {
        step_over_breakpoint();
    } else {
        single_step_instruction();
    }
}

void debugger::step_out() {
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer+8);

    bool should_remove_breakpoint = false;
    if(!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if(should_remove_breakpoint) {
        remove_breakpoint(return_address);
    }
}

void debugger::remove_breakpoint(std::intptr_t addr) {
    if(m_breakpoints.at(addr).is_enabled()) {
        m_breakpoints.at(addr).disable();
    }
    m_breakpoints.erase(addr);
}

void debugger::step_in() {
    auto line = get_line_entry_from_pc(get_offset_pc())->line;

    while(get_line_entry_from_pc(get_offset_pc())->line == line) {
        single_step_instruction_with_breakpoint_check();
    }

    auto line_entry = get_line_entry_from_pc(get_offset_pc());
    print_source(line_entry->file->path, line_entry->line);
}

uint64_t debugger::get_offset_pc() {
    return offset_load_address(get_pc());
}

uint64_t debugger::offset_dwarf_address(uint64_t addr) {
    return addr + m_base_addr;
}

void debugger::step_over() {
    auto func = get_function_from_pc(get_offset_pc());
    auto func_entry = at_low_pc(func);
    auto func_end = at_high_pc(func);

    auto line = get_line_entry_from_pc(func_entry);
    auto start_line = get_line_entry_from_pc(get_offset_pc());

    std::vector<std::intptr_t> to_delete{};

    while(line->address < func_end) {
        auto load_address = offset_dwarf_address(line->address);
        if(line->address != start_line->address && !m_breakpoints.count(load_address)) {
            set_breakpoint_at_address(load_address);
            to_delete.push_back(load_address);
        }
        ++line;
    }

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer+0x8);
    if(!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    continue_execution();

    for(auto addr : to_delete) {
        remove_breakpoint(addr);
    }
}

vector<string> split(const string &s, const char delimiter) {
    vector<string> ret;
    std::stringstream ss{s};
    string item;
    while(std::getline(ss,item,delimiter)) {
        ret.push_back(item);
    }
    return ret;
}


bool is_prefix(const string &s, const string &of) {
    if(s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

