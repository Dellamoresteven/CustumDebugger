#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/personality.h>
#include <sys/ioctl.h>
#include <cmath>
#include <cstddef>

#include "linenoise.h"

#include "debugger.hpp"
#include "registers.h"
#include "colors.h"

using std::string;
using std::vector;
using std::cerr;
using std::cout;
using std::endl;
using namespace minidbg;

vector<string> split(const string &s, const char delimiter);
bool is_prefix(const string &s, const string &of);
bool is_suffix(const string &s, const std::string &of);
std::string exec(const char* cmd);

class ptrace_expr_context : public dwarf::expr_context {
    public:
   ptrace_expr_context (pid_t pid, uint64_t load_address) :
       m_pid{pid}, m_base_address(load_address) {};

   dwarf::taddr reg(unsigned regnum) override {
       return get_register_value_from_dwarf_register(m_pid, regnum);
   }

   dwarf::taddr pc() override {
       struct user_regs_struct regs;
       ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
       return regs.rip - m_base_address;
   }

   dwarf::taddr deref_size(dwarf::taddr address, unsigned size) override {
       return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
   }

    private:
    pid_t m_pid;
    uint64_t m_base_address;
};

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
    if(args.size() == 0) return;
    auto command = args[0];


    if(is_prefix(command, "continue")) {
        continue_execution();
    } else if(is_prefix(command, "breakpoint")) {
        if(args[1][0] == '0' && args[1][1] == 'x') {
            string addr {args[1], 2};
            set_breakpoint_at_address(std::stol(addr,0,16));
        } else if(args[1].find(':') != std::string::npos) {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        } else {
            set_breakpoint_at_function(args[1]);
        }
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
    } else if(is_prefix(command, "step")) {
        step_in();
    } else if(is_prefix(command, "stepi")) {
        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_pc(get_pc());
        print_source(line_entry->file->path, line_entry->line);
    } else if(is_prefix(command, "next")) {
        step_over();
    } else if(is_prefix(command, "finish")) {
        step_out();
    } else if(is_prefix(command, "symbol")) {
        auto syms = lookup_symbol(args[1]);
        std::cout << syms.size() << endl;
        for(auto &&s : syms) {
            std::cout << s.name << ' ' << to_string(s.type) << " 0x" << std::hex << s.addr << std::endl;
        }
    } else if(is_prefix(command, "backtrace")) {
        print_backtrace();
    } else if(is_prefix(command, "run")) {
        set_breakpoint_at_function("main");
        continue_execution();
    } else if(is_prefix(command, "variables")) {
        read_variables();
    } else if(is_prefix(command, "hexdump")) {
        if(args.size() < 2) {
            std::cout << "Usage hexdump <addr> <length>" << std::endl;
            std::cout << "Usage hexdump <length>" << std::endl;
        } else if(args.size() == 3){
            std::string addr{args[1],2};
            std::string num{args[2]};
            auto byte_dump = hexdump(std::stol(addr,0,16), std::stoi(num,0,10));
            //for(int i = 0; i < byte_dump.size(); i++) {
                //if(i != 0 && i % 16 == 0) std::cout << endl;
                //std::cout << std::setw(2) << std::setfill('0') << int(byte_dump.at(i)) << " ";
            //}
        } else {
            std::stringstream stream;
            stream << std::hex << get_register_value(m_pid, reg::rsp);
            std::string addr(stream.str());
            std::string num{args[1]};
            auto byte_dump = hexdump(std::stol(addr,0,16), std::stoi(num,0,10));
        }
        cout << endl;
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
    //std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void debugger::dump_registers() {
    for(const auto &rd : g_register_descriptors) {
        cout << reg_color << "$" << rd.name << def << std::setfill(' ') << std::setw(14-rd.name.length()) << ": 0x" << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, rd.r) << endl;
    }
    cout << def;
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
                throw std::out_of_range{"Cannot find line entry 2"};
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

    auto start_line = line <= n_lines_context ? 1 : line-n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context : 0) + 1;

    char c{};
    auto current_line = 1u;

    while(current_line != start_line && file.get(c)) {
        if(c == '\n') {
            ++current_line;
        }
    }

    std::cout << std::dec << current_line << std::setw(5-current_line/10) << std::setfill(' ');

    while(current_line <= end_line && file.get(c)) {
        if(current_line==line) {
            std::cout << green << c;
        } else {
            std::cout << def << c;
        }
        if(c == '\n') {
            ++current_line;
            if(current_line == line) {
                std::cout << green << std::dec << current_line << std::setw(7 - current_line/10) << std::setfill(' ') << "→";
            } else {
                std::cout << def << std::dec << current_line << std::setw(5 - current_line/10) << std::setfill(' ') << "";
            }
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
                //std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;

                //auto offset_pc = offset_load_address(get_pc());
                //auto line_entry = get_line_entry_from_pc(offset_pc);
                //print_source(line_entry->file->path, line_entry->line);
                print_prompt();
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

void debugger::set_breakpoint_at_function(const std::string &name) {
    for(const auto &cu : m_dwarf.compilation_units()) {
        for(const auto &die : cu.root()) {
            if(die.has(dwarf::DW_AT::name) && at_name(die) == name) {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry;
                set_breakpoint_at_address(offset_dwarf_address(entry->address));
            }
        }
    }
}

void debugger::set_breakpoint_at_source_line(const std::string &file, unsigned line) {
    for(const auto &cu : m_dwarf.compilation_units()) {
        if(is_suffix(file, at_name(cu.root()))) {
            const auto &lt = cu.get_line_table();
            for(const auto &entry : lt) {
                if(entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(offset_dwarf_address(entry.address));
                    return;
                }
            }
        }
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

std::vector<symbol> debugger::lookup_symbol(const std::string &name) {
    std::vector<symbol> syms;
    for(auto &sec : m_elf.sections()) {
        if(sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
            continue;
        for(auto sym : sec.as_symtab()) {
            if(sym.get_name() == name) {
                auto &d = sym.get_data();
                syms.push_back(symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
            }
        }
    }
    return syms;
}

void debugger::print_backtrace() {
    auto output_frame = [frame_number = 0](auto && func) mutable {
        std::cout << "frame #" << frame_number++ << ": 0x" << dwarf::at_low_pc(func) << " " << dwarf::at_name(func) << std::endl;
    };

    auto current_func = get_function_from_pc(offset_load_address(get_pc()));
    output_frame(current_func);

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_addr = read_memory(frame_pointer + 8);

    while(dwarf::at_name(current_func) != "main") {
        current_func = get_function_from_pc(offset_load_address(return_addr));
        output_frame(current_func);
        frame_pointer = read_memory(frame_pointer);
        return_addr = read_memory(frame_pointer+8);
    }
}

template class std::initializer_list<dwarf::taddr>;
void debugger::read_variables() {
    using namespace dwarf;

    auto func = get_function_from_pc(get_offset_pc());

    for (const auto& die : func) {
        if (die.tag == DW_TAG::variable) {
            auto loc_val = die[DW_AT::location];

            //only supports exprlocs for now
            if (loc_val.get_type() == value::type::exprloc) {
                ptrace_expr_context context {m_pid, m_base_addr};
                auto result = loc_val.as_exprloc().evaluate(&context);

                switch (result.location_type) {
                case expr_result::type::address:
                {
                    auto offset_addr = result.value;
                    auto value = read_memory(offset_addr);
                    std::cout << at_name(die) << " (0x" << std::hex << offset_addr << ") = " << value << std::endl;
                    break;
                }

                case expr_result::type::reg:
                {
                    auto value = get_register_value_from_dwarf_register(m_pid, result.value);
                    std::cout << at_name(die) << " (reg " << result.value << ") = " << value << std::endl;
                    break;
                }

                default:
                    throw std::runtime_error{"Unhandled variable location"};
                }
            }
            else {
                throw std::runtime_error{"Unhandled variable location"};
            }
        }
    }
}

//auto debugger::test_read(uint64_t) {

//}

void debugger::print_prompt() {
    struct winsize size;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
    for(int i = 0; i < size.ws_row; i++) {
        cout << endl;
    }
    auto splitter = [&](string label) {
        cout << line_color;
        for(int i = 0; i < size.ws_col-label.size()-2-14; i++) {
            cout << "─";
        }
        cout << color_breaker << " " << label << line_color << " ──────────────\n";
        cout << def;
    };
    splitter("registers");
    dump_registers();
    splitter("source");
    auto offset_pc = offset_load_address(get_pc());
    auto line_entry = get_line_entry_from_pc(offset_pc);
    print_source(line_entry->file->path, line_entry->line, 5);
    splitter("stack");
    auto rbp = get_register_value(m_pid, reg::rbp);
    auto rsp = get_register_value(m_pid, reg::rsp);
    auto stack_size = rbp-rsp;
    for(int i = 0; i < stack_size+8; i+=8) {
        cout << std::hex << green << rsp+i << def << " : " << read_memory(rsp+i) << "\n";
    }
    splitter("trace");
    print_backtrace();
    cout << endl;
}

vector<uint8_t> debugger::hexdump(uint64_t address, unsigned num) {
    vector<uint8_t> mem_dump;
    int curr_num = 0;
    while(curr_num < num) {
        uint64_t mem = read_memory(address+curr_num);
        mem_dump.push_back(mem >> 8*0);
        mem_dump.push_back(mem >> 8*1);
        mem_dump.push_back(mem >> 8*2);
        mem_dump.push_back(mem >> 8*3);
        mem_dump.push_back(mem >> 8*4);
        mem_dump.push_back(mem >> 8*5);
        mem_dump.push_back(mem >> 8*6);
        mem_dump.push_back(mem >> 8*7);
        curr_num += 8;
    }
    return mem_dump;
}

bool is_prefix(const string &s, const string &of) {
    if(s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

bool is_suffix(const string &s, const std::string &of) {
    if(s.size() > of.size()) return false;
    auto diff = of.size()-s.size();
    return std::equal(s.begin(), s.end(), of.begin() + diff);
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

int main(int argc, char* argv[]) {
    if(argc < 2) {
        cerr << "Program name not specified";
    }
    auto program = argv[1];
    auto pid = fork();
    if(pid == 0) {
        // child
        personality(ADDR_NO_RANDOMIZE);
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            std::cerr << "Error in ptrace\n";
            exit(1);
        }
        execl(program, program, nullptr);
    } else if(pid >= 1) {
        // parent
        debugger dbg{program, pid};
        dbg.run();
    }
    return 0;
}
