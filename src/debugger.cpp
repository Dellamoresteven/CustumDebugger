#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <iostream>

#include "linenoise.h"
#include "debugger.h"
#include "registers.h"

using std::string;
using std::vector;
using std::cerr;
using namespace minidbg;

vector<string> split(const string &s, const char delimiter);
bool is_prefix(const string &s, const string &of);

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
    } else {
        cerr << "Unknown Command\n";
    }
}

void debugger::continue_execution() {
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
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
