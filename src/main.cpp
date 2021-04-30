#include <iostream>
#include <unistd.h>
#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <sys/personality.h>
#include "debugger.h"

// https://blog.tartanllama.xyz/writing-a-linux-debugger-setup/

using std::cout;
using std::cerr;
using std::endl;
using namespace minidbg;

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
}
