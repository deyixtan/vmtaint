#include <vector>
#include <iostream>
#include <triton/api.hpp>
#include <triton/aarch64Specifications.hpp>
#include <libvmi/libvmi.h>
#include <getopt.h>

using namespace std;
using namespace triton;
using namespace triton::arch;
using namespace triton::arch::x86;
triton::API triton_api;

#define STACK_MEMORY_SIZE 0x1000
char stack_memory[STACK_MEMORY_SIZE];

struct taint_address {
    addr_t address;
    size_t size;
};

static bool load_state(const char *filepath)
{
    x86_registers_t regs;
    memset(&regs, 0, sizeof(regs));

    FILE *i = fopen(filepath, "r");
    if ( !i )
        return false;

    size_t read = fread(&regs, 1, sizeof(x86_registers_t), i);

    if ( read != sizeof(x86_registers_t) )
    {
        fclose(i);
        return false;
    }

    triton_api.setConcreteRegisterValue(triton_api.getRegister("rax"), regs.rax);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rbx"), regs.rbx);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rcx"), regs.rcx);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rdx"), regs.rdx);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rdi"), regs.rdi);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rsi"), regs.rsi);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rbp"), regs.rbp);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rsp"), regs.rsp);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rip"), regs.rip);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r8"), regs.r8);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r9"), regs.r9);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r10"), regs.r10);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r11"), regs.r11);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r12"), regs.r12);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r13"), regs.r13);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r14"), regs.r14);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r15"), regs.r15);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("eflags"), regs.rflags);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("fs"), regs.fs_base);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("gs"), regs.fs_base);

    read = fread(stack_memory, 1, sizeof(stack_memory), i);

    if( read != sizeof(stack_memory) )
    {
        fclose(i);
        return false;
    }

    addr_t index = 0;
    for ( addr_t addr = regs.rbp - sizeof(stack_memory); addr < regs.rbp; addr++)
    {
        triton_api.setConcreteMemoryValue(addr, stack_memory[index++]);
    }

    fclose(i);
    return true;
}

static bool process_data(const char *filepath)
{
    // for now taint rdi register (1st arg)
    triton_api.taintRegister(triton_api.registers.x86_rdi);

    FILE* file = fopen(filepath, "r");
    char line[256];
    set<string> addr_set;

    cout << "[Tainted Disassembly::START]" << endl;
    while (fgets(line, sizeof(line), file)) {
        const char delim[2] = ";";
        char *token, *addr;
        // char *insn, *operands
        char *hex;
        
        token = strtok(line, delim);
        addr = token;
        token = strtok(NULL, delim);
        //insn = token;
        token = strtok(NULL, delim);
        //operands = token;
        token = strtok(NULL, delim);
        hex = token;

        Instruction inst;
        string tmp;
        stringstream ss(hex);
        vector<unsigned char> bytes;
        while (getline(ss, tmp, ' ')) {
            bytes.push_back(strtoul(tmp.c_str(), NULL, 16));
        }

        inst.setOpcode(bytes.data(), bytes.size());
        inst.setAddress(strtoull(addr, NULL, 16));
        triton_api.processing(inst);
        string disass = inst.getDisassembly();
        cout << addr << "\t" << disass << endl;

        unordered_set<const triton::arch::Register *> tainted_regs = triton_api.getTaintedRegisters();

        for (auto itr = tainted_regs.begin(); itr != tainted_regs.end(); ++itr)
        {
            const triton::arch::Register *reg = *itr;
            if ( (*itr)->getId() != ID_REG_INVALID && (*itr)->getSize() ) {
                cout << "\t Tainted reg: " << reg->getName() << ": " << triton_api.getConcreteRegisterValue(*reg) << endl;
                size_t pos = disass.find("call ");
                if (pos != string::npos) {
                    string affected_func = disass.substr(pos + 5);
                    addr_set.insert(affected_func);
                }
            }
        }
    }
    cout << "[Tainted Disassembly::END]" << endl;

    fclose(file);
    cout << endl << endl;
    cout << "[Affected Functions::START]" << endl;
    if (addr_set.size() > 0) {
        for (string const& addr : addr_set)
        {
            std::cout << addr << endl;
        } 
    } else {
        std::cout << "None" << endl;
    }
    cout << "[Affected functions::END]" << endl;
    return true;
}

int main(int argc, char *const *argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"taint", required_argument, NULL, 't'},
        {"load-state", required_argument, NULL, 's'},
        {"load-data", required_argument, NULL, 'd'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "t:s:d";
    const char* statefile = NULL;
    const char* datafile = NULL;
    vector<struct taint_address> taint_addresses;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 't':
        {
            string s(optarg);
            size_t pos = s.find(":");
            addr_t address = strtoull(s.substr(0, pos).c_str(), NULL, 0);
            size_t size = pos ? strtoull(s.substr(pos+1, s.length()).c_str(), NULL, 0) : 1;

            taint_addresses.push_back({address, size});
            break;
        }
        case 's':
            statefile = optarg;
            break;
        case 'd':
            datafile = optarg;
            break;      
        default:
            return -1;
        };
    }

    if ( !statefile )
    {
        cout << "No state file specified" << endl;
        return -1;
    }

    if ( !datafile )
    {
        cout << "No data file specified" << endl;
        return -1;
    }

    triton_api.setArchitecture(ARCH_X86_64);
    triton_api.enableTaintEngine(1);
    triton_api.enableSymbolicEngine(0);

    if ( !load_state(statefile) )
    {
        cout << "Unable to load state file" << endl;
        return -1;
    }

    if ( !process_data(datafile) )
    {
        cout << "Unable to process data file" << endl;
        return -1;
    }

    return 0;
}
