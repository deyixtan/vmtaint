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

static vmi_instance_t vmi;
#define STACK_MEMORY_SIZE 0x1000
char stack_memory[STACK_MEMORY_SIZE];

struct taint_address {
    addr_t address;
    size_t size;
};

static bool save_state(const char *filepath, vector<struct taint_address> taint_addresses)
{
    registers_t regs;
    memset(&regs, 0, sizeof(regs));

    vmi_get_vcpuregs(vmi, &regs, 0);

    FILE *i = fopen(filepath, "w+");
    if ( !i )
        return false;

    fwrite(&regs, sizeof(regs), 1, i);

    ACCESS_CONTEXT(ctx);
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = regs.x86.cr3;
    ctx.addr = regs.x86.rbp - sizeof(stack_memory);

    size_t sz = 0;
    vmi_read(vmi, &ctx, sizeof(stack_memory), reinterpret_cast<uint8_t*>(stack_memory), &sz);

    fwrite(stack_memory, 1, sizeof(stack_memory), i);

    // save tainted buffer
    for (unsigned int j = 0; j < taint_addresses.size(); j++)
    {
        ACCESS_CONTEXT(ctx);
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = regs.x86.cr3;
        ctx.addr = taint_addresses[j].address;

        size_t sz = 0;
        char buf[taint_addresses[j].size];
        vmi_read(vmi, &ctx, sizeof(buf), reinterpret_cast<uint8_t*>(buf), &sz);

        fwrite(buf, 1, sizeof(buf), i);   
    }

    fclose(i);
    return true;
}

static bool load_state(const char *filepath, vector<struct taint_address> taint_addresses)
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

    // load tainted buffer
    for (unsigned int j = 0; j < taint_addresses.size(); j++)
    {
        char buf[taint_addresses[j].size];
        read = fread(buf, 1, sizeof(buf), i);

        if( read != sizeof(buf) )
        {
            fclose(i);
            return false;
        }

        addr_t index = 0;
        for ( addr_t addr = taint_addresses[j].address; addr < taint_addresses[j].address + sizeof(buf); addr++)
        {
            triton_api.setConcreteMemoryValue(addr, buf[index++]);
        }
    }

    fclose(i);
    return true;
}

static bool process_data(const char *filepath, bool show_disassembly, bool show_disassembly_regs, bool show_disassembly_stack,
    bool show_functions, bool show_functions_regs, bool show_functions_stack)
{
    FILE* file = fopen(filepath, "r");
    char line[256];
    set<string> addr_set;

    if (show_disassembly)
        cout << "[Tainted Disassembly::START]" << endl;
    while (fgets(line, sizeof(line), file)) {
        const char delim[2] = ";";
        char *token, *addr;
        //char *insn, *operands;
        char *hexbytes;
        
        token = strtok(line, delim);
        addr = token;
        token = strtok(NULL, delim);
        //insn = token;
        token = strtok(NULL, delim);
        //operands = token;
        token = strtok(NULL, delim);
        hexbytes = token;

        Instruction inst;
        string tmp;
        stringstream ss(hexbytes);
        vector<unsigned char> bytes;
        while (getline(ss, tmp, ' ')) {
            bytes.push_back(strtoul(tmp.c_str(), NULL, 16));
        }

        inst.setOpcode(bytes.data(), bytes.size());
        inst.setAddress(strtoull(addr, NULL, 16));
        triton_api.processing(inst);
        
        string disass = inst.getDisassembly();

        unordered_set<triton::uint64> tainted_mem = triton_api.getTaintedMemory();
        unordered_set<const triton::arch::Register *> tainted_regs = triton_api.getTaintedRegisters();
        string regs;

        if (show_disassembly) {
            cout << addr << "\t" << disass << endl;
            if (show_disassembly_stack) {
                for (auto itr = tainted_mem.begin(); itr != tainted_mem.end(); ++itr) {
                    cout << "\t Tainted mem: 0x" << hex << *itr;
                    cout << " 0x" << std::setfill('0') << std::setw(2) << unsigned(triton_api.getConcreteMemoryValue(*itr)) << endl;
                }
            }
        }

        regs = "[";
        for (auto itr = tainted_regs.begin(); itr != tainted_regs.end(); ++itr)
        {
            const triton::arch::Register *reg = *itr;
            if ( (*itr)->getId() != ID_REG_INVALID && (*itr)->getSize() ) {
                std::stringstream sstream;
                sstream << std::hex << triton_api.getConcreteRegisterValue(*reg);
                
                regs.append(reg->getName());
                regs.append("=0x");
                regs.append(sstream.str());
                regs.append(",");

                if (show_disassembly && show_disassembly_regs)
                    cout << "\t Tainted reg: " << reg->getName() << ": " << std::hex << "0x" << triton_api.getConcreteRegisterValue(*reg) << endl;
            }
        }
        
        if (regs.length() > 1) // only substr if there is at least 1 reg tainted
            regs = regs.substr(0, regs.length() - 1);
        regs.append("]");

        size_t pos = disass.find("call ");
        if (pos != string::npos) {
            string affected_func = disass.substr(pos + 5);
            if (show_functions_regs) {
                if (tainted_regs.size() > 0) {
                    affected_func.append(" ");
                    affected_func.append(regs);
                }
            }
            if (show_functions_stack) {
                if (tainted_mem.size() > 0) {
                    affected_func.append("\n");
                    for (auto itr = tainted_mem.begin(); itr != tainted_mem.end(); ++itr) {
                        std::stringstream sstream;
                        sstream << "\t0x" << hex << *itr;
                        sstream << " 0x" << std::setfill('0') << std::setw(2) << unsigned(triton_api.getConcreteMemoryValue(*itr)) << endl;
                        affected_func.append(sstream.str());
                    }
                    affected_func = affected_func.substr(0, affected_func.length() - 1);
                }
            }
            if (tainted_regs.size() > 0 || tainted_mem.size() > 0)
                addr_set.insert(affected_func);
        }
    }
    if (show_disassembly)
        cout << "[Tainted Disassembly::END]" << endl;

    fclose(file);

    if (show_functions) {
        if (show_disassembly)
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
    }
    return true;
}

int main(int argc, char *const *argv)
{
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"domid", required_argument, NULL, 'a'},
        {"save-state", required_argument, NULL, 'b'},
        {"load-state", required_argument, NULL, 'c'},
        {"load-data", required_argument, NULL, 'd'},
        {"taint", required_argument, NULL, 'e'},
        {"show-disassembly", no_argument, NULL, 'f'},
        {"show-disassembly-regs", no_argument, NULL, 'g'},
        {"show-disassembly-stack", no_argument, NULL, 'h'},
        {"show-functions", no_argument, NULL, 'i'},
        {"show-functions-regs", no_argument, NULL, 'j'},
        {"show-functions-stack", no_argument, NULL, 'k'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "a:b:cdefgh";
    uint64_t domid = 0;
    bool save = false;
    const char* statefile = NULL;
    const char* datafile = NULL;
    bool show_disassembly = false;
    bool show_disassembly_regs = false;
    bool show_disassembly_stack = false;
    bool show_functions = false;
    bool show_functions_regs = false;
    bool show_functions_stack = false;
    vector<struct taint_address> taint_addresses;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 'a':
            domid = strtoull(optarg, NULL, 0);
            break;
        case 'b':
            save = true;
            statefile = optarg;
            break;
        case 'c':
            statefile = optarg;
            break;
        case 'd':
            datafile = optarg;
            break;
        case 'e':
        {
            string s(optarg);
            size_t pos = s.find(":");
            addr_t address = strtoull(s.substr(0, pos).c_str(), NULL, 0);
            size_t size = pos ? strtoull(s.substr(pos+1, s.length()).c_str(), NULL, 0) : 1;

            taint_addresses.push_back({address, size});
            break;
        }
        case 'f':
            show_disassembly = true;
            break;    
        case 'g':
            show_disassembly_regs = true;
            break;    
        case 'h':
            show_disassembly_stack = true;
            break;    
        case 'i':
            show_functions = true;
            break;  
        case 'j':
            show_functions_regs = true;
            break;  
        case 'k':
            show_functions_stack = true;
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

    if ( save )
    {
        if ( !domid )
        {
            cout << "No domid specified\n" << endl;
            return -1;
        }
    }

    if ( VMI_FAILURE == vmi_init(&vmi, VMI_XEN, &domid, VMI_INIT_DOMAINID, NULL, NULL) )
        return -1;

    vmi_init_paging(vmi, 0);

    if ( save )
    {
        cout << "Saving state" << endl;
        save_state(statefile, taint_addresses);
        vmi_destroy(vmi);
        return 0;
    }

    if ( !datafile )
    {
        cout << "No data file specified" << endl;
        return -1;
    }

    triton_api.setArchitecture(ARCH_X86_64);
    triton_api.enableTaintEngine(1);
    triton_api.enableSymbolicEngine(0);

    if ( !load_state(statefile, taint_addresses) )
    {
        cout << "Unable to load state file" << endl;
        return -1;
    }

    for (unsigned int i = 0; i < taint_addresses.size(); i++)
    {
        cout << "Tainting memory at 0x" << hex << taint_addresses[i].address << " + " << taint_addresses[i].size << endl;
        for (unsigned int s = 0; s < taint_addresses[i].size; s++ )
            triton_api.taintMemory(taint_addresses[i].address + s);
    }

    if ( !process_data(datafile, show_disassembly, show_disassembly_regs, show_disassembly_stack,
                show_functions, show_functions_regs, show_functions_stack ) )
    {
        cout << "Unable to process data file" << endl;
        return -1;
    }

    return 0;
}
