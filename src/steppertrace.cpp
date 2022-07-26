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
    triton_api.setConcreteRegisterValue(triton_api.getRegister("cr0"), regs.cr0);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("cr2"), regs.cr2);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("cr3"), regs.cr3);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("cr4"), regs.cr4);

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

vector<string> split(string str, string token){
    vector<string>result;
    while(str.length()){
        int index = str.find(token);
        if(index!=string::npos){
            result.push_back(str.substr(0,index));
            str = str.substr(index+token.size());
            if(str.length()==0)result.push_back(str);
        }else{
            result.push_back(str);
            str = "";
        }
    }
    return result;
}

static bool process_data(const char *filepath, bool show_disassembly, bool show_disassembly_regs, bool show_disassembly_mem,
    bool show_functions, bool show_functions_regs, bool show_functions_mem)
{
    FILE* file = fopen(filepath, "r");
    char line[1024];
    vector<string> addr_list;

    if (show_disassembly)
        cout << "[Tainted Disassembly::START]" << endl;

    vector<string> lines;
    while (fgets(line, sizeof(line), file)) {
        lines.push_back(line);
    }

    for (int i = 0; i < lines.size(); i++) {
        vector<string> stepper_output = split(lines[i], ";");
        if (stepper_output.size() != 5)
            continue;
        string addr = stepper_output.at(0);
        string insn = stepper_output.at(1);
        string operands = stepper_output.at(2);
        string hexbytes = stepper_output.at(3);
        string regs_tmp = stepper_output.at(4);

        vector<string> hexbytes_list = split(hexbytes, " ");
        vector<unsigned char> bytes;
        for (int i = 0; i < hexbytes_list.size(); i++) {
            bytes.push_back(strtoul(hexbytes_list[i].c_str(), NULL, 16));
        }

        vector<string> regs_tmp_list = split(regs_tmp, ",");
        for (int i = 0; i < regs_tmp_list.size(); i++) {
            vector<string> regs_tmp_single = split(regs_tmp_list[i], "=");
            triton_api.setConcreteRegisterValue(triton_api.getRegister(regs_tmp_single[0]), strtoull(regs_tmp_single[1].c_str(), NULL, 16));
        }

        Instruction inst;
        inst.setOpcode(bytes.data(), bytes.size());
        inst.setAddress(strtoull(addr.c_str(), NULL, 16));    
        triton_api.processing(inst);

        string disass = inst.getDisassembly();

        unordered_set<triton::uint64> tainted_mem = triton_api.getTaintedMemory();
        unordered_set<const triton::arch::Register *> tainted_regs = triton_api.getTaintedRegisters();
        string regs;

        // process current instruction (for disassembly)
        if (show_disassembly) {
            cout << addr << "\t" << disass << endl;
            if (show_disassembly_mem) {
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

        // check for call insns that have ptr to tainted buffer
        size_t pos_tmp = disass.find("call ");
        if (pos_tmp != string::npos) {
            const Register rcx = triton_api.getRegister("rcx");
            const Register rdx = triton_api.getRegister("rdx");
            const Register r8 = triton_api.getRegister("r8");
            const Register r9 = triton_api.getRegister("r9");
            vector<Register> regs_list;
            regs_list.push_back(rcx);
            regs_list.push_back(rdx);
            regs_list.push_back(r8);
            regs_list.push_back(r9);

            for (const Register r : regs_list) {
                if (!triton_api.isRegisterTainted2(r)) {
                    uint64 addr = (uint64)triton_api.getConcreteRegisterValue(r);
                    if (triton_api.isMemoryTainted2(addr)) {
                        std::stringstream sstream;
                        sstream << std::hex << addr;
                        regs.append(r.getName());
                        regs.append("=0x");
                        regs.append(sstream.str());
                        regs.append(",");

                        if (show_disassembly && show_disassembly_regs)
                            cout << "\t Tainted reg*: " << r.getName() << ": " << std::hex << "0x" << triton_api.getConcreteRegisterValue(r) << endl;
                    }
                }
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
            if (show_functions_mem) {
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
                addr_list.push_back(affected_func);
        }
    }
    if (show_disassembly)
        cout << "[Tainted Disassembly::END]" << endl;

    fclose(file);

    if (show_functions) {
        if (show_disassembly)
            cout << endl << endl;

        cout << "[Affected Functions::START]" << endl;
        if (addr_list.size() > 0) {
            for (string const& addr : addr_list)
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
        {"taint-reg", required_argument, NULL, 'e'},
        {"taint-mem", required_argument, NULL, 'f'},
        {"show-disassembly", no_argument, NULL, 'g'},
        {"show-disassembly-regs", no_argument, NULL, 'h'},
        {"show-disassembly-mem", no_argument, NULL, 'i'},
        {"show-functions", no_argument, NULL, 'j'},
        {"show-functions-regs", no_argument, NULL, 'k'},
        {"show-functions-mem", no_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "a:b:c:d:e:f:g:hijkl";
    uint64_t domid = 0;
    bool save = false;
    const char* statefile = NULL;
    const char* datafile = NULL;
    bool show_disassembly = false;
    bool show_disassembly_regs = false;
    bool show_disassembly_mem = false;
    bool show_functions = false;
    bool show_functions_regs = false;
    bool show_functions_mem = false;
    uint64_t registerid = 0;
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
            registerid = strtoull(optarg, NULL, 0);
            break;
        case 'f':
        {
            string s(optarg);
            size_t pos = s.find(":");
            addr_t address = strtoull(s.substr(0, pos).c_str(), NULL, 0);
            size_t size = pos ? strtoull(s.substr(pos+1, s.length()).c_str(), NULL, 0) : 1;

            taint_addresses.push_back({address, size});
            break;
        }
        case 'g':
            show_disassembly = true;
            break;    
        case 'h':
            show_disassembly_regs = true;
            break;    
        case 'i':
            show_disassembly_mem = true;
            break;    
        case 'j':
            show_functions = true;
            break;  
        case 'k':
            show_functions_regs = true;
            break;  
        case 'l':
            show_functions_mem = true;
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
    triton_api.setMode(modes::TAINT_THROUGH_POINTERS, true);

    if ( !load_state(statefile, taint_addresses) )
    {
        cout << "Unable to load state file" << endl;
        return -1;
    }

    if ( registerid ) {
        if (registerid == 1)
            triton_api.taintRegister(triton_api.registers.x86_rax);
        else if (registerid == 2)
            triton_api.taintRegister(triton_api.registers.x86_rbx);
        else if (registerid == 3)
            triton_api.taintRegister(triton_api.registers.x86_rcx);
        else if (registerid == 4)
            triton_api.taintRegister(triton_api.registers.x86_rdx);                                 
        else if (registerid == 5)
            triton_api.taintRegister(triton_api.registers.x86_rbp);
        else if (registerid == 6)
            triton_api.taintRegister(triton_api.registers.x86_rsi);
        else if (registerid == 7)
            triton_api.taintRegister(triton_api.registers.x86_rdi);
        else if (registerid == 8)
            triton_api.taintRegister(triton_api.registers.x86_rsp);
        else if (registerid == 9)
            triton_api.taintRegister(triton_api.registers.x86_r8);
        else if (registerid == 10)
            triton_api.taintRegister(triton_api.registers.x86_r9);
        else if (registerid == 11)
            triton_api.taintRegister(triton_api.registers.x86_r10);
        else if (registerid == 12)
            triton_api.taintRegister(triton_api.registers.x86_r11);
        else if (registerid == 13)
            triton_api.taintRegister(triton_api.registers.x86_r12);
        else if (registerid == 14)
            triton_api.taintRegister(triton_api.registers.x86_r13);
        else if (registerid == 15)
            triton_api.taintRegister(triton_api.registers.x86_r14);
        else if (registerid == 16)
            triton_api.taintRegister(triton_api.registers.x86_r15);
        else if (registerid == 17)
            triton_api.taintRegister(triton_api.registers.x86_rip);                                                                                                                                                           
    }

    for (unsigned int i = 0; i < taint_addresses.size(); i++)
    {
        cout << "Tainting memory at 0x" << hex << taint_addresses[i].address << " + " << taint_addresses[i].size << endl;
        for (unsigned int s = 0; s < taint_addresses[i].size; s++ )
            triton_api.taintMemory(taint_addresses[i].address + s);
    }

    if ( !process_data(datafile, show_disassembly, show_disassembly_regs, show_disassembly_mem,
                show_functions, show_functions_regs, show_functions_mem ) )
    {
        cout << "Unable to process data file" << endl;
        return -1;
    }

    return 0;
}
