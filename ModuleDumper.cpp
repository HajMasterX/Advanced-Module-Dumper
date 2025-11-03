#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

class ModuleDumper {
private:
    struct ProcessInfo {
        DWORD pid;
        std::string name;
    };

    struct ModuleInfo {
        std::string name;
        DWORD_PTR baseAddress;
        DWORD size;
        std::string path;
    };

    HANDLE m_processHandle;
    DWORD m_processId;

    void cleanup() {
        if (m_processHandle) {
            CloseHandle(m_processHandle);
            m_processHandle = NULL;
        }
    }

    bool enableDebugPrivilege() {
        HANDLE hToken;
        TOKEN_PRIVILEGES tkp;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            return false;
        }

        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, 0);
        CloseHandle(hToken);

        return result == TRUE;
    }

    std::vector<ProcessInfo> enumerateProcesses() {
        std::vector<ProcessInfo> processes;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return processes;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                ProcessInfo info;
                info.pid = pe.th32ProcessID;
                info.name = pe.szExeFile;
                processes.push_back(info);
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return processes;
    }

    DWORD findProcessByName(const std::string& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        DWORD pid = 0;
        if (Process32First(hSnapshot, &pe)) {
            do {
                std::string currentProcess = pe.szExeFile;
                std::string targetProcess = processName;
                
                std::transform(currentProcess.begin(), currentProcess.end(), currentProcess.begin(), ::tolower);
                std::transform(targetProcess.begin(), targetProcess.end(), targetProcess.begin(), ::tolower);
                
                if (currentProcess == targetProcess) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return pid;
    }

    bool openProcess(const std::string& processName) {
        cleanup();

        m_processId = findProcessByName(processName);
        if (m_processId == 0) {
            std::cout << "Process '" << processName << "' not found.\n";
            return false;
        }

        enableDebugPrivilege();

        m_processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, m_processId);
        if (!m_processHandle) {
            DWORD error = GetLastError();
            std::cout << "Failed to open process with VM_READ. Error: " << error << "\n";
            
            m_processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_processId);
            if (!m_processHandle) {
                error = GetLastError();
                std::cout << "Failed to open process with ALL_ACCESS. Error: " << error << "\n";
                return false;
            }
        }

        return true;
    }

    std::vector<ModuleInfo> enumerateModules() {
        std::vector<ModuleInfo> modules;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_processId);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cout << "Failed to create module snapshot. Error: " << GetLastError() << "\n";
            return modules;
        }

        MODULEENTRY32 me;
        me.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hSnapshot, &me)) {
            do {
                ModuleInfo info;
                info.name = me.szModule;
                info.baseAddress = (DWORD_PTR)me.modBaseAddr;
                info.size = me.modBaseSize;
                info.path = me.szExePath;
                modules.push_back(info);
            } while (Module32Next(hSnapshot, &me));
        }

        CloseHandle(hSnapshot);
        return modules;
    }

    bool findModule(const std::string& moduleName, ModuleInfo& result) {
        auto modules = enumerateModules();
        for (const auto& mod : modules) {
            std::string currentModule = mod.name;
            std::string targetModule = moduleName;
            
            std::transform(currentModule.begin(), currentModule.end(), currentModule.begin(), ::tolower);
            std::transform(targetModule.begin(), targetModule.end(), targetModule.begin(), ::tolower);
            
            if (currentModule == targetModule) {
                result = mod;
                return true;
            }
        }
        return false;
    }

    bool dumpMemory(DWORD_PTR baseAddress, DWORD size, const std::string& outputPath) {
        std::vector<BYTE> buffer(size);
        SIZE_T bytesRead = 0;

        std::cout << "Reading memory at 0x" << std::hex << baseAddress << " size " << std::dec << size << " bytes...\n";
        
        BOOL success = ReadProcessMemory(m_processHandle, (LPCVOID)baseAddress, buffer.data(), size, &bytesRead);
        if (!success) {
            DWORD error = GetLastError();
            std::cout << "ReadProcessMemory failed. Error: " << error << "\n";
            return false;
        }

        std::cout << "Successfully read " << bytesRead << " bytes\n";
        std::cout << "Writing to file: " << outputPath << "\n";
        
        std::ofstream file(outputPath, std::ios::binary);
        if (!file.is_open()) {
            std::cout << "Failed to create output file\n";
            return false;
        }

        file.write((const char*)buffer.data(), bytesRead);
        file.close();

        if (file.fail()) {
            std::cout << "Error writing to file\n";
            return false;
        }

        std::cout << "Dump completed successfully!\n";
        return true;
    }

public:
    ModuleDumper() : m_processHandle(NULL), m_processId(0) {}
    ~ModuleDumper() { cleanup(); }

    bool listProcesses() {
        std::vector<ProcessInfo> processes = enumerateProcesses();
        if (processes.empty()) {
            std::cout << "No processes found\n";
            return false;
        }

        std::cout << "Found " << processes.size() << " processes:\n";
        std::cout << "PID\tProcess Name\n";
        std::cout << "---\t------------\n";
        
        for (const auto& proc : processes) {
            std::cout << proc.pid << "\t" << proc.name << "\n";
        }
        
        return true;
    }

    bool listModules(const std::string& processName) {
        if (!openProcess(processName)) {
            return false;
        }

        std::vector<ModuleInfo> modules = enumerateModules();
        if (modules.empty()) {
            std::cout << "No modules found\n";
            return false;
        }

        std::cout << "Found " << modules.size() << " modules in " << processName << ":\n";
        std::cout << "Base Address\tSize\t\tModule Name\n";
        std::cout << "------------\t----\t\t-----------\n";
        
        for (const auto& mod : modules) {
            std::cout << "0x" << std::hex << mod.baseAddress << "\t" 
                      << std::dec << mod.size << "\t\t" << mod.name << "\n";
        }

        return true;
    }

    bool dumpModule(const std::string& processName, const std::string& moduleName, const std::string& outputPath) {
        if (!openProcess(processName)) {
            return false;
        }

        ModuleInfo targetModule;
        if (!findModule(moduleName, targetModule)) {
            std::cout << "Module not found: " << moduleName << "\n";
            return false;
        }

        std::cout << "Target module found:\n";
        std::cout << "  Name: " << targetModule.name << "\n";
        std::cout << "  Base: 0x" << std::hex << targetModule.baseAddress << "\n";
        std::cout << "  Size: " << std::dec << targetModule.size << " bytes\n";
        std::cout << "  Path: " << targetModule.path << "\n";

        return dumpMemory(targetModule.baseAddress, targetModule.size, outputPath);
    }
};

void printUsage(const char* programName) {
    std::cout << "Module Dumper\n";
    std::cout << "Usage:\n";
    std::cout << "  " << programName << " list\n";
    std::cout << "  " << programName << " list <process_name>\n";
    std::cout << "  " << programName << " dump <process> <module> <output>\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << programName << " list\n";
    std::cout << "  " << programName << " list notepad.exe\n";
    std::cout << "  " << programName << " dump notepad.exe notepad.exe dump.bin\n";
}

int main(int argc, char* argv[]) {
    ModuleDumper dumper;

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    if (command == "list" && argc == 2) {
        if (!dumper.listProcesses()) {
            return 1;
        }
    }
    else if (command == "list" && argc == 3) {
        if (!dumper.listModules(argv[2])) {
            return 1;
        }
    }
    else if (command == "dump" && argc == 5) {
        if (!dumper.dumpModule(argv[2], argv[3], argv[4])) {
            return 1;
        }
    }
    else {
        printUsage(argv[0]);
        return 1;
    }

    return 0;
}