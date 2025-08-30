// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "symbols/dbghelp_symbol_parser.h"
#include "utils/logger.h"
#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <memory>
#include <sstream>
#include <string>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

namespace WinSyscall
{

    class DbgHelpSymbolParser : public ISymbolParser
    {
    public:
        DbgHelpSymbolParser();
        ~DbgHelpSymbolParser() override;

        bool Initialize(const std::string &module_path, const std::string &pdb_path) override;
        bool EnumerateSymbols(std::function<bool(const SymbolInfo &)> callback) override;
        bool GetFunctionPrototype(const std::string &function_name,
                                  std::string &return_type,
                                  std::vector<Parameter> &parameters,
                                  CallingConvention &calling_convention) override;
        bool GetSymbolByName(const std::string &name, SymbolInfo &info) override;
        bool GetSymbolByAddress(uint64_t address, SymbolInfo &info) override;
        bool HasSymbols() const override;
        std::string GetLastError() const override { return last_error_; }

    private:
        HANDLE process_handle_ = nullptr;
        DWORD64 base_address_ = 0;
        bool symbols_loaded_ = false;

        static BOOL CALLBACK EnumSymbolsCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext);
        bool ParseTypeInfo(DWORD type_index, std::string &type_name);
        CallingConvention GetCallingConvention(DWORD calling_conv);
    };

    DbgHelpSymbolParser::DbgHelpSymbolParser()
    {
        process_handle_ = GetCurrentProcess();

        // Initialize DbgHelp
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

        if (!SymInitialize(process_handle_, nullptr, FALSE))
        {
            LOG_WARNING("Failed to initialize DbgHelp");
        }
    }

    DbgHelpSymbolParser::~DbgHelpSymbolParser()
    {
        if (process_handle_)
        {
            SymCleanup(process_handle_);
        }
    }

    bool DbgHelpSymbolParser::Initialize(const std::string &module_path, const std::string &pdb_path)
    {
        module_path_ = module_path;
        pdb_path_ = pdb_path;

        // Set symbol search path to include PDB directory
        std::string search_path;
        if (!pdb_path.empty())
        {
            size_t pos = pdb_path.find_last_of("\\/");
            if (pos != std::string::npos)
            {
                search_path = pdb_path.substr(0, pos);
            }
        }

        // Add system directories for ARM64 compatibility
        if (!search_path.empty())
        {
            search_path += ";";
        }
        search_path += "srv*"; // Use symbol server

        if (!search_path.empty())
        {
            SymSetSearchPath(process_handle_, search_path.c_str());
        }

        // Get actual module base address from loaded module
        HMODULE hModule = LoadLibraryExA(module_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!hModule)
        {
            DWORD error = ::GetLastError();
            std::stringstream ss;
            ss << "Failed to load module for inspection. Error: " << error;
            last_error_ = ss.str();
            LOG_ERROR(last_error_);
            return false;
        }

        // Use the actual module base address
        DWORD64 module_base = reinterpret_cast<DWORD64>(hModule);

        // Get module size
        MODULEINFO mod_info = {0};
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &mod_info, sizeof(mod_info)))
        {
            FreeLibrary(hModule);
            last_error_ = "Failed to get module information";
            LOG_ERROR(last_error_);
            return false;
        }

        // Load module and symbols with actual base and size
        base_address_ = SymLoadModuleEx(process_handle_, nullptr, module_path.c_str(),
                                        nullptr, module_base, mod_info.SizeOfImage, nullptr, 0);

        FreeLibrary(hModule);

        if (base_address_ == 0)
        {
            DWORD error = ::GetLastError();

            // Error 87 (ERROR_INVALID_PARAMETER) might mean module is already loaded
            if (error == ERROR_INVALID_PARAMETER)
            {
                // Try to find if module is already loaded
                IMAGEHLP_MODULE64 mod_info_ex = {0};
                mod_info_ex.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);

                if (SymGetModuleInfo64(process_handle_, module_base, &mod_info_ex))
                {
                    base_address_ = module_base;
                    symbols_loaded_ = true;
                    LOG_INFO("Module already loaded in symbol engine: " + module_path);
                    return true;
                }
            }

            std::stringstream ss;
            ss << "Failed to load module symbols. Error: " << error;
            last_error_ = ss.str();
            LOG_ERROR(last_error_);
            return false;
        }

        symbols_loaded_ = true;
        LOG_INFO("DbgHelp symbols loaded for " + module_path);
        return true;
    }

    bool DbgHelpSymbolParser::EnumerateSymbols(std::function<bool(const SymbolInfo &)> callback)
    {
        if (!symbols_loaded_)
        {
            return false;
        }

        struct CallbackContext
        {
            std::function<bool(const SymbolInfo &)> *callback;
            DWORD64 base_address;
        } context = {&callback, base_address_};

        return SymEnumSymbols(process_handle_, base_address_, "*",
                              EnumSymbolsCallback, &context) != FALSE;
    }

    BOOL CALLBACK DbgHelpSymbolParser::EnumSymbolsCallback(PSYMBOL_INFO pSymInfo,
                                                           ULONG /*SymbolSize*/,
                                                           PVOID UserContext)
    {
        struct CallbackContext
        {
            std::function<bool(const SymbolInfo &)> *callback;
            DWORD64 base_address;
        };

        auto *context = static_cast<CallbackContext *>(UserContext);

        SymbolInfo info;
        info.name = pSymInfo->Name;
        info.address = pSymInfo->Address;
        info.size = pSymInfo->Size;

        // Check if it's a function (Tag 5 is SymTagFunction)
        if (pSymInfo->Tag == 5)
        { // SymTagFunction
            return (*context->callback)(info) ? TRUE : FALSE;
        }

        return TRUE;
    }

    bool DbgHelpSymbolParser::GetFunctionPrototype(const std::string &function_name,
                                                   std::string &return_type,
                                                   std::vector<Parameter> &parameters,
                                                   CallingConvention &calling_convention)
    {
        if (!symbols_loaded_)
        {
            return false;
        }

        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        PSYMBOL_INFO symbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        if (!SymFromName(process_handle_, function_name.c_str(), symbol))
        {
            LOG_DEBUG("Failed to find symbol for: " + function_name);
            return false;
        }

        LOG_DEBUG("Found symbol " + function_name + " with TypeIndex: " + std::to_string(symbol->TypeIndex));

        // Get type information if available
        if (symbol->TypeIndex != 0)
        {
            // Try to get function signature type
            DWORD func_type_index = symbol->TypeIndex;

            // Get symbol tag to verify it's a function
            DWORD tag = 0;
            if (SymGetTypeInfo(process_handle_, base_address_, func_type_index, TI_GET_SYMTAG, &tag))
            {
                LOG_DEBUG("Symbol tag: " + std::to_string(tag));

                // Tag values: 5 = Function, 14 = PointerType, 16 = BaseType
                if (tag == 14)
                { // SymTagPointerType
                    LOG_DEBUG("Found pointer type, getting underlying type");
                    if (!SymGetTypeInfo(process_handle_, base_address_, func_type_index, TI_GET_TYPE, &func_type_index))
                    {
                        LOG_DEBUG("Failed to get underlying type from pointer");
                    }
                }
            }

            // Try to get return type
            DWORD return_type_index = 0;
            if (SymGetTypeInfo(process_handle_, base_address_, func_type_index,
                               TI_GET_TYPE, &return_type_index))
            {
                ParseTypeInfo(return_type_index, return_type);
                LOG_DEBUG("Return type: " + return_type);
            }
            else
            {
                LOG_DEBUG("Failed to get return type");
            }

            // Try to get calling convention
            DWORD calling_conv = 0;
            if (SymGetTypeInfo(process_handle_, base_address_, func_type_index,
                               TI_GET_CALLING_CONVENTION, &calling_conv))
            {
                calling_convention = GetCallingConvention(calling_conv);
                LOG_DEBUG("Calling convention: " + std::to_string(calling_conv));
            }
            else
            {
                LOG_DEBUG("Failed to get calling convention");
            }

            // Try to get parameters using TI_GET_COUNT
            DWORD param_count = 0;
            if (SymGetTypeInfo(process_handle_, base_address_, func_type_index,
                               TI_GET_COUNT, &param_count))
            {
                LOG_DEBUG("Function has " + std::to_string(param_count) + " parameters");

                if (param_count > 0)
                {
                    // Allocate buffer for children
                    DWORD children_size = sizeof(TI_FINDCHILDREN_PARAMS) + param_count * sizeof(ULONG);
                    TI_FINDCHILDREN_PARAMS *children = (TI_FINDCHILDREN_PARAMS *)malloc(children_size);
                    if (children)
                    {
                        memset(children, 0, children_size);
                        children->Count = param_count;

                        // Get parameter type indices
                        if (SymGetTypeInfo(process_handle_, base_address_, func_type_index,
                                           TI_FINDCHILDREN, children))
                        {
                            LOG_DEBUG("Got children for parameters, actual count: " + std::to_string(children->Count));

                            for (DWORD i = 0; i < children->Count && i < param_count; ++i)
                            {
                                Parameter param;

                                LOG_DEBUG("Processing parameter " + std::to_string(i) + " with ID: " +
                                          std::to_string(children->ChildId[i]));

                                // Get parameter type
                                DWORD param_type_index = 0;
                                if (SymGetTypeInfo(process_handle_, base_address_, children->ChildId[i],
                                                   TI_GET_TYPE, &param_type_index))
                                {
                                    ParseTypeInfo(param_type_index, param.type);
                                    LOG_DEBUG("Parameter " + std::to_string(i) + " type: " + param.type);
                                }
                                else
                                {
                                    LOG_DEBUG("Failed to get type for parameter " + std::to_string(i));
                                }

                                // Get parameter name (often not available for syscalls)
                                WCHAR *param_name = nullptr;
                                if (SymGetTypeInfo(process_handle_, base_address_, children->ChildId[i],
                                                   TI_GET_SYMNAME, &param_name))
                                {
                                    int len = WideCharToMultiByte(CP_UTF8, 0, param_name, -1, nullptr, 0, nullptr, nullptr);
                                    if (len > 0)
                                    {
                                        std::vector<char> name_buffer(len);
                                        WideCharToMultiByte(CP_UTF8, 0, param_name, -1, name_buffer.data(), len, nullptr, nullptr);
                                        param.name = name_buffer.data();
                                    }
                                    LocalFree(param_name);
                                }

                                // If no name, generate one
                                if (param.name.empty())
                                {
                                    param.name = "param" + std::to_string(i + 1);
                                }

                                // Check if it's a pointer
                                DWORD param_tag = 0;
                                if (SymGetTypeInfo(process_handle_, base_address_, param_type_index,
                                                   TI_GET_SYMTAG, &param_tag))
                                {
                                    param.is_pointer = (param_tag == 14); // SymTagPointerType
                                }

                                parameters.push_back(param);
                            }
                        }
                        else
                        {
                            DWORD error = ::GetLastError(); // Use global scope for Windows API
                            LOG_DEBUG("Failed to get children with TI_FINDCHILDREN, error: " + std::to_string(error));
                        }

                        free(children);
                    }
                    else
                    {
                        LOG_DEBUG("Failed to allocate memory for children");
                    }
                }
            }
            else
            {
                LOG_DEBUG("Failed to get parameter count with TI_GET_COUNT");
            }
        }
        else
        {
            LOG_DEBUG("Symbol has no TypeIndex (0)");
        }

        // Default values if we couldn't get them
        if (return_type.empty())
        {
            return_type = "NTSTATUS"; // Common for syscalls
        }
        if (calling_convention == CallingConvention::Unknown)
        {
            calling_convention = CallingConvention::Stdcall; // Default for syscalls
        }

        LOG_DEBUG("Final: " + function_name + " has " + std::to_string(parameters.size()) + " parameters");

        return true;
    }

    bool DbgHelpSymbolParser::GetSymbolByName(const std::string &name, SymbolInfo &info)
    {
        if (!symbols_loaded_)
        {
            return false;
        }

        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        PSYMBOL_INFO symbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        if (!SymFromName(process_handle_, name.c_str(), symbol))
        {
            return false;
        }

        info.name = symbol->Name;
        info.address = symbol->Address;
        info.size = symbol->Size;

        return true;
    }

    bool DbgHelpSymbolParser::GetSymbolByAddress(uint64_t address, SymbolInfo &info)
    {
        if (!symbols_loaded_)
        {
            return false;
        }

        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        PSYMBOL_INFO symbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement = 0;
        if (!SymFromAddr(process_handle_, address, &displacement, symbol))
        {
            return false;
        }

        info.name = symbol->Name;
        info.address = symbol->Address;
        info.size = symbol->Size;

        return true;
    }

    bool DbgHelpSymbolParser::HasSymbols() const
    {
        return symbols_loaded_;
    }

    bool DbgHelpSymbolParser::ParseTypeInfo(DWORD type_index, std::string &type_name)
    {
        // First try to get the type name directly
        WCHAR *type_name_w = nullptr;
        if (SymGetTypeInfo(process_handle_, base_address_, type_index,
                           TI_GET_SYMNAME, &type_name_w))
        {
            // Convert wide string to narrow
            int len = WideCharToMultiByte(CP_UTF8, 0, type_name_w, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0)
            {
                std::vector<char> buffer(len);
                WideCharToMultiByte(CP_UTF8, 0, type_name_w, -1, buffer.data(), len, nullptr, nullptr);
                type_name = buffer.data();
            }
            LocalFree(type_name_w);
            return true;
        }

        // If that fails, try to determine type from tag and size
        DWORD tag = 0;
        if (SymGetTypeInfo(process_handle_, base_address_, type_index, TI_GET_SYMTAG, &tag))
        {
            ULONG64 size = 0;
            SymGetTypeInfo(process_handle_, base_address_, type_index, TI_GET_LENGTH, &size);

            switch (tag)
            {
            case 14: // SymTagPointerType
            {
                // Get the type it points to
                DWORD pointed_type = 0;
                if (SymGetTypeInfo(process_handle_, base_address_, type_index, TI_GET_TYPE, &pointed_type))
                {
                    std::string pointed_type_name;
                    if (ParseTypeInfo(pointed_type, pointed_type_name))
                    {
                        type_name = "P" + pointed_type_name;
                    }
                    else
                    {
                        type_name = "PVOID";
                    }
                }
                else
                {
                    type_name = "PVOID";
                }
                return true;
            }
            case 16: // SymTagBaseType
            {
                DWORD base_type = 0;
                if (SymGetTypeInfo(process_handle_, base_address_, type_index, TI_GET_BASETYPE, &base_type))
                {
                    switch (base_type)
                    {
                    case 1:
                        type_name = "VOID";
                        break;
                    case 2:
                        type_name = "CHAR";
                        break;
                    case 3:
                        type_name = "WCHAR";
                        break;
                    case 6:
                        type_name = (size == 4) ? "INT" : "LONGLONG";
                        break;
                    case 7:
                        type_name = (size == 4) ? "ULONG" : "ULONGLONG";
                        break;
                    case 8:
                        type_name = "FLOAT";
                        break;
                    case 9:
                        type_name = "DOUBLE";
                        break;
                    case 10:
                        type_name = "BOOL";
                        break;
                    case 13:
                        type_name = (size == 4) ? "LONG" : "LONGLONG";
                        break;
                    case 14:
                        type_name = (size == 4) ? "ULONG" : "ULONGLONG";
                        break;
                    default:
                        type_name = "UNKNOWN";
                        break;
                    }
                    return true;
                }
                break;
            }
            case 11: // SymTagUDT (user defined type)
            {
                type_name = "STRUCT";
                return true;
            }
            }
        }

        return false;
    }

    CallingConvention DbgHelpSymbolParser::GetCallingConvention(DWORD calling_conv)
    {
        switch (calling_conv)
        {
        case 0: // CV_CALL_NEAR_C
            return CallingConvention::Cdecl;
        case 1: // CV_CALL_FAR_C
            return CallingConvention::Cdecl;
        case 2: // CV_CALL_NEAR_PASCAL
        case 3: // CV_CALL_FAR_PASCAL
            return CallingConvention::Stdcall;
        case 4: // CV_CALL_NEAR_FAST
        case 5: // CV_CALL_FAR_FAST
            return CallingConvention::Fastcall;
        case 7: // CV_CALL_NEAR_STD
        case 8: // CV_CALL_FAR_STD
            return CallingConvention::Stdcall;
        case 9:  // CV_CALL_NEAR_SYS
        case 10: // CV_CALL_FAR_SYS
            return CallingConvention::Stdcall;
        case 11: // CV_CALL_THISCALL
            return CallingConvention::Thiscall;
        default:
            return CallingConvention::Unknown;
        }
    }

    // Forward declaration for DIA parser factory
    std::unique_ptr<ISymbolParser> CreateDiaSymbolParser();

    // Factory function implementation
    std::unique_ptr<ISymbolParser> CreateSymbolParser(bool prefer_dia)
    {
        if (prefer_dia)
        {
            // Try to create DIA parser first
            auto dia_parser = CreateDiaSymbolParser();
            if (dia_parser)
            {
                return dia_parser;
            }
        }

        return std::make_unique<DbgHelpSymbolParser>();
    }

}
