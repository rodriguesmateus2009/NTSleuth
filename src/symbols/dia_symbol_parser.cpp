// NTSleuth - Advanced Windows syscall extraction & analysis framework
// Copyright (c) 2025 Alexander Hagenah (@xaitax)
// Licensed under the BSD 3-Clause License - see LICENSE file for details

#include "symbols/dia_symbol_parser.h"
#include "utils/logger.h"
#include <Windows.h>

#ifdef HAS_DIA_SDK
#include <dia2.h>
#include <atlbase.h>
#include <comutil.h>
#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "comsuppw.lib")
#endif

namespace WinSyscall
{

#ifdef HAS_DIA_SDK

    class DiaSymbolParser : public ISymbolParser
    {
    public:
        DiaSymbolParser();
        ~DiaSymbolParser() override;

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
        CComPtr<IDiaDataSource> data_source_;
        CComPtr<IDiaSession> session_;
        CComPtr<IDiaSymbol> global_scope_;
        bool symbols_loaded_ = false;

        bool LoadDataSource();
        bool ParseFunctionType(IDiaSymbol *type_symbol,
                               std::string &return_type,
                               std::vector<Parameter> &parameters);
        std::string GetSymbolType(IDiaSymbol *symbol);
        CallingConvention GetCallingConvention(DWORD cv);
    };

    DiaSymbolParser::DiaSymbolParser()
    {
        CoInitialize(nullptr);
    }

    DiaSymbolParser::~DiaSymbolParser()
    {
        global_scope_.Release();
        session_.Release();
        data_source_.Release();
        CoUninitialize();
    }

    bool DiaSymbolParser::Initialize(const std::string &module_path, const std::string &pdb_path)
    {
        module_path_ = module_path;
        pdb_path_ = pdb_path;

        if (!LoadDataSource())
        {
            return false;
        }

        // Load PDB
        std::wstring wide_pdb = std::wstring(pdb_path.begin(), pdb_path.end());
        HRESULT hr = data_source_->loadDataFromPdb(wide_pdb.c_str());

        if (FAILED(hr))
        {
            last_error_ = "Failed to load PDB file";
            LOG_ERROR(last_error_);
            return false;
        }

        // Open session
        hr = data_source_->openSession(&session_);
        if (FAILED(hr))
        {
            last_error_ = "Failed to open DIA session";
            LOG_ERROR(last_error_);
            return false;
        }

        // Get global scope
        hr = session_->get_globalScope(&global_scope_);
        if (FAILED(hr))
        {
            last_error_ = "Failed to get global scope";
            LOG_ERROR(last_error_);
            return false;
        }

        symbols_loaded_ = true;
        LOG_INFO("DIA symbols loaded for " + module_path);
        return true;
    }

    bool DiaSymbolParser::LoadDataSource()
    {
        // Try to create DIA data source
        HRESULT hr = CoCreateInstance(
            CLSID_DiaSource,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IDiaDataSource,
            (void **)&data_source_);

        if (FAILED(hr))
        {
            // Try to load msdia140.dll directly
            HMODULE hModule = LoadLibraryA("msdia140.dll");
            if (!hModule)
            {
                last_error_ = "Failed to load msdia140.dll";
                LOG_ERROR(last_error_);
                return false;
            }

            typedef HRESULT(WINAPI * DllGetClassObjectFunc)(REFCLSID, REFIID, LPVOID *);
            DllGetClassObjectFunc DllGetClassObject = (DllGetClassObjectFunc)GetProcAddress(hModule, "DllGetClassObject");

            if (!DllGetClassObject)
            {
                last_error_ = "Failed to get DllGetClassObject";
                LOG_ERROR(last_error_);
                return false;
            }

            CComPtr<IClassFactory> class_factory;
            hr = DllGetClassObject(CLSID_DiaSource, IID_IClassFactory, (void **)&class_factory);
            if (FAILED(hr))
            {
                last_error_ = "Failed to get class factory";
                LOG_ERROR(last_error_);
                return false;
            }

            hr = class_factory->CreateInstance(nullptr, IID_IDiaDataSource, (void **)&data_source_);
            if (FAILED(hr))
            {
                last_error_ = "Failed to create DIA data source";
                LOG_ERROR(last_error_);
                return false;
            }
        }

        return true;
    }

    bool DiaSymbolParser::EnumerateSymbols(std::function<bool(const SymbolInfo &)> callback)
    {
        if (!symbols_loaded_)
        {
            return false;
        }

        CComPtr<IDiaEnumSymbols> enum_symbols;
        HRESULT hr = global_scope_->findChildren(SymTagFunction, nullptr, nsNone, &enum_symbols);

        if (FAILED(hr))
        {
            return false;
        }

        CComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;

        while (SUCCEEDED(enum_symbols->Next(1, &symbol, &fetched)) && fetched == 1)
        {
            BSTR name;
            if (SUCCEEDED(symbol->get_name(&name)))
            {
                SymbolInfo info;
                // Convert BSTR to std::string
                int len = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
                if (len > 0)
                {
                    std::vector<char> buffer(len);
                    WideCharToMultiByte(CP_UTF8, 0, name, -1, buffer.data(), len, nullptr, nullptr);
                    info.name = buffer.data();
                }
                SysFreeString(name);

                ULONGLONG va;
                if (SUCCEEDED(symbol->get_virtualAddress(&va)))
                {
                    info.address = va;
                }

                ULONGLONG length;
                if (SUCCEEDED(symbol->get_length(&length)))
                {
                    info.size = static_cast<uint32_t>(length);
                }

                if (!callback(info))
                {
                    break;
                }
            }

            symbol.Release();
        }

        return true;
    }

    bool DiaSymbolParser::GetFunctionPrototype(const std::string &function_name,
                                               std::string &return_type,
                                               std::vector<Parameter> &parameters,
                                               CallingConvention &calling_convention)
    {
        if (!symbols_loaded_)
        {
            return false;
        }

        // Find function symbol
        CComPtr<IDiaEnumSymbols> enum_symbols;
        std::wstring wide_name = std::wstring(function_name.begin(), function_name.end());

        HRESULT hr = global_scope_->findChildren(SymTagFunction, wide_name.c_str(), nsCaseSensitive, &enum_symbols);
        if (FAILED(hr))
        {
            return false;
        }

        CComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;

        if (FAILED(enum_symbols->Next(1, &symbol, &fetched)) || fetched != 1)
        {
            return false;
        }

        // Get function type
        CComPtr<IDiaSymbol> type_symbol;
        if (FAILED(symbol->get_type(&type_symbol)))
        {
            return false;
        }

        // Get calling convention
        DWORD cv;
        if (SUCCEEDED(type_symbol->get_callingConvention(&cv)))
        {
            calling_convention = GetCallingConvention(cv);
        }

        // Parse function type
        return ParseFunctionType(type_symbol, return_type, parameters);
    }

    bool DiaSymbolParser::ParseFunctionType(IDiaSymbol *type_symbol,
                                            std::string &return_type,
                                            std::vector<Parameter> &parameters)
    {
        // Get return type
        CComPtr<IDiaSymbol> return_type_symbol;
        if (SUCCEEDED(type_symbol->get_type(&return_type_symbol)))
        {
            return_type = GetSymbolType(return_type_symbol);
        }

        // Get parameters
        CComPtr<IDiaEnumSymbols> enum_params;
        if (SUCCEEDED(type_symbol->findChildren(SymTagFunctionArgType, nullptr, nsNone, &enum_params)))
        {
            CComPtr<IDiaSymbol> param_symbol;
            ULONG fetched = 0;

            while (SUCCEEDED(enum_params->Next(1, &param_symbol, &fetched)) && fetched == 1)
            {
                Parameter param;

                CComPtr<IDiaSymbol> param_type;
                if (SUCCEEDED(param_symbol->get_type(&param_type)))
                {
                    param.type = GetSymbolType(param_type);

                    // Check if pointer
                    DWORD sym_tag;
                    if (SUCCEEDED(param_type->get_symTag(&sym_tag)))
                    {
                        param.is_pointer = (sym_tag == SymTagPointerType);
                    }
                }

                parameters.push_back(param);
                param_symbol.Release();
            }
        }

        return true;
    }

    std::string DiaSymbolParser::GetSymbolType(IDiaSymbol *symbol)
    {
        if (!symbol)
        {
            return "void";
        }

        BSTR name;
        if (SUCCEEDED(symbol->get_name(&name)))
        {
            std::string result;
            int len = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0)
            {
                std::vector<char> buffer(len);
                WideCharToMultiByte(CP_UTF8, 0, name, -1, buffer.data(), len, nullptr, nullptr);
                result = buffer.data();
            }
            SysFreeString(name);
            return result;
        }

        // Try to get base type
        DWORD base_type;
        if (SUCCEEDED(symbol->get_baseType(&base_type)))
        {
            switch (base_type)
            {
            case btVoid:
                return "void";
            case btChar:
                return "char";
            case btWChar:
                return "wchar_t";
            case btInt:
                return "int";
            case btUInt:
                return "unsigned int";
            case btFloat:
                return "float";
            case btBool:
                return "bool";
            case btLong:
                return "long";
            case btULong:
                return "unsigned long";
            default:
                return "unknown";
            }
        }

        return "unknown";
    }

    CallingConvention DiaSymbolParser::GetCallingConvention(DWORD cv)
    {
        switch (cv)
        {
        case CV_CALL_NEAR_C:
        case CV_CALL_FAR_C:
            return CallingConvention::Cdecl;
        case CV_CALL_NEAR_PASCAL:
        case CV_CALL_FAR_PASCAL:
        case CV_CALL_NEAR_STD:
        case CV_CALL_FAR_STD:
            return CallingConvention::Stdcall;
        case CV_CALL_NEAR_FAST:
        case CV_CALL_FAR_FAST:
            return CallingConvention::Fastcall;
        case CV_CALL_THISCALL:
            return CallingConvention::Thiscall;
        default:
            return CallingConvention::Unknown;
        }
    }

    bool DiaSymbolParser::GetSymbolByName(const std::string & /*name*/, SymbolInfo & /*info*/)
    {
        // Implementation similar to GetFunctionPrototype
        return false;
    }

    bool DiaSymbolParser::GetSymbolByAddress(uint64_t /*address*/, SymbolInfo & /*info*/)
    {
        // Implementation would use findSymbolByVA
        return false;
    }

    bool DiaSymbolParser::HasSymbols() const
    {
        return symbols_loaded_;
    }

#endif // HAS_DIA_SDK

    // Factory function that creates DIA parser if available, otherwise DbgHelp
    std::unique_ptr<ISymbolParser> CreateDiaSymbolParser()
    {
#ifdef HAS_DIA_SDK
        return std::make_unique<DiaSymbolParser>();
#else
        LOG_WARNING("DIA SDK not available, using DbgHelp parser");
        return nullptr;
#endif
    }

}
