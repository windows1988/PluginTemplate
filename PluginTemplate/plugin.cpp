#include "plugin.h"
#include "om.h"
#include <map>
#include "qq_datadefs.h"
#include <functional>

enum
{
    MENU_TEST,
    MENU_DISASM_ADLER32,
    MENU_DUMP_ADLER32,
    MENU_STACK_ADLER32
};

static void Adler32Menu(int hWindow)
{
    if(!DbgIsDebugging())
    {
        dputs("You need to be debugging to use this command");
        return;
    }
    SELECTIONDATA sel;
    GuiSelectionGet(hWindow, &sel);
    duint len = sel.end - sel.start + 1;
    unsigned char* data = new unsigned char[len];
    if(DbgMemRead(sel.start, data, len))
    {
        DWORD a = 1, b = 0;
        for(duint index = 0; index < len; ++index)
        {
            a = (a + data[index]) % 65521;
            b = (b + a) % 65521;
        }
        delete[] data;
        DWORD checksum = (b << 16) | a;
        dprintf("Adler32 of %p[%X] is: %08X\n", sel.start, len, checksum);
    }
    else
        dputs("DbgMemRead failed...");
}

static bool cbTestCommand(int argc, char* argv[])
{
    dputs("Test command!");
    char line[GUI_MAX_LINE_SIZE] = "";
    if(!GuiGetLineWindow("test", line))
        dputs("Cancel pressed!");
    else
        dprintf("Line: \"%s\"\n", line);
    return true;
}

static duint exprZero(int argc, duint* argv, void* userdata)
{
    return 0;
}

PLUG_EXPORT void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
    dprintf("Debugging of %s started!\n", info->szFileName);
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    dputs("Debugging stopped!");
}

PLUG_EXPORT void CBEXCEPTION(CBTYPE cbType, PLUG_CB_EXCEPTION* info)
{
    dprintf("ExceptionRecord.ExceptionCode: %08X\n", info->Exception->ExceptionRecord.ExceptionCode);
}

PLUG_EXPORT void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{
    if(info->DebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        dprintf("DebugEvent->EXCEPTION_DEBUG_EVENT->%.8X\n", info->DebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
    }
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    switch(info->hEntry)
    {
    case MENU_TEST:
        MessageBoxA(hwndDlg, "Test Menu Entry Clicked!", PLUGIN_NAME, MB_ICONINFORMATION);
        break;

    case MENU_DISASM_ADLER32:
        Adler32Menu(GUI_DISASSEMBLY);
        break;

    case MENU_DUMP_ADLER32:
        Adler32Menu(GUI_DUMP);
        break;

    case MENU_STACK_ADLER32:
        Adler32Menu(GUI_STACK);
        break;

    default:
        break;
    }
}
#define QQ_KEY "[qq_key]"

void txbuff_free(qqsso_txbuff_t& buf)
{
    if (buf.buff_ptr != NULL)
    {
        free(buf.buff_ptr);
        memset(&buf, 0, sizeof(qqsso_txbuff_t));
    }
}

void txbuff_load_from_debugee(unsigned int ptr, qqsso_txbuff_t& buf)
{
    memset(&buf,0 ,sizeof(qqsso_txbuff_t));
    duint sizeRead = 0;
    if (Script::Memory::Read(ptr, &buf, sizeof(qqsso_txbuff_t), &sizeRead) && sizeRead == sizeof(qqsso_txbuff_t))
    {
     //   dprintf("%08x, %08x,", buf.buff_len, buf.buff_ptr);

        if (buf.buff_len == 0)
        {
           // dputs(QQ_KEY "empty str");
           // PrintDebugA(QQ_KEY "empty str");
        }
        else
        {
            unsigned int content_ptr = (unsigned int)buf.buff_ptr;
            buf.buff_ptr = (unsigned char*)malloc(buf.buff_len);
            sizeRead = 0;
            bool ret = Script::Memory::Read(content_ptr, buf.buff_ptr, buf.buff_len, &sizeRead);
            if (ret && sizeRead == buf.buff_len)
            {
                //dputs(QQ_KEY "load_from_debugee ok");
               // PrintDebugA(QQ_KEY "load_from_debugee   ok");
            }
            else
            {
              //  dputs(QQ_KEY "load_from_debugee err");
            //    PrintDebugA(QQ_KEY "load_from_debugee  err[%d,%d]", ret, sizeRead);
            }
        }
      
    }
    else
    {
     //   dputs(QQ_KEY "read debugee mem fail");
      //  PrintDebugA(QQ_KEY "read debugee mem fail");
    }
}

string BinToHex(const string& strBin, bool bIsUpper = false)
{
    string strHex;
    strHex.resize(strBin.size() * 2);
    for (size_t i = 0; i < strBin.size(); i++)
    {
        uint8_t cTemp = strBin[i];
        for (size_t j = 0; j < 2; j++)
        {
            uint8_t cCur = (cTemp & 0x0f);
            if (cCur < 10)
            {
                cCur += '0';
            }
            else
            {
                cCur += ((bIsUpper ? 'A' : 'a') - 10);
            }
            strHex[2 * i + 1 - j] = cCur;
            cTemp >>= 4;
        }
    }

    return strHex;
}

static bool cbqq_EncryptPayloadCommand(int argc, char* argv[])
{
    unsigned int esp = Script::Register::GetESP();
    unsigned int key_ptr = Script::Memory::ReadDword(esp + 8);
    unsigned char key_buff[0x10] = { 0 };
    duint sizeReaded = 0;
    if (Script::Memory::Read(key_ptr, key_buff, 0x10, &sizeReaded) && sizeReaded == 0x10)
    {
        std::string two((char*)key_buff, 0x10);
        std::string two_hex = BinToHex(two);
        PrintDebugA(QQ_KEY " qq_EncryptPayload key  [%s]", two_hex.c_str());
    }
    else
    {
        PrintDebugA(QQ_KEY "qq_EncryptPayload err ");
    }
    return true;
}

static bool cbqq_SetCrypyKeyCommand(int argc, char* argv[])
{
    // dputs
    // dprintf
 //   dputs(QQ_KEY "qq_SetCrypyKey");
   // PrintDebugA(QQ_KEY "qq_SetCrypyKey");
    
    unsigned int edx = Script::Register::GetEDX();
    unsigned int ptr_CsCmdCryptKey = Script::Memory::ReadDword(edx);
    qqsso_txbuff_t CsCmdCryptKey = {0};
   txbuff_load_from_debugee(ptr_CsCmdCryptKey, CsCmdCryptKey);
  //  dprintf("%08x, %08x,", edx, ptr_CsCmdCryptKey);

    std::string one((char*)CsCmdCryptKey.buff_ptr, CsCmdCryptKey.buff_len);
    std::string one_hex = BinToHex(one);

  //  dprintf(QQ_KEY " CsCmdCryptKey[%s]", one_hex.c_str());
    PrintDebugA(QQ_KEY " CsCmdCryptKey ptr[%08x][%s]", ptr_CsCmdCryptKey, one_hex.c_str());

    txbuff_free(CsCmdCryptKey);
     

    unsigned int esp = Script::Register::GetESP();
    unsigned int CsPrefix_ptr = Script::Memory::ReadDword(esp+4);

    unsigned int ptr_bufCsPrefix = Script::Memory::ReadDword(CsPrefix_ptr);
    

    qqsso_txbuff_t bufCsPrefix = {0};
   txbuff_load_from_debugee(ptr_bufCsPrefix, bufCsPrefix);
    std::string two((char*)bufCsPrefix.buff_ptr, bufCsPrefix.buff_len);
    std::string two_hex = BinToHex(two);


       
  //  dprintf(QQ_KEY " CsPrefix[%s]", two_hex.c_str());
    PrintDebugA(QQ_KEY "ptr[%08x] CsPrefix[%s]", ptr_bufCsPrefix, two_hex.c_str());

    txbuff_free(bufCsPrefix);
    

    return true;
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    _plugin_registercommand(pluginHandle, "qq_SetCrypyKey", cbqq_SetCrypyKeyCommand, false);
    _plugin_registercommand(pluginHandle, "qq_EncryptPayload", cbqq_EncryptPayloadCommand, false);

  //  _plugin_registerexprfunction(pluginHandle, PLUGIN_NAME ".zero", 0, exprZero, nullptr);
    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
    _plugin_menuentryremove(pluginHandle, MENU_TEST);
    //  _plugin_registercommand(pluginHandle, "qq_SetCrypyKey", cbqq_SetCrypyKeyCommand, false);
    _plugin_unregistercommand(pluginHandle, "qq_SetCrypyKey");
    _plugin_unregistercommand(pluginHandle, "qq_EncryptPayload");

    /*
    _plugin_unregistercommand(pluginHandle, PLUGIN_NAME);
    _plugin_unregisterexprfunction(pluginHandle, PLUGIN_NAME ".zero");

   
    _plugin_menuentryremove(pluginHandle, MENU_DISASM_ADLER32);
    _plugin_menuentryremove(pluginHandle, MENU_DUMP_ADLER32);
    _plugin_menuentryremove(pluginHandle, MENU_STACK_ADLER32);//*/
}

static void cbWinEventCallback(CBTYPE cbType, void* info)
{
    MSG* msg = ((PLUG_CB_WINEVENT*)info)->message;
    switch (msg->message)
    {
    case WM_SYSKEYDOWN:
        if (0X53 == msg->wParam && (GetKeyState(VK_MENU) & 0X8000))
        {
            MessageBoxA(hwndDlg, "alt +s ", PLUGIN_NAME, MB_ICONINFORMATION);
        }
        break;
    }
}

class Buffer
{
public:
    Buffer()
    {
        buff = nullptr;
        len = 0;
    }

    void free_mem()
    {
        if (buff && len >0)
        {
            free(buff);
            buff = nullptr;
            len = 0;
        }     
    }

    ~Buffer()
    {

    }
    void* buff;
    int len;
};

void handler_EncryptPayload_ret()
{
}

typedef struct 
{
    std::string bp_name;
    std::function<void()> bp_handler;
} qq_bp_handler_t;

std::map<duint, qq_bp_handler_t> bp_map;

// RVA B47C2 qq_EncryptPayload
static void cbLoadDllCallback(CBTYPE cbType, void* info)
{
    PLUG_CB_LOADDLL* callbackInfo = (PLUG_CB_LOADDLL*)info;
    if (0 == _stricmp(callbackInfo->modname, "ssoplatform.dll"))
    {
        PrintDebugA("%s load in %08x", callbackInfo->modname, callbackInfo->modInfo->BaseOfImage);
        if (Script::Debug::SetBreakpoint(callbackInfo->modInfo->BaseOfImage + 0xB47C2))
        {
            PrintDebugA("bp[%08x] ok", callbackInfo->modInfo->BaseOfImage + 0xB47C2);

            qq_bp_handler_t handler;
            handler.bp_name = "qq_EncryptPayload_ret";
            handler.bp_handler = handler_EncryptPayload_ret;
            bp_map[callbackInfo->modInfo->BaseOfImage + 0xB47C2] = handler;
        }
        else
        {
            PrintDebugA("bp[%08x] fail",callbackInfo->modInfo->BaseOfImage + 0xB47C2);
        }
    }
    //PrintDebugA("%s load in %08x", callbackInfo->modname, callbackInfo->modInfo->BaseOfImage);
}

static void cbBreakPointCallback(CBTYPE cbType, void* info)
{
    BRIDGEBP* breakpoint = ((PLUG_CB_BREAKPOINT*)info)->breakpoint;
    if (bp_map.find(breakpoint->addr) != bp_map.end())
    {
        PrintDebugA("Break %s hit", bp_map[breakpoint->addr].bp_name.c_str());
        bp_map[breakpoint->addr].bp_handler();
    }
}

//Do GUI/Menu related things here.
void pluginSetup()
{
    _plugin_menuaddentry(hMenu, MENU_TEST, "&Menu Test");
    //_plugin_registercallback(pluginHandle, CB_LOADDLL, cbLoadDllCallback);
   // _plugin_registercallback(pluginHandle, CB_BREAKPOINT, cbBreakPointCallback);

    /*
  
    _plugin_menuaddentry(hMenuDisasm, MENU_DISASM_ADLER32, "&Adler32 Selection");
    _plugin_menuaddentry(hMenuDump, MENU_DUMP_ADLER32, "&Adler32 Selection");
    _plugin_menuaddentry(hMenuStack, MENU_STACK_ADLER32, "&Adler32 Selection");

    _plugin_registercallback(pluginHandle, CB_WINEVENT, cbWinEventCallback);


   
    _plugin_registercallback(pluginHandle, CB_INITDEBUG, cbInitDebugCallback);
    _plugin_registercallback(pluginHandle, CB_BREAKPOINT, cbBreakPointCallback);
    _plugin_registercallback(pluginHandle, CB_STOPDEBUG, cbStopDebugCallback);
    _plugin_registercallback(pluginHandle, CB_CREATEPROCESS, cbCreateProcessCallback);
    _plugin_registercallback(pluginHandle, CB_EXITPROCESS, cbExitProcessCallback);
    _plugin_registercallback(pluginHandle, CB_CREATETHREAD, cbCreateThreadCallback);
    _plugin_registercallback(pluginHandle, CB_EXITTHREAD, cbExitThreadCallback);
    _plugin_registercallback(pluginHandle, CB_SYSTEMBREAKPOINT, cbSystemBreakpointCallback);
    _plugin_registercallback(pluginHandle, CB_LOADDLL, cbLoadDllCallback);
    _plugin_registercallback(pluginHandle, CB_UNLOADDLL, cbUnloadDllCallback);
    _plugin_registercallback(pluginHandle, CB_TRACEEXECUTE, cbTraceExecuteCallback);//*/
}
