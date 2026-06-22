/**
 * @file SPF_ConvoyChatMessaging.cpp
 * @brief Professional implementation of the Convoy Chat Messaging plugin.
 * @details This plugin demonstrates advanced reverse engineering techniques:
 * 1. Finding game functions by unique instruction patterns (Signatures).
 * 2. Dynamically extracting global variable addresses and struct offsets from machine code.
 * 3. Intercepting game logic using function hooking with trampolines.
 */

#include "SPF_ConvoyChatMessaging.hpp"
#include <cstdio>
#include <cstring>
#include <Windows.h>
#include <algorithm>

namespace SPF_ConvoyChatMessaging {

PluginContext g_ctx;

// =================================================================================================
// 1. Manifest & Setup
// =================================================================================================

void BuildManifest(SPF_Manifest_Builder_Handle* h, const SPF_Manifest_Builder_API* api) {
    {
        api->Info_SetName(h, "SPF_ConvoyChatMessaging");
        api->Info_SetVersion(h, "1.1.0");
        api->Info_SetMinFrameworkVersion(h, "1.1.9");
        api->Info_SetAuthor(h, "Track'n'Truck Devs");
        api->Info_SetDescriptionLiteral(h, "Reference plugin for Convoy Chat manipulation and interception.");
    }

    {
        api->Policy_SetAllowUserConfig(h, true);
        api->Policy_AddConfigurableSystem(h, "logging");
    }

    // Default Keybind: CTRL + Y to toggle the manager window
    api->Defaults_AddKeybind(h, "MainWindow", "toggle", "chord", "keyboard:KEY_LCONTROL+keyboard:KEY_Y", "never");

    // UI Window Registration (Hidden by default)
    api->Defaults_AddWindow(h, "MainWindow", false, true, 100, 100, 500, 450, false, false);

    // Logging: Set to debug to see intercepted messages in the console
    api->Defaults_SetLogging(h, "debug", true);

    api->Meta_AddWindow(h, "MainWindow", "Convoy Chat Manager", "Tool for sending and logging chat messages.");
    api->Meta_AddKeybind(h, "MainWindow", "toggle", "Toggle Chat Manager", "Show or hide the Convoy Chat Messaging window.");
}

void OnLoad(const SPF_Load_API* load_api) {
    g_ctx.loadAPI = load_api;
    if (g_ctx.loadAPI) {
        g_ctx.loggerHandle = g_ctx.loadAPI->logger->Log_GetContext("SPF_ConvoyChatMessaging");
        g_ctx.formattingAPI = g_ctx.loadAPI->formatting;
        g_ctx.baseAddress = (uintptr_t)GetModuleHandle(NULL);
    }
}

// =================================================================================================
// 2. Lifecycle & Hook Registration
// =================================================================================================

void OnActivated(const SPF_Core_API* core_api) {
    g_ctx.coreAPI = core_api;
    if (!g_ctx.coreAPI || !g_ctx.coreAPI->hooks) return;

    auto hooks = g_ctx.coreAPI->hooks;
    g_ctx.hooksAPI = hooks;

    auto logMsg = [&](SPF_LogLevel level, const char* fmt, auto... args) {
        if (!g_ctx.coreAPI || !g_ctx.coreAPI->logger || !g_ctx.loggerHandle) return;

        char buf[512];
        if (g_ctx.formattingAPI) {
            g_ctx.formattingAPI->Fmt_Format(buf, sizeof(buf), fmt, args...);
        } else {
            snprintf(buf, sizeof(buf), fmt, args...);
        }
        g_ctx.coreAPI->logger->Log(g_ctx.loggerHandle, level, buf);
    };

    // --- STEP 1: Find the AddToChat function (Visual logic) ---
    // This signature matches the prologue of FUN_1408a42c0 (ver 1.60).
    // It is used to display messages in the local chat window.
    const char* addToChatStr = "str:@@mp_chat_system@@";
    logMsg(SPF_LOG_INFO, "[STEP 1] Searching AddToChat by string: %s", addToChatStr);
    g_ctx.fnAddToChat = (AddToChat_t)hooks->Hook_FindFunctionByString("@@mp_chat_system@@", true, nullptr, 0);
    logMsg(SPF_LOG_INFO, "[STEP 1] AddToChat function %s at 0x%llX",
           g_ctx.fnAddToChat ? "found" : "not found",
           (unsigned long long)(uintptr_t)g_ctx.fnAddToChat);
    if (g_ctx.fnAddToChat) {
        logMsg(SPF_LOG_INFO, "[STEP 1] Registering hook: %s", addToChatStr);
        hooks->Hook_Register(
            "SPF_ConvoyChatMessaging", "ChatIntercept", "Intercepts messages before display",
            (void*)&Detour_AddToChat, (void**)&g_ctx.o_AddToChat, addToChatStr, true
        );
        logMsg(SPF_LOG_INFO, "[STEP 1] ChatIntercept hook registered");
    } else {
        logMsg(SPF_LOG_WARN, "[STEP 1] Skipping hook registration because AddToChat was not found");
    }

    // --- STEP 2: Extract pUIManager Address & Offset ---
    // Find the string first, then walk backward to the nearby MOV RSI, [pUIManager].
    // The cmp [rsi + offset], rax is in the same local block right after it.
    const char* leavingPrivateStr = "@@mp_leaving_private@@"; //1408ad8b5
    logMsg(SPF_LOG_INFO, "[STEP 2] Searching string: %s", leavingPrivateStr);
    uintptr_t leavingStrAddr = hooks->Hook_FindFunctionByString(leavingPrivateStr, false, nullptr, 0);
    logMsg(SPF_LOG_INFO, "[STEP 2] String %s at 0x%llX",
           leavingStrAddr ? "found" : "not found",
           (unsigned long long)leavingStrAddr);
    if (leavingStrAddr != 0) {
        uintptr_t finderAddr = hooks->Hook_FindBackward(leavingStrAddr, 16, "48 8B [05-3D]"); //1408ad8a7
        logMsg(SPF_LOG_INFO, "[STEP 2] MOV pattern %s at 0x%llX",
               finderAddr ? "found" : "not found",
               (unsigned long long)finderAddr);
        if (finderAddr != 0) {
            // First instruction (7 bytes): 48 8B 35 [offset_32] -> Extract RIP-relative address of pUIManager
            g_ctx.ppUIManager = (void**)hooks->Memory_GetRipAddress(finderAddr, 3, 7);
            logMsg(SPF_LOG_INFO, "[STEP 2] pUIManager pointer slot = 0x%llX",
                   (unsigned long long)(uintptr_t)g_ctx.ppUIManager);
        }
        // Find the nearby CMP [RSI + offset], RAX and read the 32-bit offset.
        uintptr_t cmpAddr = hooks->Hook_FindPatternFrom("48 39 [81-86]", leavingStrAddr, 32); // 1408ad8ba
        logMsg(SPF_LOG_INFO, "[STEP 2] CMP pattern %s at 0x%llX",
               cmpAddr ? "found" : "not found",
               (unsigned long long)cmpAddr);
        if (cmpAddr != 0) {
            g_ctx.chatManagerOffset = (uint32_t)hooks->Memory_ReadInt32(cmpAddr + 3);
            logMsg(SPF_LOG_INFO, "[STEP 2] chatManagerOffset = 0x%X", g_ctx.chatManagerOffset);
        } else {
            logMsg(SPF_LOG_WARN, "[STEP 2] chatManagerOffset not resolved");
        }
    } else {
        logMsg(SPF_LOG_WARN, "[STEP 2] Skipping pUIManager lookup because string was not found");
    }

    // --- STEP 3: Register Input Hook ---
    // This hook on FUN_1408a2fa0 allows us to capture the live chat manager instance (RCX).
    // ver. ATS 1.60
    const char* inputHandlerSig = "str:@@mp_chat_no_admin@@";
    logMsg(SPF_LOG_INFO, "[STEP 3] Registering input hook by string: %s", inputHandlerSig);
    hooks->Hook_Register(
        "SPF_ConvoyChatMessaging", "ChatInput", "Captures ChatManager instance",
        (void*)&Detour_ChatInputHandler, (void**)&g_ctx.o_ChatInputHandler, inputHandlerSig, true
    );
    logMsg(SPF_LOG_INFO, "[STEP 3] ChatInput hook registered");

    // --- STEP 4: Keybinds ---
    if (g_ctx.coreAPI->keybinds) {
        g_ctx.keybindsHandle = g_ctx.coreAPI->keybinds->Kbind_GetContext("SPF_ConvoyChatMessaging");
        g_ctx.coreAPI->keybinds->Kbind_Register(g_ctx.keybindsHandle, "MainWindow.toggle", OnToggleMainWindow);
    }

    logMsg(SPF_LOG_INFO, "Convoy Chat Messaging plugin fully activated.");
}

void OnUpdate() {
    // Continuously try to resolve the chat manager instance if not yet captured
    if (g_ctx.chatManagerInstance == nullptr && g_ctx.ppUIManager != nullptr) {
        void* pUIManager = *g_ctx.ppUIManager;
        if (pUIManager != nullptr) {
            // Navigate the object tree: pUIManager -> [Offset] -> ChatManager
            void* resolved = *(void**)((uintptr_t)pUIManager + g_ctx.chatManagerOffset);
            if (resolved != nullptr) {
                g_ctx.chatManagerInstance = resolved;
            }
        }
    }
}

void OnUnload() {
    g_ctx.interceptedLog.clear();
    // Pointers will be nullified by the framework on shutdown.
}

// =================================================================================================
// 3. UI Implementation
// =================================================================================================

void OnRegisterUI(SPF_UI_API* ui_api) {
    if (ui_api) {
        g_ctx.uiAPI = ui_api;
        ui_api->UI_RegisterDrawCallback("SPF_ConvoyChatMessaging", "MainWindow", RenderMainWindow, nullptr);
        g_ctx.mainWindowHandle = ui_api->UI_GetWindowHandle("SPF_ConvoyChatMessaging", "MainWindow");
    }
}

void RenderMainWindow(SPF_UI_API* ui, void* user_data) {
    // --- Header Section ---
    if (g_ctx.chatManagerInstance == nullptr) {
        ui->UI_TextColored(1.0f, 0.4f, 0.4f, 1.0f, ICON_FA_CIRCLE_XMARK " Chat Manager instance not found.");
        ui->UI_TextWrapped("Try to type something in the game chat to capture it via hook.");
    } else {
        ui->UI_TextColored(0.4f, 1.0f, 0.4f, 1.0f, ICON_FA_CIRCLE_CHECK " Chat Manager captured! Ready to send.");
    }
    ui->UI_Separator();

    // --- Configuration Section ---
    ui->UI_Text("Message Parameters:");
    
    // Type Selection (Horizontal Row)
    ui->UI_PushStyleVarVec2(SPF_STYLE_VAR_ITEM_SPACING, 10.0f, 4.0f);
    static int type = 4;
    if (ui->UI_RadioButton("Player (1)", type == 1)) type = 1; ui->UI_SameLine(0, 0);
    if (ui->UI_RadioButton("Local (2)", type == 2)) type = 2; ui->UI_SameLine(0, 0);
    if (ui->UI_RadioButton("Private (3)", type == 3)) type = 3; ui->UI_SameLine(0, 0);
    if (ui->UI_RadioButton("System (4)", type == 4)) type = 4;
    g_ctx.messageType = (uint8_t)type;
    ui->UI_PopStyleVar(1);

    // Sender ID Input
    int sender = (int)g_ctx.customSenderId;
    ui->UI_SetNextItemWidth(150.0f);
    if (ui->UI_InputInt("Sender ID", &sender, 1, 10, SPF_INPUT_TEXT_FLAG_NONE)) {
        g_ctx.customSenderId = (uint16_t)max(0, min(sender, 65535));
    }
    if (ui->UI_IsItemHovered(SPF_HOVERED_FLAG_NONE)) ui->UI_SetTooltip("0: Server, 1: You, >1: Others");

    ui->UI_Checkbox("Route through Input Handler (Enables Commands)", &g_ctx.processAsInput);
    if (ui->UI_IsItemHovered(SPF_HOVERED_FLAG_NONE)) ui->UI_SetTooltip("If enabled, text starting with '/' will be parsed as a command.");

    // --- Message Input ---
    ui->UI_SetNextItemWidth(-1.0f); // Fill width
    ui->UI_InputTextWithHint("##MsgInput", "Enter your message here...", g_ctx.messageBuffer, sizeof(g_ctx.messageBuffer), SPF_INPUT_TEXT_FLAG_NONE);

    if (ui->UI_Button(ICON_FA_PAPER_PLANE " Send Message to Game", -1.0f, 35.0f)) {
        if (strlen(g_ctx.messageBuffer) > 0) {
            SendChatMessage(g_ctx.messageBuffer, g_ctx.messageType, g_ctx.customSenderId);
            g_ctx.messageBuffer[0] = '\0'; // Clear buffer
        }
    }

    // --- History Section ---
    ui->UI_Spacing();
    ui->UI_Separator();
    ui->UI_Text(ICON_FA_LIST " Intercepted Messages (Last 50):");
    ui->UI_SameLine(0, 10);
    if (ui->UI_SmallButton(ICON_FA_TRASH_CAN " Clear Log")) {
        g_ctx.interceptedLog.clear();
    }

    if (ui->UI_BeginTable("HistoryTable", 3, (SPF_TableFlags)(SPF_TABLE_FLAG_BORDERS | SPF_TABLE_FLAG_ROW_BG | SPF_TABLE_FLAG_RESIZABLE), 0, 0, 0)) {
        ui->UI_TableSetupColumn("Sender", SPF_TABLE_COLUMN_FLAG_WIDTH_FIXED, 60.0f, 0);
        ui->UI_TableSetupColumn("Type", SPF_TABLE_COLUMN_FLAG_WIDTH_FIXED, 40.0f, 0);
        ui->UI_TableSetupColumn("Content", SPF_TABLE_COLUMN_FLAG_WIDTH_STRETCH, 0, 0);
        ui->UI_TableHeadersRow();

        for (auto it = g_ctx.interceptedLog.rbegin(); it != g_ctx.interceptedLog.rend(); ++it) {
            ui->UI_TableNextRow(SPF_TABLE_ROW_FLAG_NONE, 0);
            
            ui->UI_TableNextColumn();
            ui->UI_Text(std::to_string(it->senderId).c_str());

            ui->UI_TableNextColumn();
            ui->UI_Text(std::to_string(it->type).c_str());

            ui->UI_TableNextColumn();
            ui->UI_TextWrapped(it->text.c_str());
        }
        ui->UI_EndTable();
    }
}

void OnToggleMainWindow() {
    if (g_ctx.uiAPI && g_ctx.mainWindowHandle) {
        bool visible = g_ctx.uiAPI->UI_IsVisible(g_ctx.mainWindowHandle);
        g_ctx.uiAPI->UI_SetVisibility(g_ctx.mainWindowHandle, !visible);
    }
}

// =================================================================================================
// 4. Detours & Game Logic
// =================================================================================================

void Detour_AddToChat(void* chat_manager, uint16_t sender_id, const char** pp_text, uint8_t message_type) {
    // Intercept and store the message for our UI logger
    if (pp_text && *pp_text) {
        InterceptedMessage msg;
        msg.senderId = sender_id;
        msg.type = message_type;
        msg.text = *pp_text;

        g_ctx.interceptedLog.push_back(msg);
        if (g_ctx.interceptedLog.size() > 50) g_ctx.interceptedLog.erase(g_ctx.interceptedLog.begin());

        // Also log to framework console for deep debugging
        if (g_ctx.formattingAPI) {
            char buf[512];
            g_ctx.formattingAPI->Fmt_Format(buf, sizeof(buf), "[CHAT INTERCEPT] S:%u T:%u Text: %s", sender_id, (uint32_t)message_type, *pp_text);
            g_ctx.coreAPI->logger->Log(g_ctx.loggerHandle, SPF_LOG_DEBUG, buf);
        }
    }

    // Forward the call to the original game function
    if (g_ctx.o_AddToChat) g_ctx.o_AddToChat(chat_manager, sender_id, pp_text, message_type);
}

void Detour_ChatInputHandler(void* chat_manager, const char** pp_text, uint8_t message_type, bool should_broadcast) {
    // Capture the chat manager instance when the player interacts with chat
    if (chat_manager) g_ctx.chatManagerInstance = chat_manager;

    // Pass control back to the game
    if (g_ctx.o_ChatInputHandler) g_ctx.o_ChatInputHandler(chat_manager, pp_text, message_type, should_broadcast);
}

void SendChatMessage(const char* text, uint8_t message_type, uint16_t sender_id) {
    if (!g_ctx.chatManagerInstance) return;

    const char* p_text = text;

    if (g_ctx.processAsInput && g_ctx.o_ChatInputHandler) {
        // Send through input handler (processes commands and net-sync)
        g_ctx.o_ChatInputHandler(g_ctx.chatManagerInstance, &p_text, message_type, true);
    } else if (g_ctx.fnAddToChat) {
        // Direct UI display call (local only, bypasses net-sync)
        g_ctx.fnAddToChat(g_ctx.chatManagerInstance, sender_id, &p_text, message_type);
    }
}

// =================================================================================================
// 5. Exports
// =================================================================================================

extern "C" {
    SPF_PLUGIN_EXPORT bool SPF_GetManifestAPI(SPF_Manifest_API* out_api) {
        if (out_api) { out_api->BuildManifest = BuildManifest; return true; }
        return false;
    }

    SPF_PLUGIN_EXPORT bool SPF_GetPlugin(SPF_Plugin_Exports* exports) {
        if (exports) {
            exports->OnLoad = OnLoad;
            exports->OnActivated = OnActivated;
            exports->OnUnload = OnUnload;
            exports->OnUpdate = OnUpdate;
            exports->OnRegisterUI = OnRegisterUI;
            return true;
        }
        return false;
    }
}

} // namespace SPF_ConvoyChatMessaging
