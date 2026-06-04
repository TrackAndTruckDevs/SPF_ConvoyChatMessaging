/**
 * @file SPF_ConvoyChatMessaging.cpp
 * @brief Professional implementation of the Convoy Chat Messaging plugin.
 * @details This plugin demonstrates advanced reverse engineering techniques:
 * 1. Finding game functions by unique instruction patterns (Signatures).
 * 2. Dynamically extracting global variable addresses and struct offsets from machine code.
 * 3. Intercepting game logic using function hooking with trampolines.
 */

#include "SPF_ConvoyChatMessaging.hpp"
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

    // --- STEP 1: Find the AddToChat function (Visual logic) ---
    // This signature matches the prologue of FUN_140805c30.
    // It is used to display messages in the local chat window.
    // 48 89 5C 24 08 44 88 4C 24 20 66 89 54 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 80 F8 FF FF ver. ATS 1.59.2
    const char* addToChatSig = "48 89 ? ? ? 44 88 ? ? ? 66 89 ? ? ? ? ? ? ? ? ? ? ? ? ? ? 48 8D";
    g_ctx.fnAddToChat = (AddToChat_t)hooks->Hook_FindPattern(addToChatSig);

    if (g_ctx.fnAddToChat) {
        // We install a hook to intercept INCOMING messages from other players or the game itself.
        hooks->Hook_Register(
            "SPF_ConvoyChatMessaging", "ChatIntercept", "Intercepts messages before display",
            (void*)&Detour_AddToChat, (void**)&g_ctx.o_AddToChat, addToChatSig, true
        );
    }

    // --- STEP 2: Extract Global Manager Address & Offset ---
    // We search for a specific code block in FUN_14080ecc0 that accesses the Multiplayer Manager.
    // Signature: MOV RSI, [GlobalMgr]; LEA RDX, [String]; ... ; CMP [RSI+Offset], RAX
    // 48 8b 35 da 6f bb 02 48 8d 15 4b 3f 81 01 48 89 54 24 38 48 39 86 40 02 00 00 0f 84 de 00 00 00 48 8d 95 78 03 00 00  ver. ATS 1.59.2
    const char* managerFinderSig = "48 8b ? ? ? ? ? 48 ? ? ? ? ? ? 48 89 ? ? ? 48 39 86 ? ? ? ? 0f 84 ? ? ? ? 48 ? ? ? ? ? ? 48";
    uintptr_t finderAddr = hooks->Hook_FindPattern(managerFinderSig);
    if (finderAddr != 0) {
        // First instruction (7 bytes): 48 8B 35 [offset_32] -> Extract RIP-relative address of ppGlobalManager
        g_ctx.ppGlobalManager = (void**)hooks->Memory_GetRipAddress(finderAddr, 3, 7);
        
        // Fourth instruction (+19 bytes): 48 39 86 [offset_32] -> Extract 32-bit offset to ChatManager
        g_ctx.chatManagerOffset = *(uint32_t*)(finderAddr + 19 + 3);
    }

    // --- STEP 3: Register Input Hook ---
    // This hook on FUN_140804a50 allows us to capture the live chat manager instance (RCX).
    // 48 89 7c 24 20 55 41 54 41 55 41 56 41 57 48 8b ec 48 81 ec 80 00 00 00 48 8b 3a 49 c7 c6 ff ff ff ff 49 8b c6   ver. ATS 1.59.2
    const char* inputHandlerSig = "48 89 7C ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 48 8B ? 49 c7 ? ? ? ? ? 49";
    hooks->Hook_Register(
        "SPF_ConvoyChatMessaging", "ChatInput", "Captures ChatManager instance",
        (void*)&Detour_ChatInputHandler, (void**)&g_ctx.o_ChatInputHandler, inputHandlerSig, true
    );

    // --- STEP 4: Keybinds ---
    if (g_ctx.coreAPI->keybinds) {
        g_ctx.keybindsHandle = g_ctx.coreAPI->keybinds->Kbind_GetContext("SPF_ConvoyChatMessaging");
        g_ctx.coreAPI->keybinds->Kbind_Register(g_ctx.keybindsHandle, "MainWindow.toggle", OnToggleMainWindow);
    }

    g_ctx.loadAPI->logger->Log(g_ctx.loggerHandle, SPF_LOG_INFO, "Convoy Chat Messaging plugin fully activated.");
}

void OnUpdate() {
    // Continuously try to resolve the chat manager instance if not yet captured
    if (g_ctx.chatManagerInstance == nullptr && g_ctx.ppGlobalManager != nullptr) {
        void* pGlobal = *g_ctx.ppGlobalManager;
        if (pGlobal != nullptr) {
            // Navigate the object tree: GameManager -> [Offset] -> ChatManager
            void* resolved = *(void**)((uintptr_t)pGlobal + g_ctx.chatManagerOffset);
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
