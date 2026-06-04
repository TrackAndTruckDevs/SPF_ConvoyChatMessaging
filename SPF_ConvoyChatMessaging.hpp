/**
 * @file SPF_ConvoyChatMessaging.hpp
 * @brief Internal header for the Convoy Chat Messaging plugin.
 * @details This plugin serves as a reference for intercepting and manipulating the 
 * in-game convoy chat system in ETS2/ATS.
 */
#pragma once

#include <SPF_Plugin.h>
#include <SPF_Manifest_API.h>
#include <SPF_Logger_API.h>
#include <SPF_Formatting_API.h>
#include <SPF_KeyBinds_API.h>
#include <SPF_UI_API.h>
#include <SPF_Icons.h>
#include <SPF_Hooks_API.h>

#include <cstdint>
#include <string>
#include <vector>

namespace SPF_ConvoyChatMessaging {

// =================================================================================================
// 1. Game Function Types (Reverse Engineered)
// =================================================================================================

/**
 * @brief Logic for adding a message to the chat display buffer.
 * @details Corresponding to Ghidra: FUN_140805c30.
 * This function handles the final stage of displaying a message in the Route Adviser chat.
 * 
 * @param chat_manager (RCX) The pointer to the multiplayer chat manager instance.
 * @param sender_id    (RDX) The internal ID of the player (1 = Local Player, 0 = Server/Unknown).
 * @param pp_text      (R8)  Pointer to the text string (often a pointer to a prism::string or char*).
 * @param message_type (R9)  The category of the message:
 *                           0: Warning (Red/Orange)
 *                           1: Player (Standard Blue/White)
 *                           2: Local Channel
 *                           3: Private / VTC
 *                           4: System (Yellow/Gray, [chat_system] prefix)
 */
using AddToChat_t = void (*)(void* chat_manager, uint64_t sender_id, const char** pp_text, uint64_t message_type);

/**
 * @brief Handler for processing raw chat input from the user.
 * @details Corresponding to Ghidra: FUN_140804a50.
 * This function is called when the player presses Enter in the chat box. It parses commands 
 * (starting with '/') and handles network broadcasting.
 */
using ChatInputHandler_t = void (*)(void* chat_manager, const char** pp_text, uint64_t message_type, uint64_t should_broadcast);

// =================================================================================================
// 2. Plugin Structures
// =================================================================================================

struct InterceptedMessage {
    uint16_t senderId;
    uint8_t type;
    std::string text;
};

/**
 * @brief Encapsulates all global state for the plugin.
 */
struct PluginContext {
    // --- Framework APIs ---
    const SPF_Load_API* loadAPI = nullptr;
    const SPF_Core_API* coreAPI = nullptr;
    SPF_Logger_Handle* loggerHandle = nullptr;
    const SPF_Formatting_API* formattingAPI = nullptr;
    SPF_UI_API* uiAPI = nullptr;
    SPF_Hooks_API* hooksAPI = nullptr;
    SPF_KeyBinds_Handle* keybindsHandle = nullptr;
    SPF_Window_Handle* mainWindowHandle = nullptr;

    // --- Dynamic Addresses & Offsets ---
    uintptr_t baseAddress = 0;
    AddToChat_t fnAddToChat = nullptr;               // Address used to call the original function
    AddToChat_t o_AddToChat = nullptr;               // Trampoline for the AddToChat hook
    ChatInputHandler_t o_ChatInputHandler = nullptr; // Trampoline for the ChatInputHandler hook

    void** ppGlobalManager = nullptr;                // Pointer to the global game manager (extracted from code)
    uint32_t chatManagerOffset = 0;                  // Offset to the chat manager within the global manager
    void* chatManagerInstance = nullptr;             // The live pointer to the chat manager object

    // --- Plugin Runtime State ---
    char messageBuffer[256] = "";
    uint16_t customSenderId = 1;
    uint8_t messageType = 4;
    bool processAsInput = false;
    std::vector<InterceptedMessage> interceptedLog;
};

extern PluginContext g_ctx;

// =================================================================================================
// 3. Prototypes
// =================================================================================================

void BuildManifest(SPF_Manifest_Builder_Handle* h, const SPF_Manifest_Builder_API* api);
void OnLoad(const SPF_Load_API* load_api);
void OnActivated(const SPF_Core_API* core_api);
void OnUpdate();
void OnUnload();

void OnRegisterUI(SPF_UI_API* ui_api);
void RenderMainWindow(SPF_UI_API* ui, void* user_data);
void OnToggleMainWindow();

// Hook Detours
void Detour_AddToChat(void* chat_manager, uint16_t sender_id, const char** pp_text, uint8_t message_type);
void Detour_ChatInputHandler(void* chat_manager, const char** pp_text, uint8_t message_type, bool should_broadcast);

// Logic
void SendChatMessage(const char* text, uint8_t message_type, uint16_t sender_id);

} // namespace SPF_ConvoyChatMessaging
