<h1 align="center">SPF Convoy Chat Messaging Plugin</h1>

<p align="center">
    <a href=""><img src="https://github.com/user-attachments/assets/59abbd2c-414a-4745-a3cd-5cff4cc8901e" alt="Logo SPF Framework" height="222px" /></a>
</p>

<p align="center">
    <a href="https://github.com/TrackAndTruckDevs/SPF_ConvoyChatMessaging/releases/latest/" target="_blank" title="SPF Convoy Chat Messaging Plugin"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/TrackAndTruckDevs/SPF_ConvoyChatMessaging"></a>
    <a href="/LICENSE" title="SPF Convoy Chat Messaging Plugin license"><img alt="GitHub License" src="https://img.shields.io/github/license/TrackAndTruckDevs/SPF_ConvoyChatMessaging"></a>
</p>

<p align="center">
    <a href="https://www.patreon.com/TrackAndTruckDevs" target="_blank" title="Support us on Patreon"><img alt="Patreon" src="https://img.shields.io/badge/patreon-Becoming a patron-3404021712?style=flat&logo=patreon"></a>
    <a href="https://github.com/TrackAndTruckDevs/SPF_ConvoyChatMessaging/stargazers" title="Liked it? Starred"><img src="https://img.shields.io/github/stars/TrackAndTruckDevs/SPF_ConvoyChatMessaging?style=flat&logo=github" alt="Stars" /></a>
    <a href="https://discord.gg/kadd8AQuMt" target="_blank" title="Join our Discord"><img alt="Discord" src="https://img.shields.io/badge/discord-join-7289da?style=flat&logo=discord&logoColor=white"></a>
    <a href="https://youtube.com/@TrackAndTruck" target="_blank" title="Subscribe to our channel"><img alt="Youtube" src="https://img.shields.io/badge/youtube-subscribe-orange?logo=youtube&style=flat"></a>
</p>

---

A reference plugin for American Truck Simulator and Euro Truck Simulator 2 that demonstrates how to intercept and manipulate the in-game Convoy chat system. **This plugin is primarily intended for educational purposes and research.**

## 🎓 Demonstration Purpose

This project is a high-level example of reverse engineering and plugin development using the SPF-Framework. It showcases:
*   **Signature Scanning**: Finding internal game functions by instruction patterns.
*   **Dynamic Data Extraction**: Extracting global pointers and structure offsets directly from machine code.
*   **Function Hooking**: Intercepting game logic using trampolines to monitor or modify behavior.

## Features

*   **Programmatic Chat Sending**: Send messages to the convoy chat directly from the plugin UI.
*   **Message Type Support**: Test different chat channels: Player (Broad), Local, Private, and System.
*   **Real-time Interception**: Log every incoming and outgoing chat message, including Sender IDs and internal type IDs.
*   **Auto-Capture Logic**: Automatically finds the game's Chat Manager instance using advanced memory scanning.
*   **Integrated Logger**: View the history of intercepted messages within the plugin window.

## Support the Project

If you find this reference plugin useful for your own development, consider supporting us on Patreon.

► **[Support on Patreon](https://www.patreon.com/TrackAndTruckDevs)**

## How to Build 🛠️

This is a standard CMake project. To build it from source:

1.  Clone this repository.
2.  Ensure you have **CMake** and a compatible C++ compiler with the **MSVC toolchain** (e.g., Visual Studio) installed.
3.  Create a `build` directory inside the project folder.
4.  Run CMake from the `build` directory to generate project files (e.g., `cmake ..`).
5.  Build the project using your chosen build tool (e.g., run `cmake --build .`).

## Installation

### Prerequisites

You must have the **SPF Framework** installed for this plugin to work.
*   **[Download the SPF-Framework here](https://github.com/TrackAndTruckDevs/SPF-Framework)**

### Steps

1.  Download the latest release of this plugin.
2.  Copy the `SPF_ConvoyChatMessaging` folder into your game's `\bin\win_x64\plugins\spfPlugins\` directory.

## How to Use

1.  Start the game and enter a **Convoy** session.
2.  Press **`Ctrl + Y`** to open the Convoy Chat Manager window.
3.  **Capture the instance**: The plugin is designed to automatically capture the Chat Manager as soon as you **create or join a Convoy session**. If the status remains red for any reason, simply type any message in the standard game chat to trigger manual capture via the input hook.
4.  **Send Messages**: Enter text, select the message type, and click "Send".
5.  **Monitor Chat**: View all captured messages in the "Intercepted Messages" table.

<h2 align="center">🙏 Acknowledgements</h2>

This project was created using the **[SPF-Framework](https://github.com/TrackAndTruckDevs/SPF-Framework)**, the foundation for modern plugin development in ATS/ETS2.
