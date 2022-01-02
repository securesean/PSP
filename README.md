# Personal Security Product

Sean Pierce

As normal computer user, I've always been a little miffed that I don't have a basic awareness of who is remotely accessing/scanning/attacking my machine. So I created this program to simply notify me of the most obvious events I would want to know about.

## How to Run:
- Compile
- Right click and "Run as Admin"

## Features:
- When something attempts to remotely accessing/scanning/attacking my machine a toast notification will notify the user
- Full details are writen to %Programdata%\PSP_Logs
- Supported Events:
   - 4624 - Logon Success
   - 4625 - Logon Failed


## Future Feature Ideas:
- Add default actions to the Toast notifications ('Block IP', 'Start watching for new processes as that user/Service', 'scan for yara sigs', 'Check VT for Exe', 'Launch Autoruns', 'Kill Service', 'Log off user and reset password', etc.)
- Add a better sound for the Toast Notification
- Add icons for the Toast Notification
- Add icons for the Toast Notification buttons - https://docs.microsoft.com/en-us/windows/apps/design/shell/tiles-and-notifications/adaptive-interactive-toasts?tabs=builder-syntax
- Reimplement as a service
- subscribe to events on a remote computer: https://docs.microsoft.com/en-us/previous-versions/bb671202(v=vs.90)?redirectedfrom=MSDN
- Perhaps look at implementing good basic execution rules?
- Perhaps look at what a local sigma instance might look like?

## Credits
Icon from: https://icon-icons.com/download/127074/ICO/512/