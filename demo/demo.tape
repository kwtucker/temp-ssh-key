Output demo.gif

Require temp-ssh-key
Require ssh-keygen

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 800
Set Padding 20
Set Theme "Catppuccin Frappe"
Set WindowBar Colorful
Set TypingSpeed 70ms
Set CursorBlink false

Hide
Type "export PS1='demo> '"
Enter
Type "clear"
Enter
Show

Type "temp-ssh-key --version"
Enter
Sleep 500ms

Type "# demo only: unencrypted key, never authorized"
Enter
Sleep 300ms

Type "temp-ssh-key start --format qr --allow-unencrypted --shell bash --name Demo --email demo@example.com"
Enter
Enter
Sleep 8s

Type "temp-ssh-key cleanup --dry-run"
Enter
Enter
Sleep 8s

Type "temp-ssh-key cleanup"
Enter
Sleep 500ms
Type "y"
Enter
Sleep 300ms
Type "y"
Enter
Enter
Sleep 4s

Type "unset KEY_DIR KEY KEY_FINGERPRINT"
Enter
Sleep 300ms
Type "exit"
Enter
Sleep 8s
