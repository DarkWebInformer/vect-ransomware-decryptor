This tool decrypts files encrypted by VECT ransomware at no cost.

REQUIREMENTS (to run recovery)
- Encryptor binary (the malware executable, same strain that locked the files)
- At least one encrypted sample file (.vect1)
- Usually a Windows PC where the infected files live (paths below use Windows-style names)

REQUIREMENTS (to compile from source)
- Go toolchain (see go.mod for the minimum version)
- Network once, so Go can fetch dependencies when you build

BUILD
1. Copy or clone this decryptor folder onto your machine.
2. Open a terminal in that folder (on Windows: Command Prompt or PowerShell, cd into the folder).
3. Fetch modules and compile:

       go build -o vect1_decryptor.exe .

   On Linux or macOS the binary name omits ".exe"; use any name you like.

4. You should now have vect1_decryptor.exe (or vect1_decryptor) in that folder.

   To produce a Windows .exe from another OS when Go cross-build is configured:

       GOOS=windows GOARCH=amd64 go build -o vect1_decryptor.exe .

USAGE

The tool is a command-line program. Put the ransomware EXE somewhere you can reference, collect your .vect1 files under one directory, then run ONE of these patterns from a terminal opened in any directory (adjust paths accordingly).

Easiest mode: recover key from your binary plus one sample under -target and decrypt everything .vect1 under that folder:

    vect1_decryptor.exe auto -binary C:\Recovery\encryptor.exe -target D:\EncryptedFiles [-backup] [-hexdump]

  "-backup" saves a ".vect1.bak" copy before overwriting.
  "-hexdump" prints a short byte preview for troubleshooting.

Step-by-step (same folder shortcut)

1. Copy vect1_decryptor.exe and the ransomware exe into one folder.

2. Put your encrypted (.vect1) files in that folder, or anywhere under one parent folder; that parent is what you give as "-target".

3. Open Command Prompt or PowerShell, change to wherever you stored the tools, run auto with paths you actually use:

    cd C:\Recovery
    vect1_decryptor.exe auto -binary name_of_encryptor.exe -target .

4. The program reads the ransomware binary for the key using an encrypted sample it finds under -target, then decrypts all .vect1 files there and strips the ".vect1" extension from their names.

Other commands

  Extract key only (prints hex):

    vect1_decryptor.exe extract-key -binary encryptor.exe -sample file.docx.vect1 [-out key.txt]

  Decrypt later if you already have the hex key (64 hex characters = 32 bytes):

    vect1_decryptor.exe decrypt -target D:\EncryptedFiles -key <hex64> [-backup] [-hexdump]

Need help?

    vect1_decryptor.exe

with no arguments prints the brief built-in syntax.

-- SHHQ Ransomware Response & Recovery Unit (RRU)
