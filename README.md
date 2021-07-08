# WindowsToolbox-Auto
WindowsToolbox but automatic, intended for post-install and first boot setup.


## DISCLAMER:

This software is in beta. **All scripts are provided as-is and you use them at your own risk. WinTweakers are NOT responsible for ANY damage caused by these scripts. These scripts is only ment for system administrators who know what they're doing. Please read README before proceeding**

# Usage

**You have to at least edit main.ps1 before using since all functions are enabled by default**


Comment out the function that you don't want to run. E.g: DisableWindowsDefender -> #DisableWindowsDefender

For post-install after first boot purposes: extract this repo to your install image under "%WINDIR%\Setup\Scripts" 

For more infomation about Windows Setup, go to [Microsoft's documentation](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-a-custom-script-to-windows-setup)

## Liability

**All scripts are provided as-is and you use them at your own risk.**

## Contributing

Contributions are welcome, just make a pull request and we'll accept it if it's actually helpful.

## License

Copyright (c) 2021 WinTweakers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
