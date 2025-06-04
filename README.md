# DPSG - Dynamic PowerShell Script Generator

**Transform natural language descriptions into working PowerShell GUI applications and portable executables.**

DPSG is an AI-powered PowerShell script generator that takes your plain English descriptions and creates complete, functional Windows Forms applications. No coding required - just describe what you want, and DPSG builds it for you.

## 🚀 Features

- **Natural Language Input**: Describe your application in plain English
- **AI-Powered Generation**: Uses OpenAI GPT-4o to create intelligent, context-aware scripts
- **Portable Executables**: Automatically converts scripts to standalone .exe files using ps2exe
- **GUI Interface**: User-friendly Windows Forms interface for easy operation
- **Multiple Modes**: Normal script generation, file loading, script enhancement, and app creation
- **Built-in Templates**: Application examples to get you started
- **Script Enhancement**: Load existing scripts and ask AI to improve, refactor, or explain them
- **No Dependencies**: Generated executables run without requiring PowerShell installation

## 📋 Requirements

- **PowerShell 5.1** or later
- **Windows OS** (Windows Forms dependency)
- **OpenAI API Key** (get one from [OpenAI Platform](https://platform.openai.com/api-keys))
- **ps2exe module** (auto-installed when needed)

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/DPSG.git
   cd DPSG
   ```

2. **Set up your OpenAI API key**:
   ```powershell
   # Option 1: Set as environment variable (recommended)
   [Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "your-api-key-here", "User")
   
   # Option 2: Set for current session only
   $env:OPENAI_API_KEY = "your-api-key-here"
   ```

3. **Run DPSG**:
   ```powershell
   .\DPSG.ps1 -GUI
   ```

## 🎯 Usage

### GUI Mode (Recommended)
```powershell
.\DPSG.ps1 -GUI
```

### Command Line Mode
```powershell
# Interactive mode
.\DPSG.ps1 -Interactive

# Direct prompt
.\DPSG.ps1 -PromptFile "prompt.txt"

# Specify model and parameters
.\DPSG.ps1 -GUI -Model "gpt-4o" -MaxTokens 4000
```

### Available Modes

1. **Normal**: Generate PowerShell scripts from descriptions
2. **Load File**: Load existing scripts for enhancement
3. **Ask**: Enhance, refactor, summarize, or explain loaded scripts
4. **Create App**: Generate portable .exe applications

## 💡 Examples

### Creating a File Manager Application
```
Description: "File manager with tree view, copy/move operations, search functionality, and bulk file operations"
```

### Creating a System Monitor
```
Description: "System monitoring tool showing CPU, memory, disk usage with real-time graphs and alerts"
```

### Creating a Network Scanner
```
Description: "Network scanner that pings IP ranges, shows open ports, and exports results to CSV"
```

### Script Enhancement
1. Load an existing PowerShell script using "Load File"
2. Switch to "Ask" mode
3. Enter enhancement request: "Add error handling and improve performance"

## ⚙️ Configuration

### API Key Setup
The script checks for your OpenAI API key in this order:
1. Command line parameter (`-ApiKey`)
2. Process environment variable (`$env:OPENAI_API_KEY`)
3. User environment variable
4. Machine environment variable
5. Interactive prompt (if not found)

### Model Selection
Default model is `gpt-4o`. You can specify different models:
- `gpt-4o` (recommended)
- `gpt-4-turbo`
- `gpt-3.5-turbo`

### Output Customization
- **Generated scripts**: Saved as `.ps1` files
- **Executables**: Automatically converted to `.exe` using ps2exe
- **Backup**: Original scripts preserved during conversion

## 🔧 Troubleshooting

### Common Issues

**API Key Not Found**
- Ensure your API key is set as an environment variable
- Check the key format (should start with `sk-` or `sk-proj-`)
- Verify the key is active on OpenAI platform

**ps2exe Module Issues**
- Module auto-installs when needed
- Manual install: `Install-Module ps2exe -Scope CurrentUser`
- Run PowerShell as Administrator if needed

**Generated Script Errors**
- Scripts are syntax-validated before compilation
- Check the output log for specific error details
- Try simplifying your description if generation fails

**Executable Creation Fails**
- Ensure ps2exe module is properly installed
- Check that Windows Defender isn't blocking the conversion
- PowerShell script (.ps1) is always created as fallback

### Debug Mode
Enable verbose logging by checking the live log window in GUI mode, or run with detailed error reporting.

## 📚 Advanced Features

### Template System
- Use "Insert Application Example" for pre-built templates
- Templates serve as starting points for complex applications
- Custom templates can be added to the `Get-ApplicationTemplates` function

### Script Enhancement Modes
- **Enhance**: Improve performance, add features, fix issues
- **Refactor**: Reorganize code for better readability
- **Summarize**: Get concise explanations of script functionality
- **Explain**: Detailed breakdown of script operations

### Batch Processing
Load and enhance multiple scripts by switching between Load File and Ask modes.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OpenAI** for providing the GPT API
- **ps2exe** module by Ingo Karstein and Markus Scholtes
- **PowerShell Community** for inspiration and best practices

## 📞 Support

For issues, feature requests, or questions:
- Open an [Issue](https://github.com/yourusername/DPSG/issues)
- Check existing issues for solutions
- Provide detailed error logs when reporting bugs

---

**⭐ Star this repository if DPSG helps you create amazing PowerShell applications!**
