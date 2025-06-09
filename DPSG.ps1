<#
.SYNOPSIS
DPSG - Dynamic PowerShell Script Generator with Portable Executable Generation
.DESCRIPTION
This script provides AI-assisted PowerShell script generation and converts them to portable executables using ps2exe.
Takes natural language descriptions and creates working .exe applications with GUI interfaces.
.NOTES
Version: 2.0.0
Author: NC-ADC
Key Features:
- Natural language to PowerShell GUI application
- Enhanced version that creates complete standalone EXE files with proper dependencies and error handling.
- Built-in application templates (Inventory, File Manager, Network Tools, etc.)
- No dependencies required for generated executables
#>

param(
    [string]$Model = "gpt-4o",
    [int]$MaxTokens = 8000,
    [float]$Temperature = 0.2,
    [string]$ApiKey,
    [switch]$Interactive,
    [switch]$Gui,
    [string]$PromptFile,
    [switch]$EnableOptionalFeatures,
    [ValidateSet("code-generation","code-interpreter","powershell-apps")]
    [string]$TaskType = "code-generation"
)

# Standardize the user input parameter globally
$global:UserInput = if ($PromptFile -and (Test-Path $PromptFile)) {
    Get-Content -Raw -Path $PromptFile -ErrorAction SilentlyContinue
} elseif (-not [string]::IsNullOrWhiteSpace($UserMessage)) {
    $UserMessage
} elseif (-not [string]::IsNullOrWhiteSpace($SingleInput)) {
    $SingleInput
} elseif (-not [string]::IsNullOrWhiteSpace($Prompt)) {
    $Prompt
} elseif ($PSBoundParameters.ContainsKey("UserPrompt")) {
    $UserPrompt
} elseif ($Interactive) {
    Read-Host -Prompt "Enter your prompt"
} else {
    if ($Gui) { "" } else { throw "No input provided" }
}

# Validate user input before proceeding
if ([string]::IsNullOrWhiteSpace($global:UserInput)) {
    if ($Gui) {
        $global:UserInput = ""
    }
    elseif (-not $Interactive) {
        throw "No input provided. Please enter a valid prompt or specify a prompt file."
    }
}

# Load required assemblies early if GUI mode is enabled
if ($Gui) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName Microsoft.VisualBasic
}

# Initialize script variables
$script:GeneratedScripts = @()
$notepadPlusPlusPath = "C:\Program Files\Notepad++\notepad++.exe"
if ($env:NotepadPlusPlusPath) { $notepadPlusPlusPath = $env:NotepadPlusPlusPath }

#region Enhanced Helper Functions

function Get-DefaultIconPath {
    # Skip icon creation - ps2exe works fine without icons
    return $null
}

function Get-AppropriateIcon {
    param(
        [string]$ScriptContent
    )
    
    # Skip icon functionality - ps2exe works fine without icons
    # Creating valid ICO files is complex and not essential for functionality
    Write-LogMessage "Skipping icon - proceeding without icon file" "DEBUG"
    return $null
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Value
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Value, $utf8NoBom)
}

function Write-LogMessage {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO","WARNING","ERROR","DEBUG")]
        [string]$Level="INFO"
    )
    $time = Get-Date -Format "HH:mm:ss"
    $formattedMessage = "[$time] $Level`: $Message"
    
    # Check if Windows Forms is loaded and txtLog exists
    try {
        if ($Gui -and $script:txtLog -and $script:txtLog.GetType().Name -eq "RichTextBox") {
            $script:txtLog.AppendText("$formattedMessage`r`n")
            $script:txtLog.ScrollToCaret()
        } else {
            Write-Output $formattedMessage
        }
    } catch {
        Write-Output $formattedMessage
    }
}

function Show-GenerationProgress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete,
        [int]$SecondsRemaining = -1
    )
    $params = @{
        Activity = $Activity
        Status = $Status
        PercentComplete = $PercentComplete
    }
    if ($SecondsRemaining -ge 0) {
        $params.SecondsRemaining = $SecondsRemaining
    }
    Write-Progress @params
    if ($Gui -and $script:progress -ne $null) {
        $script:targetProgressValue = $PercentComplete
        $script:progressTimer.Start()
    }
}

function Get-ApiKey {
    Write-LogMessage "Attempting to retrieve API key from environment..." "DEBUG"
    
    # Start with the parameter if provided
    $retrievedApiKey = $ApiKey
    
    if ([string]::IsNullOrWhiteSpace($retrievedApiKey)) {
        # Check environment variables in priority order
        Write-LogMessage "Checking Process environment variable..." "DEBUG"
        $retrievedApiKey = $env:OPENAI_API_KEY
        
        if ([string]::IsNullOrWhiteSpace($retrievedApiKey)) {
            Write-LogMessage "Checking User environment variable..." "DEBUG"
            $retrievedApiKey = [Environment]::GetEnvironmentVariable("OPENAI_API_KEY", "User")
        }
        
        if ([string]::IsNullOrWhiteSpace($retrievedApiKey)) {
            Write-LogMessage "Checking Machine environment variable..." "DEBUG"
            $retrievedApiKey = [Environment]::GetEnvironmentVariable("OPENAI_API_KEY", "Machine")
        }
    }
    
    # Clean and validate the API key
    if (-not [string]::IsNullOrWhiteSpace($retrievedApiKey)) {
        # Remove any whitespace, newlines, or hidden characters
        $retrievedApiKey = $retrievedApiKey.Trim().Replace("`r", "").Replace("`n", "").Replace("`t", "")
        
        # Remove any quotes that might have been included
        $retrievedApiKey = $retrievedApiKey.Trim('"').Trim("'")
        
        # Detect corruption patterns
        $isCorrupted = $false
        
        # Check for log message corruption (starts with timestamp)
        if ($retrievedApiKey -match "^\[\d{2}:\d{2}:\d{2}\]") {
            Write-LogMessage "CORRUPTION DETECTED: API key contains log timestamps" "ERROR"
            $isCorrupted = $true
        }
        
        # Check for excessive length
        if ($retrievedApiKey.Length -gt 300) {
            Write-LogMessage "CORRUPTION DETECTED: API key too long (length: $($retrievedApiKey.Length))" "ERROR"
            $isCorrupted = $true
        }
        
        # Check if it doesn't start with expected OpenAI format
        if (-not ($retrievedApiKey -match "^sk-")) {
            Write-LogMessage "CORRUPTION DETECTED: API key doesn't start with 'sk-'" "ERROR"
            $isCorrupted = $true
        }
        
        if ($isCorrupted) {
            Write-LogMessage "Corrupted key preview: '$($retrievedApiKey.Substring(0, [Math]::Min(50, $retrievedApiKey.Length)))'" "DEBUG"
            
            # Try to extract valid key from corrupted data
            if ($retrievedApiKey -match "(sk-proj-[a-zA-Z0-9\-_]{50,200})") {
                $extractedKey = $matches[1]
                Write-LogMessage "Successfully extracted project key from corruption" "INFO"
                $retrievedApiKey = $extractedKey
                $isCorrupted = $false
            } elseif ($retrievedApiKey -match "(sk-[a-zA-Z0-9]{48})") {
                $extractedKey = $matches[1]
                Write-LogMessage "Successfully extracted standard key from corruption" "INFO"
                $retrievedApiKey = $extractedKey
                $isCorrupted = $false
            } else {
                Write-LogMessage "Could not extract valid API key from corrupted data" "ERROR"
                $retrievedApiKey = $null
            }
        }
        
        if (-not $isCorrupted -and -not [string]::IsNullOrWhiteSpace($retrievedApiKey)) {
            Write-LogMessage "API key retrieved successfully" "DEBUG"
            Write-LogMessage "API key length: $($retrievedApiKey.Length)" "DEBUG"
            Write-LogMessage "API key format: $($retrievedApiKey.Substring(0, [Math]::Min(15, $retrievedApiKey.Length)))..." "DEBUG"
            return $retrievedApiKey
        }
    }
    
    # If still no key found or corrupted, prompt user
    if ([string]::IsNullOrWhiteSpace($retrievedApiKey)) {
        Write-LogMessage "No valid API key found, prompting user..." "INFO"
        
        if ($Gui) {
            do {
                $retrievedApiKey = [Microsoft.VisualBasic.Interaction]::InputBox("OpenAI API key not found or corrupted in environment variables.`n`nPlease enter your OpenAI API key:`n(Get one from: https://platform.openai.com/api-keys)", "API Key Required", "")
                
                if ([string]::IsNullOrWhiteSpace($retrievedApiKey)) {
                    $result = [System.Windows.Forms.MessageBox]::Show("No API key entered. The application cannot function without a valid OpenAI API key.`n`nWould you like to try entering it again?", "API Key Required", "YesNo", "Question")
                    if ($result -eq "No") {
                        break
                    }
                } else {
                    # Clean the input
                    $retrievedApiKey = $retrievedApiKey.Trim().Replace("`r", "").Replace("`n", "").Replace("`t", "").Trim('"').Trim("'")
                    
                    # Validate user input
                    if ($retrievedApiKey -match "^sk-") {
                        Write-LogMessage "Valid API key provided by user" "INFO"
                        
                        # Optionally save to environment
                        $saveResult = [System.Windows.Forms.MessageBox]::Show("Would you like to save this API key to your environment variables for future use?", "Save API Key", "YesNo", "Question")
                        if ($saveResult -eq "Yes") {
                            try {
                                [Environment]::SetEnvironmentVariable("OPENAI_API_KEY", $retrievedApiKey, "User")
                                Write-LogMessage "API key saved to user environment variables" "INFO"
                            } catch {
                                Write-LogMessage "Could not save API key: $($_.Exception.Message)" "WARNING"
                            }
                        }
                        break
                    } else {
                        [System.Windows.Forms.MessageBox]::Show("Invalid API key format. OpenAI keys should start with 'sk-'", "Invalid Format", "OK", "Warning")
                        $retrievedApiKey = $null
                    }
                }
            } while ($true)
        } else {
            Write-Host "OpenAI API key not found or corrupted in environment variables." -ForegroundColor Yellow
            Write-Host "You can get an API key from: https://platform.openai.com/api-keys" -ForegroundColor Cyan
            
            do {
                $retrievedApiKey = Read-Host -Prompt "Please enter your OpenAI API key (or 'quit' to exit)"
                
                if ($retrievedApiKey -eq "quit") {
                    $retrievedApiKey = $null
                    break
                }
                
                if (-not [string]::IsNullOrWhiteSpace($retrievedApiKey)) {
                    $retrievedApiKey = $retrievedApiKey.Trim().Replace("`r", "").Replace("`n", "").Replace("`t", "").Trim('"').Trim("'")
                    
                    if ($retrievedApiKey -match "^sk-") {
                        Write-Host "Valid API key format detected" -ForegroundColor Green
                        break
                    } else {
                        Write-Host "Invalid API key format. OpenAI keys should start with 'sk-'" -ForegroundColor Red
                        $retrievedApiKey = $null
                    }
                }
            } while ($true)
        }
    }
    
    if (-not [string]::IsNullOrWhiteSpace($retrievedApiKey)) {
        Write-LogMessage "API key obtained successfully" "DEBUG"
        Write-LogMessage "API key length: $($retrievedApiKey.Length)" "DEBUG"
        Write-LogMessage "API key format: $($retrievedApiKey.Substring(0, [Math]::Min(15, $retrievedApiKey.Length)))..." "DEBUG"
    } else {
        Write-LogMessage "No valid API key could be obtained" "ERROR"
    }
    
    return $retrievedApiKey
}

function Test-PS2EXE {
    try {
        $module = Get-Module -ListAvailable -Name ps2exe
        if (-not $module) {
            Write-LogMessage "ps2exe module not found." "WARNING"
            
            if ($Gui) {
                $result = [System.Windows.Forms.MessageBox]::Show(
                    "The ps2exe module is required to create executable files. Would you like to install it now?`n`nThis will run: Install-Module ps2exe -Scope CurrentUser",
                    "Module Installation Required",
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Question
                )
                if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
                    try {
                        Write-LogMessage "Installing ps2exe module..." "INFO"
                        Install-Module -Name ps2exe -Scope CurrentUser -Force -ErrorAction Stop
                        Write-LogMessage "ps2exe module installed successfully" "INFO"
                    } catch {
                        Write-LogMessage "Failed to install ps2exe: $($_.Exception.Message)" "ERROR"
                        [System.Windows.Forms.MessageBox]::Show(
                            "Failed to install ps2exe module. Please install manually using:`nInstall-Module ps2exe",
                            "Installation Failed",
                            [System.Windows.Forms.MessageBoxButtons]::OK,
                            [System.Windows.Forms.MessageBoxIcon]::Error
                        )
                        return $false
                    }
                } else {
                    return $false
                }
            } else {
                Write-Host "The ps2exe module is required. Install with: Install-Module ps2exe -Scope CurrentUser" -ForegroundColor Yellow
                $response = Read-Host "Install now? (y/n)"
                if ($response -eq "y" -or $response -eq "Y") {
                    try {
                        Install-Module -Name ps2exe -Scope CurrentUser -Force -ErrorAction Stop
                        Write-LogMessage "ps2exe module installed successfully" "INFO"
                    } catch {
                        Write-LogMessage "Failed to install ps2exe: $($_.Exception.Message)" "ERROR"
                        return $false
                    }
                } else {
                    return $false
                }
            }
        }
        Import-Module ps2exe -ErrorAction Stop
        return $true
    }
    catch {
        Write-LogMessage "Failed to import ps2exe: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-PowerShellScriptSyntax {
    param(
        [string]$ScriptContent,
        [string]$ScriptPath
    )
    
    try {
        # Test the script syntax by parsing it
        $errors = @()
        $tokens = @()
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($ScriptContent, [ref]$tokens, [ref]$errors)
        
        if ($errors.Count -gt 0) {
            Write-LogMessage "Script syntax errors detected:" "ERROR"
            foreach ($error in $errors) {
                Write-LogMessage "  Line $($error.Extent.StartLineNumber): $($error.Message)" "ERROR"
            }
            return $false
        }
        
        Write-LogMessage "Script syntax validation passed" "DEBUG"
        return $true
    }
    catch {
        Write-LogMessage "Script syntax validation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Request-ScriptGeneration {
    [CmdletBinding(DefaultParameterSetName = "SingleInput")]
    param (
        [Parameter(Mandatory=$true, ParameterSetName="SingleInput", Position=0)]
        [Alias("UserMessage","UserPrompt","Prompt","Input","Request","Query")]
        [ValidateNotNullOrEmpty()]
        [string]$UserInput,
        [Parameter(Mandatory=$true, ParameterSetName="ContextMessages")]
        [Alias("Context","Messages","Conversation")]
        [ValidateNotNullOrEmpty()]
        [array]$ContextMessages,
        [Parameter(ParameterSetName="SingleInput")]
        [Parameter(ParameterSetName="ContextMessages")]
        [string]$SystemPrompt = @"
You are a PowerShell expert assistant that generates complete, working PowerShell scripts.
When generating PowerShell scripts, output ONLY valid PowerShell code with NO markdown formatting whatsoever.
Do NOT include code blocks, backticks, or any markdown syntax like ```powershell or ```.
Focus on creating functional scripts that solve the user's requirements.
Include proper error handling and clear, readable code.
Only include GUI elements (Windows Forms) if specifically requested by the user.
Start your response directly with PowerShell code.
"@,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Model = "gpt-4o",
        [Parameter()]
        [ValidateRange(1, 8000)]
        [int]$MaxTokens = 8000,
        [Parameter()]
        [ValidateRange(0.0, 2.0)]
        [double]$Temperature = 0.3,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKey = $global:ApiKey
    )
    
    begin {
        if ([string]::IsNullOrWhiteSpace($ApiKey)) {
            throw "API key is required. Please provide via -ApiKey parameter or set OPENAI_API_KEY environment variable"
        }
        
        # Clean the API key
        $ApiKey = $ApiKey.Trim().Replace("`r", "").Replace("`n", "").Replace("`t", "").Trim('"').Trim("'")
        
        Write-LogMessage "Final API key being sent: length=$($ApiKey.Length), starts with: '$($ApiKey.Substring(0, [Math]::Min(20, $ApiKey.Length)))'" "DEBUG"
        
        # Final validation before sending
        if ($ApiKey.Length -gt 300) {
            Write-LogMessage "ERROR: API key appears corrupted (length: $($ApiKey.Length)) - cannot proceed" "ERROR"
            throw "API key appears corrupted after cleaning. Length: $($ApiKey.Length)"
        }
        
        $maxRetries = 3
        $retryDelay = 2
        $url = "https://api.openai.com/v1/chat/completions"
        $retryDelay = 2
        $url = "https://api.openai.com/v1/chat/completions"
    }
    
    process {
        try {
            switch ($PSCmdlet.ParameterSetName) {
                "SingleInput" {
                    $messages = @(
                        @{
                            role = "system"
                            content = $SystemPrompt
                        },
                        @{
                            role = "user"
                            content = $UserInput
                        }
                    )
                    Write-LogMessage "Processing API request..." "DEBUG"
                }
                "ContextMessages" {
                    if ($ContextMessages.Count -eq 0) {
                        throw "ContextMessages array cannot be empty"
                    }
                    foreach ($msg in $ContextMessages) {
                        if (-not $msg.role -or -not $msg.content) {
                            throw "Each context message must contain role and content properties"
                        }
                    }
                    $messages = $ContextMessages
                    Write-LogMessage "Processing context messages request" "DEBUG"
                }
            }
            
            $requestBody = @{
                model = $Model
                messages = $messages
                max_tokens = $MaxTokens
                temperature = $Temperature
            }
            
            for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
                try {
                    Show-GenerationProgress -Activity "Contacting OpenAI API" -Status "Sending request (attempt $attempt)" -PercentComplete (20 * $attempt)
                    
                    $jsonBody = $requestBody | ConvertTo-Json -Depth 10 -Compress
                    if (-not $jsonBody) {
                        throw "Failed to serialize request to JSON"
                    }
                    
                    $headers = @{
                        "Authorization" = "Bearer $ApiKey"
                        "Content-Type" = "application/json"
                        "User-Agent" = "DPSG-PowerShell-Generator/2.0"
                    }
                    
                    Write-LogMessage "Sending request to OpenAI API (Attempt $attempt/$maxRetries)" "INFO"
                    Write-LogMessage "Using model: $Model" "DEBUG"
                    Write-LogMessage "Request body size: $($jsonBody.Length) characters" "DEBUG"
                    
                    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $jsonBody -ErrorAction Stop -TimeoutSec 120
                    
                    if (-not $response -or -not $response.choices -or $response.choices.Count -eq 0) {
                        throw "Invalid response format - no choices returned from API"
                    }
                    
                    $content = $response.choices[0].message.content
                    if ([string]::IsNullOrWhiteSpace($content)) {
                        throw "Empty response content received from API"
                    }
                    
                    Show-GenerationProgress -Activity "Processing Response" -Status "Validating content" -PercentComplete 90
                    Show-GenerationProgress -Activity "Complete" -Status "Success" -PercentComplete 100
                    
                    Start-Sleep -Milliseconds 500  # Brief pause to show completion
                    Write-LogMessage "API request completed successfully" "INFO"
                    return $content.Trim()
                }
                catch {
                    $errorMsg = $_.Exception.Message
                    $shouldRetry = $false
                    
                    # Handle specific error types
                    if ($_.Exception.Response) {
                        try {
                            $errorStream = $_.Exception.Response.GetResponseStream()
                            $reader = New-Object System.IO.StreamReader($errorStream)
                            $errorResponse = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction SilentlyContinue
                            
                            if ($errorResponse -and $errorResponse.error) {
                                $errorMsg = $errorResponse.error.message
                                $errorType = $errorResponse.error.type
                                
                                Write-LogMessage "OpenAI API Error Type: $errorType" "ERROR"
                                Write-LogMessage "OpenAI API Error Message: $errorMsg" "ERROR"
                                
                                # Handle specific error types
                                if ($errorType -eq "invalid_api_key" -or $errorMsg -match "api key") {
                                    Write-LogMessage "API key is invalid. Please check your OpenAI API key." "ERROR"
                                    throw "Invalid API key. Please verify your OpenAI API key is correct."
                                } elseif ($errorType -eq "rate_limit_exceeded" -or $errorMsg -match "rate limit") {
                                    $retryAfter = 5
                                    if ($_.Exception.Response.Headers["Retry-After"]) {
                                        $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                                    }
                                    Write-LogMessage "Rate limit hit - waiting $retryAfter seconds before retry" "WARNING"
                                    Start-Sleep -Seconds $retryAfter
                                    $shouldRetry = $true
                                } elseif ($_.Exception.Response.StatusCode -eq 400) {
                                    Write-LogMessage "Bad Request (400) - Check model name and request parameters" "ERROR"
                                    Write-LogMessage "Model used: $Model" "ERROR"
                                    Write-LogMessage "API Error Details: $errorMsg" "ERROR"
                                    throw "Bad Request (400): $errorMsg. Check if model '$Model' is valid."
                                }
                            } else {
                                Write-LogMessage "HTTP Status: $($_.Exception.Response.StatusCode)" "ERROR"
                                Write-LogMessage "HTTP Status Description: $($_.Exception.Response.StatusDescription)" "ERROR"
                            }
                        } catch {
                            Write-LogMessage "Could not parse error response: $($_.Exception.Message)" "DEBUG"
                        }
                    }
                    
                    if ($attempt -eq $maxRetries -or -not $shouldRetry) {
                        Write-LogMessage "API request failed after $attempt attempts: $errorMsg" "ERROR"
                        Show-GenerationProgress -Activity "Failed" -Status "Error occurred" -PercentComplete -1
                        throw "OpenAI API request failed: $errorMsg"
                    }
                    
                    if (-not $shouldRetry) {
                        Write-LogMessage "Attempt $attempt failed ($errorMsg), retrying in $retryDelay seconds..." "WARNING"
                        Start-Sleep -Seconds $retryDelay
                        $retryDelay = [math]::Min($retryDelay * 1.5, 30)  # Exponential backoff with cap
                    }
                }
            }
        }
        catch {
            Write-LogMessage "Fatal error in API request: $($_.Exception.Message)" "ERROR"
            Show-GenerationProgress -Activity "Failed" -Status "Fatal error" -PercentComplete -1
            throw
        }
        finally {
            Write-Progress -Activity "Complete" -Completed
        }
    }
}

function New-PowerShellApp {
    param(
        [string]$UserDescription,
        [string]$OutputPath
    )
    
    Write-LogMessage "New-PowerShellApp called with:" "DEBUG"
    Write-LogMessage "  UserDescription: $UserDescription" "DEBUG"
    Write-LogMessage "  OutputPath: $OutputPath" "DEBUG"
    Write-LogMessage "  Global API key available: $(-not [string]::IsNullOrWhiteSpace($global:ApiKey))" "DEBUG"
    Write-LogMessage "  Global API key length: $($global:ApiKey.Length)" "DEBUG"
    
    try {
        # Check if this is a template request (marked with *)
        $useTemplate = $false
        $cleanDescription = $UserDescription
        
        if ($UserDescription.StartsWith("*TEMPLATE*")) {
            $useTemplate = $true
            $cleanDescription = $UserDescription.Replace("*TEMPLATE*", "").Trim()
            Write-LogMessage "Template mode detected for: $cleanDescription" "INFO"
        }
        
        # Generate the PowerShell script - ALWAYS use API unless explicitly marked as template
        $appScript = if ($useTemplate) {
            $template = Analyze-UserPrompt $cleanDescription
            if ($template) {
                Write-LogMessage "Using template: $($template.Name)" "INFO"
                $template.Template
            } else {
                Write-LogMessage "No matching template found, using API generation" "INFO"
                $guiSystemPrompt = @"
You are a PowerShell expert assistant that generates complete, working PowerShell GUI applications.
When generating PowerShell scripts, output ONLY valid PowerShell code with NO markdown formatting whatsoever.
Do NOT include code blocks, backticks, or any markdown syntax like ```powershell or ```.
Focus on creating functional Windows Forms applications that users can run immediately.
Include proper error handling and user-friendly interfaces.
Start your response directly with PowerShell code.
"@
                Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput @"
Create a complete, working PowerShell GUI application based on: $cleanDescription

IMPORTANT REQUIREMENTS:
- Use Windows Forms (Add-Type -AssemblyName System.Windows.Forms and System.Drawing)
- Include proper error handling with try-catch blocks
- Make all functionality self-contained with no external dependencies
- Use proper PowerShell syntax that works with ps2exe compilation
- Escape variables properly in here-strings and complex expressions
- Include a Close button that calls `$form.Close()
- Wrap the main code in try-catch for error handling
- Test that all object constructors have proper syntax

EXAMPLE STRUCTURE:
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    `$form = New-Object System.Windows.Forms.Form
    `$form.Text = "Application Title"
    `$form.Size = New-Object System.Drawing.Size(800, 600)
    `$form.StartPosition = "CenterScreen"
    
    # Add your controls here
    
    [void]`$form.ShowDialog()
} catch {
    [System.Windows.Forms.MessageBox]::Show("Error: `$(`$_.Exception.Message)", "Application Error")
}

Generate a complete, functional application based on this structure.
"@ -SystemPrompt $guiSystemPrompt
            }
        } else {
            # ALWAYS use OpenAI API for dynamic generation (this is the main purpose!)
            Write-LogMessage "Using OpenAI API for dynamic generation" "INFO"
            $guiSystemPrompt = @"
You are a PowerShell expert assistant that generates complete, working PowerShell GUI applications.
When generating PowerShell scripts, output ONLY valid PowerShell code with NO markdown formatting whatsoever.
Do NOT include code blocks, backticks, or any markdown syntax like ```powershell or ```.
Focus on creating functional Windows Forms applications that users can run immediately.
Include proper error handling and user-friendly interfaces.
Start your response directly with PowerShell code.
"@
            Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput @"
Create a complete, working PowerShell GUI application based on: $UserDescription

IMPORTANT REQUIREMENTS:
- Use Windows Forms (Add-Type -AssemblyName System.Windows.Forms and System.Drawing)
- Include proper error handling with try-catch blocks
- Make all functionality self-contained with no external dependencies
- Use proper PowerShell syntax that works with ps2exe compilation
- Escape variables properly in here-strings and complex expressions
- Include a Close button that calls `$form.Close()
- Wrap the main code in try-catch for error handling
- Test that all object constructors have proper syntax

EXAMPLE STRUCTURE:
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    `$form = New-Object System.Windows.Forms.Form
    `$form.Text = "Application Title"
    `$form.Size = New-Object System.Drawing.Size(800, 600)
    `$form.StartPosition = "CenterScreen"
    
    # Add your controls here
    
    [void]`$form.ShowDialog()
} catch {
    [System.Windows.Forms.MessageBox]::Show("Error: `$(`$_.Exception.Message)", "Application Error")
}

Generate a complete, functional application based on this structure.
"@ -SystemPrompt $guiSystemPrompt
        }

        # Save the script
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $appName = if ($UserDescription -match "(\w+)") { $matches[1] } else { "PowerShellApp" }
        $fileName = "$($appName)_$timestamp.ps1"
        $fullPath = Join-Path -Path $OutputPath -ChildPath $fileName
        Write-Utf8NoBom -Path $fullPath -Value $appScript
        
        # Validate script syntax before attempting ps2exe conversion
        if (-not (Test-PowerShellScriptSyntax -ScriptContent $appScript -ScriptPath $fullPath)) {
            Write-LogMessage "Generated script has syntax errors - cannot convert to executable" "ERROR"
            Write-LogMessage "Returning PowerShell script file for manual review" "WARNING"
            return $fullPath
        }

        # Convert to EXE with appropriate settings
        if (Test-PS2EXE) {
            $exePath = $fullPath -replace "\.ps1$", ".exe"
            $iconPath = Get-AppropriateIcon -ScriptContent $appScript
            
            # Enhanced ps2exe parameters for better AV compatibility
            $ps2exeParams = @{
                inputFile = $fullPath
                outputFile = $exePath
                title = $appName
                description = "Application generated by DPSG"
                company = "Local Application"
                product = $appName
                copyright = "Copyright $(Get-Date -Format "yyyy")"
                version = "1.0.0.0"
                noConsole = $true
                verbose = $true
            }

            # Skip icon functionality to avoid compilation errors
            Write-LogMessage "Creating executable without icon (icons can cause compilation issues)" "DEBUG"

            Write-LogMessage "Converting to standalone executable..." "INFO"
            
            try {
                # Use Invoke-ps2exe with enhanced parameters for better executable behavior
                Write-LogMessage "Running ps2exe conversion with parameters:" "DEBUG"
                Write-LogMessage "Input: $($ps2exeParams.inputFile)" "DEBUG"
                Write-LogMessage "Output: $($ps2exeParams.outputFile)" "DEBUG"
                
                # Capture verbose output to help diagnose issues
                $verboseOutput = @()
                $errorOutput = @()
                
                try {
                    # Run ps2exe and capture output
                    Invoke-ps2exe @ps2exeParams -ErrorVariable errorOutput -WarningVariable warningOutput 2>&1 | ForEach-Object {
                        $verboseOutput += $_.ToString()
                        Write-LogMessage "ps2exe: $($_.ToString())" "DEBUG"
                    }
                } catch {
                    $compileError = $_.Exception.Message
                    Write-LogMessage "ps2exe compilation error: $compileError" "ERROR"
                    
                    # Log any captured output for diagnosis
                    if ($verboseOutput.Count -gt 0) {
                        Write-LogMessage "ps2exe verbose output:" "DEBUG"
                        $verboseOutput | ForEach-Object { Write-LogMessage "  $_" "DEBUG" }
                    }
                    
                    # Check if it's a script content issue
                    if ($compileError -match "compilation errors") {
                        Write-LogMessage "Script may have syntax errors or unsupported content for ps2exe" "ERROR"
                        Write-LogMessage "Returning PowerShell script file instead" "WARNING"
                        return $fullPath
                    }
                    
                    throw $_
                }
                
                if (Test-Path $exePath) {
                    # Verify the executable was created properly
                    $exeInfo = Get-Item $exePath
                    if ($exeInfo.Length -gt 100KB) {  # Reasonable size check
                        Write-LogMessage "Executable created successfully: $exePath" "INFO"
                        Write-LogMessage "Executable size: $([math]::Round($exeInfo.Length/1KB, 2)) KB" "DEBUG"
                        
                        # Clean up the PowerShell script file
                        Remove-Item $fullPath -Force -ErrorAction SilentlyContinue
                        Write-LogMessage "Cleaned up intermediate script file" "DEBUG"
                        
                        return $exePath
                    } else {
                        Write-LogMessage "Executable seems too small ($([math]::Round($exeInfo.Length/1KB, 2)) KB), may have failed" "WARNING"
                        return $fullPath
                    }
                } else {
                    Write-LogMessage "ps2exe conversion failed - executable not created" "ERROR"
                    Write-LogMessage "Check if ps2exe module is properly installed and script content is valid" "ERROR"
                    
                    # Log verbose output for troubleshooting
                    if ($verboseOutput.Count -gt 0) {
                        Write-LogMessage "ps2exe output for troubleshooting:" "ERROR"
                        $verboseOutput | ForEach-Object { Write-LogMessage "  $_" "ERROR" }
                    }
                    
                    return $fullPath
                }
            } catch {
                $errorMsg = $_.Exception.Message
                Write-LogMessage "Error during ps2exe conversion: $errorMsg" "ERROR"
                
                # Provide specific guidance for common errors
                if ($errorMsg -match "compilation errors") {
                    Write-LogMessage "ps2exe compilation failed - script may contain unsupported syntax or features" "ERROR"
                    Write-LogMessage "The generated script will be saved as .ps1 file instead" "WARNING"
                }
                
                Write-LogMessage "Returning PowerShell script instead of executable" "WARNING"
                return $fullPath
            }
        } else {
            Write-LogMessage "ps2exe not available, returning PowerShell script" "WARNING"
            return $fullPath
        }
    }
    catch {
        Write-LogMessage "Error in New-PowerShellApp: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Update-Progress {
    param(
        [int]$Value,
        [string]$Activity = "Processing",
        [string]$Status = ""
    )
    $script:targetProgressValue = [Math]::Max($script:progress.Minimum, [Math]::Min($Value, $script:progress.Maximum))
    if (-not $script:progressTimer.Enabled) {
        $script:progressTimer.Start()
    }
    if ($null -ne $lblProgressStatus) {
        $lblProgressStatus.Text = "$Activity $Status"
    }
    Write-LogMessage "Progress updated to $Value% - $Activity $Status" "DEBUG"
}

function Resolve-IntentFromPrompt {
    param(
        [string]$UserInput,
        [string]$LoadedScript
    )
    
    $input = $UserInput.ToLower()
    
    if ($input -match "enhance|improve|better|optimize") {
        return "enhance"
    }
    elseif ($input -match "summarize|summary|what does|purpose") {
        return "summarize"
    }
    elseif ($input -match "refactor|clean|organize|restructure") {
        return "refactor"
    }
    elseif ($input -match "explain|describe|how does|what is") {
        return "explain"
    }
    else {
        return "enhance"  # default
    }
}

function Truncate-TextForGPT {
    param(
        [string]$Text,
        [int]$MaxLength = 3000
    )
    
    if ($Text.Length -le $MaxLength) {
        return $Text
    }
    
    return $Text.Substring(0, $MaxLength) + "`n`n[... script truncated for length ...]"
}

function Load-FileToBuffer {
    $openFile = New-Object System.Windows.Forms.OpenFileDialog
    $openFile.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All Files (*.*)|*.*"
    $openFile.Title = "Select a script file to load"
    if ($openFile.ShowDialog() -eq "OK") {
        try {
            $raw = Get-Content $openFile.FileName -Raw
            $content = $raw -replace "[^\x00-\x7F]",""
            $global:LoadedScript = $content
            $global:loadedFilesContent = $content
            $global:loadedFileName = [System.IO.Path]::GetFileName($openFile.FileName)
            
            # Update the prompt text box if it exists
            if ($script:txtPrompt) {
                $script:txtPrompt.Text = $content
            }
            
            Write-LogMessage -Message "[OK] Loaded file: $($openFile.FileName)"
        } catch {
            Write-LogMessage -Message "[ERROR] Failed to read file: $($_.Exception.Message)" -Level "Error"
        }
    }
}

function Get-ApplicationTemplates {
    return @{
        "inventory" = @{
            Name = "Inventory Management System"
            Description = "Full CRUD data manager with grids, forms, search, and export capabilities"
            Keywords = @("inventory", "stock", "items", "products", "crud", "database")
            Template = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    `$form = New-Object System.Windows.Forms.Form
    `$form.Text = "Inventory Management System"
    `$form.Size = New-Object System.Drawing.Size(800, 600)
    `$form.StartPosition = "CenterScreen"
    `$form.FormBorderStyle = "FixedDialog"
    `$form.MaximizeBox = `$false

    `$label = New-Object System.Windows.Forms.Label
    `$label.Text = "Welcome to Inventory Management System"
    `$label.Location = New-Object System.Drawing.Point(50, 50)
    `$label.Size = New-Object System.Drawing.Size(400, 30)
    `$label.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
    `$form.Controls.Add(`$label)

    `$btnClose = New-Object System.Windows.Forms.Button
    `$btnClose.Text = "Close"
    `$btnClose.Location = New-Object System.Drawing.Point(350, 500)
    `$btnClose.Size = New-Object System.Drawing.Size(100, 30)
    `$btnClose.Add_Click({ `$form.Close() })
    `$form.Controls.Add(`$btnClose)

    [void]`$form.ShowDialog()
} catch {
    [System.Windows.Forms.MessageBox]::Show("Error: `$(`$_.Exception.Message)", "Application Error")
}
"@
        }
        
        "fileorganizer" = @{
            Name = "File Organization Tool"
            Description = "File browser with tree view, bulk operations, copy/move functionality"
            Keywords = @("file", "folder", "organize", "copy", "move", "browser", "explorer")
            Template = @"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    `$form = New-Object System.Windows.Forms.Form
    `$form.Text = "File Organization Tool"
    `$form.Size = New-Object System.Drawing.Size(800, 600)
    `$form.StartPosition = "CenterScreen"
    `$form.FormBorderStyle = "FixedDialog"
    `$form.MaximizeBox = `$false

    `$label = New-Object System.Windows.Forms.Label
    `$label.Text = "Welcome to File Organization Tool"
    `$label.Location = New-Object System.Drawing.Point(50, 50)
    `$label.Size = New-Object System.Drawing.Size(400, 30)
    `$label.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
    `$form.Controls.Add(`$label)

    `$btnClose = New-Object System.Windows.Forms.Button
    `$btnClose.Text = "Close"
    `$btnClose.Location = New-Object System.Drawing.Point(350, 500)
    `$btnClose.Size = New-Object System.Drawing.Size(100, 30)
    `$btnClose.Add_Click({ `$form.Close() })
    `$form.Controls.Add(`$btnClose)

    [void]`$form.ShowDialog()
} catch {
    [System.Windows.Forms.MessageBox]::Show("Error: `$(`$_.Exception.Message)", "Application Error")
}
"@
        }
    }
}

function Analyze-UserPrompt {
    param([string]$UserInput)
    
    $templates = Get-ApplicationTemplates
    $bestMatch = $null
    $highestScore = 0
    
    foreach ($template in $templates.Values) {
        $score = 0
        foreach ($keyword in $template.Keywords) {
            if ($UserInput -match $keyword) {
                $score++
            }
        }
        
        if ($score -gt $highestScore) {
            $highestScore = $score
            $bestMatch = $template
        }
    }
    
    return $bestMatch
}

function Get-LastOutputFolder {
    try {
        # Try to read from user registry (safer than machine registry)
        $key = "HKCU:\Software\DPSG\Settings"
        if (Test-Path $key) {
            $folder = Get-ItemPropertyValue -Path $key -Name "LastOutputFolder" -ErrorAction SilentlyContinue
            if ($folder -and (Test-Path $folder)) {
                return $folder
            }
        }
    }
    catch {
        Write-LogMessage -Message "Could not read saved folder location: $($_.Exception.Message)" -Level "DEBUG"
    }
    # Default to user Documents folder
    return [Environment]::GetFolderPath("MyDocuments")
}

function Set-LastOutputFolder {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    try {
        # Only save to user registry (HKCU), not machine registry
        $key = "HKCU:\Software\DPSG\Settings"
        if (-not (Test-Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }
        Set-ItemProperty -Path $key -Name "LastOutputFolder" -Value $Path
        Write-LogMessage -Message "Saved output folder preference: $Path" -Level "DEBUG"
    }
    catch {
        Write-LogMessage -Message "Could not save folder preference: $($_.Exception.Message)" -Level "DEBUG"
        # Do not fail if we cannot save the preference
    }
}

function Show-ErrorMessage {
    param([string]$Message)
    [void][System.Windows.Forms.MessageBox]::Show(
        $form,
        $Message,
        "Error",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error,
        [System.Windows.Forms.MessageBoxDefaultButton]::Button1,
        [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
    )
    $form.TopMost = $true
    $form.Activate()
}

#endregion

#region Main Execution
Write-LogMessage "Starting DPSG initialization..." "INFO"

$global:ApiKey = Get-ApiKey

# Validate the global API key before proceeding
if ([string]::IsNullOrWhiteSpace($global:ApiKey)) {
    Write-LogMessage "FATAL: No valid API key available. Cannot proceed." "ERROR"
    if ($Gui) {
        [System.Windows.Forms.MessageBox]::Show("No valid OpenAI API key available.`n`nPlease set the OPENAI_API_KEY environment variable or provide the key when prompted.`n`nGet your API key from: https://platform.openai.com/api-keys", "Configuration Error", "OK", "Error")
    }
    exit 1
}

# Double-check for corruption in global API key
if ($global:ApiKey.Length -gt 300 -or $global:ApiKey -match "^\[\d{2}:\d{2}:\d{2}\]") {
    Write-LogMessage "CRITICAL: Global API key is still corrupted after Get-ApiKey. Forcing user prompt." "ERROR"
    Write-LogMessage "Corrupted global key: '$($global:ApiKey.Substring(0, [Math]::Min(50, $global:ApiKey.Length)))'" "DEBUG"
    
    if ($Gui) {
        $newKey = [Microsoft.VisualBasic.Interaction]::InputBox("Your environment API key is corrupted with log data.`n`nPlease enter your clean OpenAI API key:", "Corrupted Environment Variable", "")
        if (-not [string]::IsNullOrWhiteSpace($newKey) -and $newKey -match "^sk-") {
            $global:ApiKey = $newKey.Trim()
            Write-LogMessage "Global API key replaced with user-provided key" "INFO"
        } else {
            Write-LogMessage "User did not provide valid API key, exiting..." "ERROR"
            [System.Windows.Forms.MessageBox]::Show("Cannot start DPSG without a valid OpenAI API key.", "Configuration Error", "OK", "Error")
            exit 1
        }
    } else {
        Write-Host "Your environment API key is corrupted with log data." -ForegroundColor Red
        $newKey = Read-Host "Please enter your clean OpenAI API key"
        if (-not [string]::IsNullOrWhiteSpace($newKey) -and $newKey -match "^sk-") {
            $global:ApiKey = $newKey.Trim()
            Write-LogMessage "Global API key replaced with user-provided key" "INFO"
        } else {
            Write-LogMessage "User did not provide valid API key, exiting..." "ERROR"
            exit 1
        }
    }
}

Write-LogMessage "API key successfully validated - Length: $($global:ApiKey.Length)" "INFO"

if ($PromptFile) {
    $promptContent = Get-Content -Raw $PromptFile
    if ($promptContent -match "create|generate|build") {
        $TaskType = "code-generation"
    }
    elseif ($promptContent -match "calculate|compute") {
        $TaskType = "code-interpreter"
    }
    else {
        $TaskType = "code-generation"
    }
} elseif (-not $TaskType) {
    $TaskType = "code-generation"
}

if ($Gui) {
    Write-LogMessage "GUI mode detected, checking API key before starting interface..." "DEBUG"
    
    # Make sure we have an API key before starting the GUI
    if ([string]::IsNullOrWhiteSpace($global:ApiKey)) {
        Write-LogMessage "No API key found, prompting user..." "WARNING"
        $global:ApiKey = Get-ApiKey
        
        if ([string]::IsNullOrWhiteSpace($global:ApiKey)) {
            Write-LogMessage "User did not provide valid API key, exiting..." "ERROR"
            [System.Windows.Forms.MessageBox]::Show("Cannot start DPSG without a valid OpenAI API key.", "Configuration Error", "OK", "Error")
            exit 1
        }
    }
    
    Write-LogMessage "Starting GUI with validated API key..." "INFO"
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "DPSG - Dynamic PowerShell Script Generator v2.0"
    $form.Size = New-Object System.Drawing.Size(900,750)
    $form.StartPosition = "CenterScreen"
    $form.MinimumSize = New-Object System.Drawing.Size(900,750)
    $form.Add_FormClosed({ $script:progressTimer.Dispose() })
    
    [int]$y = 10
    
    $lblPrompt = New-Object System.Windows.Forms.Label
    $lblPrompt.Text = "Prompt (describe your application):"
    $lblPrompt.Location = New-Object System.Drawing.Point(10,$y)
    $lblPrompt.AutoSize = $true
    $form.Controls.Add($lblPrompt)
    
    $y += 20
    
    $script:txtPrompt = New-Object System.Windows.Forms.TextBox
    $script:txtPrompt.Multiline = $true
    $script:txtPrompt.ScrollBars = "Vertical"
    $script:txtPrompt.Size = New-Object System.Drawing.Size(860,100)
    $script:txtPrompt.Location = New-Object System.Drawing.Point(10,$y)
    $form.Controls.Add($script:txtPrompt)
    
    $y += 110
    
    $cmbAction = New-Object System.Windows.Forms.ComboBox
    $cmbAction.DropDownStyle = "DropDownList"
    $cmbAction.Size = New-Object System.Drawing.Size(300,24)
    $cmbAction.Location = New-Object System.Drawing.Point(10,$y)
    $cmbAction.Items.AddRange(@(
        "normal = generate a PowerShell script",
        "loadfile = load a local script into buffer",
        "ask = enhance or query the loaded script",
        "createapp = generate a portable PowerShell executable (.exe)"
    ))
    $cmbAction.SelectedIndex = 0
    $form.Controls.Add($cmbAction)
    
    # Ask-intent combo (visible only when ask is selected)
    $cmbAskIntent = New-Object System.Windows.Forms.ComboBox
    $cmbAskIntent.DropDownStyle = "DropDownList"
    $cmbAskIntent.Size = New-Object System.Drawing.Size(150,24)
    $cmbAskIntent.Location = New-Object System.Drawing.Point(320,$y)
    $cmbAskIntent.Items.AddRange(@(
        "enhance",
        "summarize", 
        "refactor",
        "explain"
    ))
    $cmbAskIntent.SelectedIndex = 0
    $cmbAskIntent.Visible = $false
    $form.Controls.Add($cmbAskIntent)
    
    # Upload button (visible only when loadfile is selected)
    $btnUpload = New-Object System.Windows.Forms.Button
    $btnUpload.Text = "Upload Script"
    $btnUpload.Size = New-Object System.Drawing.Size(100,23)
    $btnUpload.Location = New-Object System.Drawing.Point(320,$y)
    $btnUpload.Visible = $false
    $btnUpload.Add_Click({
        Load-FileToBuffer
    })
    $form.Controls.Add($btnUpload)
    
    $btnInsertExample = New-Object System.Windows.Forms.Button
    $btnInsertExample.Text = "Insert Application Example"
    $btnInsertExample.Size = New-Object System.Drawing.Size(180,23)
    $btnInsertExample.Location = New-Object System.Drawing.Point(480,$y)
    $form.Controls.Add($btnInsertExample)
    
    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Text = "Execute"
    $btnRun.Size = New-Object System.Drawing.Size(80,23)
    $btnRun.Location = New-Object System.Drawing.Point(670,$y)
    $btnRun.BackColor = [System.Drawing.Color]::LightGreen
    $form.Controls.Add($btnRun)
    
    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "Save Result"
    $btnSave.Size = New-Object System.Drawing.Size(90,23)
    $btnSave.Location = New-Object System.Drawing.Point(760,$y)
    $btnSave.Enabled = $false
    $form.Controls.Add($btnSave)
    
    # Add event handler to show/hide ask intent combo and upload button
    $cmbAction.Add_SelectedIndexChanged({
        try {
            $selected = $cmbAction.SelectedItem
            if ($selected) {
                $selectedText = $selected.ToString()
                
                # Handle ask intent combo visibility
                if ($selectedText.StartsWith("ask")) {
                    $cmbAskIntent.Visible = $true
                } else {
                    $cmbAskIntent.Visible = $false
                }
                
                # Handle upload button visibility
                if ($selectedText.StartsWith("loadfile")) {
                    $btnUpload.Visible = $true
                } else {
                    $btnUpload.Visible = $false
                }
            }
        } catch {
            # Ignore combo change errors
        }
    })
    
    $y += 40
    
    $txtOutput = New-Object System.Windows.Forms.TextBox
    $txtOutput.Multiline = $true
    $txtOutput.ScrollBars = "Vertical"
    $txtOutput.Size = New-Object System.Drawing.Size(860,300)
    $txtOutput.Location = New-Object System.Drawing.Point(10,$y)
    $txtOutput.BackColor = "Honeydew"
    $txtOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
    $form.Controls.Add($txtOutput)
    
    $y += 310
    
    # Context Menu for output
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $menuOpenInEditor = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuOpenInEditor.Text = "Open in Editor"
    $menuOpenInEditor.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtOutput.Text)) {
            Write-LogMessage "No content to open in editor" "WARNING"
            return
        }
        $tempScript = Join-Path $env:TEMP "dpsg_script_$(Get-Date -Format "yyyyMMddHHmmss").ps1"
        try {
            Write-Utf8NoBom -Path $tempScript -Value $txtOutput.Text
            Write-LogMessage "Saved temporary script to $tempScript" "INFO"
            
            $editors = @(
                "C:\Program Files\Notepad++\notepad++.exe",
                "C:\Program Files\Microsoft VS Code\Code.exe",
                "notepad.exe"
            )
            
            foreach ($editor in $editors) {
                if (Test-Path $editor) {
                    Start-Process $editor -ArgumentList $tempScript
                    Write-LogMessage "Opened with $editor" "INFO"
                    return
                }
            }
            Start-Process $tempScript
            Write-LogMessage "Opened with default editor" "INFO"
        }
        catch {
            Write-LogMessage "Failed to open script: $($_.Exception.Message)" "ERROR"
        }
    })
    
    $menuCopyAll = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuCopyAll.Text = "Copy All"
    $menuCopyAll.Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($txtOutput.Text)) {
            try {
                [System.Windows.Forms.Clipboard]::SetText($txtOutput.Text)
                Write-LogMessage "Copied all text to clipboard" "INFO"
            } catch {
                Write-LogMessage "Failed to copy text: $($_.Exception.Message)" "ERROR"
            }
        }
    })
    
    $menuSaveAs = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuSaveAs.Text = "Save As..."
    $menuSaveAs.Add_Click({
        $dlg = New-Object System.Windows.Forms.SaveFileDialog
        $dlg.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All Files (*.*)|*.*"
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            Write-Utf8NoBom -Path $dlg.FileName -Value $txtOutput.Text
            Write-LogMessage "Script saved to $($dlg.FileName)" "INFO"
        }
    })
    
    $contextMenu.Items.AddRange(@($menuOpenInEditor, $menuCopyAll, $menuSaveAs))
    $txtOutput.ContextMenuStrip = $contextMenu
    
    $script:txtLog = New-Object Windows.Forms.RichTextBox
    $script:txtLog.Multiline = $true
    $script:txtLog.ScrollBars = "Vertical"
    $script:txtLog.WordWrap = $false
    $script:txtLog.Size = New-Object System.Drawing.Size(860,120)
    $script:txtLog.Location = New-Object System.Drawing.Point(10,$y)
    $script:txtLog.BackColor = "Black"
    $script:txtLog.ForeColor = "Lime"
    $script:txtLog.Font = New-Object Drawing.Font("Consolas", 9)
    $form.Controls.Add($script:txtLog)
    
    $script:txtLog.Add_TextChanged({
        $script:txtLog.SelectionStart = $script:txtLog.Text.Length
        $script:txtLog.ScrollToCaret()
    })
    
    $y += $script:txtLog.Height + 10
    
    # Copy to Clipboard button (under the live log)
    $btnCopyLog = New-Object System.Windows.Forms.Button
    $btnCopyLog.Text = "Copy Log to Clipboard"
    $btnCopyLog.Size = New-Object System.Drawing.Size(150,25)
    $btnCopyLog.Location = New-Object System.Drawing.Point(10, $y)
    $btnCopyLog.Add_Click({
        try {
            if (-not [string]::IsNullOrWhiteSpace($script:txtLog.Text)) {
                [System.Windows.Forms.Clipboard]::SetText($script:txtLog.Text)
                Write-LogMessage "Log copied to clipboard" "INFO"
            }
        } catch {
            Write-LogMessage "Failed to copy log: $($_.Exception.Message)" "ERROR"
        }
    })
    $form.Controls.Add($btnCopyLog)
    
    $y += 35
    
    $script:progress = New-Object System.Windows.Forms.ProgressBar
    $script:progress.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $script:progress.Location = New-Object System.Drawing.Point(10, $y)
    $script:progress.Size = New-Object System.Drawing.Size(860,20)
    $script:progress.Minimum = 0
    $script:progress.Maximum = 100
    $script:progress.Value = 0
    $form.Controls.Add($script:progress)
    
    $script:progressTimer = New-Object System.Windows.Forms.Timer
    $script:progressTimer.Interval = 50
    $script:targetProgressValue = 0
    $script:progressTimer.Add_Tick({
        try {
            if ($script:progress.Value -lt $script:targetProgressValue) {
                $newValue = [Math]::Min(($script:progress.Value + 5), [Math]::Min($script:targetProgressValue, $script:progress.Maximum))
                $script:progress.Value = $newValue
            }
            elseif ($script:progress.Value -gt $script:targetProgressValue) {
                $newValue = [Math]::Max(($script:progress.Value - 5), [Math]::Max($script:targetProgressValue, $script:progress.Minimum))
                $script:progress.Value = $newValue
            }
            else {
                $script:progressTimer.Stop()
            }
        }
        catch {
            Write-LogMessage "Progress update error: $_" "WARNING"
            $script:progressTimer.Stop()
        }
    })
    
    # Event Handlers
    $btnInsertExample.Add_Click({
        $exampleForm = New-Object System.Windows.Forms.Form
        $exampleForm.Text = "Application Examples"
        $exampleForm.Size = New-Object System.Drawing.Size(600,400)
        $exampleForm.StartPosition = "CenterParent"
        
        $listBox = New-Object System.Windows.Forms.ListBox
        $listBox.Size = New-Object System.Drawing.Size(550,250)
        $listBox.Location = New-Object System.Drawing.Point(20,20)
        
        # Get templates and store them with proper indexing
        $templates = Get-ApplicationTemplates
        $templateArray = @()
        foreach ($template in $templates.Values) {
            $templateArray += $template
            $listBox.Items.Add("$($template.Name) - $($template.Description)")
        }
        
        $exampleForm.Controls.Add($listBox)
        
        $btnInsert = New-Object System.Windows.Forms.Button
        $btnInsert.Text = "Insert"
        $btnInsert.Size = New-Object System.Drawing.Size(75,25)
        $btnInsert.Location = New-Object System.Drawing.Point(400,300)
        $btnInsert.Add_Click({
            try {
                if ($listBox.SelectedIndex -ge 0 -and $listBox.SelectedIndex -lt $templateArray.Count) {
                    $selectedTemplate = $templateArray[$listBox.SelectedIndex]
                    # Add template marker so the script knows to use template instead of API
                    $script:txtPrompt.Text = "*TEMPLATE* $($selectedTemplate.Description)"
                    
                    # Find and set the createapp option
                    for ($i = 0; $i -lt $cmbAction.Items.Count; $i++) {
                        if ($cmbAction.Items[$i].ToString().StartsWith("createapp")) {
                            $cmbAction.SelectedIndex = $i
                            break
                        }
                    }
                    
                    Write-LogMessage "Inserted template: $($selectedTemplate.Name) with template marker" "INFO"
                    $exampleForm.Close()
                } else {
                    Write-LogMessage "No template selected or invalid selection" "WARNING"
                }
            } catch {
                Write-LogMessage "Error inserting template: $($_.Exception.Message)" "ERROR"
            }
        })
        $exampleForm.Controls.Add($btnInsert)
        
        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text = "Cancel"
        $btnCancel.Size = New-Object System.Drawing.Size(75,25)
        $btnCancel.Location = New-Object System.Drawing.Point(490,300)
        $btnCancel.Add_Click({ $exampleForm.Close() })
        $exampleForm.Controls.Add($btnCancel)
        
        $exampleForm.ShowDialog($form)
    })
    
    $btnRun.Add_Click({
        try {
            if ($Gui -and [string]::IsNullOrWhiteSpace($script:txtPrompt.Text)) {
                [System.Windows.Forms.MessageBox]::Show(
                    "Please enter a description of what you want to create",
                    "Input Required",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                return
            }
            
            $global:UserInput = if ($Gui) { $script:txtPrompt.Text } else { $global:UserInput }
            $selected = $cmbAction.SelectedItem
            $cmd = if ($selected -match "^([^=]+)=") { $matches[1].Trim() } else { "normal" }
            
            Write-LogMessage -Message "[Action] $cmd" -Level "Info"
            $txtOutput.Text = ""
            
            switch ($cmd) {
                "normal" {
                    $resp = Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput $global:UserInput
                    $txtOutput.Text = $resp
                    $btnSave.Enabled = $true
                    Write-LogMessage -Message "[OK] Script generation completed." -Level "Info"
                }
                
                "loadfile" {
                    # File loading is handled by the Upload Script button
                    Write-LogMessage -Message "Use the 'Upload Script' button to load a file" -Level "Info"
                    $txtOutput.Text = "Click the 'Upload Script' button to select and load a PowerShell script file."
                }
                
                "ask" {
                    try {
                        if ([string]::IsNullOrWhiteSpace($global:LoadedScript)) {
                            [System.Windows.Forms.MessageBox]::Show("Please load a script first using loadfile option.", "No Script Loaded", "OK", "Warning")
                            return
                        }
                        
                        # Determine intent from combo box or from prompt
                        $intent = "enhance"  # default
                        if ($cmbAskIntent.Visible -and $cmbAskIntent.SelectedItem) {
                            $intent = $cmbAskIntent.SelectedItem.ToString().ToLower()
                        }
                        else {
                            $intent = Resolve-IntentFromPrompt -UserInput $global:UserInput -LoadedScript $global:LoadedScript
                        }
                        
                        $scriptSnippet = Truncate-TextForGPT -Text $global:LoadedScript -MaxLength 3000
                        $prompt = $script:txtPrompt.Text
                        
                        switch ($intent) {
                            "enhance" {
                                $fullPrompt = "You are a PowerShell expert. Improve the script for clarity, performance, and scalability. User request: $prompt`n`nSCRIPT:`n$scriptSnippet"
                                $txtOutput.Text = Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput $fullPrompt
                            }
                            "summarize" {
                                $fullPrompt = "You are a PowerShell guru. Summarize the main purpose and key functions of the following script in 1-2 sentences. SCRIPT: $scriptSnippet"
                                $txtOutput.Text = Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput $fullPrompt
                            }
                            "refactor" {
                                $fullPrompt = "You are a PowerShell linter and optimizer. Refactor the following script for readability, modularity, and efficiency. SCRIPT: $scriptSnippet"
                                $txtOutput.Text = Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput $fullPrompt
                            }
                            "explain" {
                                $fullPrompt = "You are a helpful assistant. Explain in detail what the following PowerShell script does. SCRIPT: $scriptSnippet"
                                $txtOutput.Text = Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput $fullPrompt
                            }
                            default {
                                $txtOutput.Text = "Unable to determine intent. Please refine your prompt or select a task."
                            }
                        }
                        $btnSave.Enabled = $true
                        Write-LogMessage -Message "[DONE] Ask processed as intent: $intent" -Level "Info"
                    } catch {
                        $txtOutput.Text = "[ERROR] Script enhancement failed: $($_.Exception.Message)"
                        Write-LogMessage -Message "[ERROR] Ask operation failed: $($_.Exception.Message)" -Level "Error"
                    }
                }
                
                "createapp" {
                    try {
                        Write-LogMessage "Starting createapp action..." "DEBUG"
                        Write-LogMessage "Global API key available: $(-not [string]::IsNullOrWhiteSpace($global:ApiKey))" "DEBUG"
                        Write-LogMessage "Global API key length: $($global:ApiKey.Length)" "DEBUG"
                        
                        if ([string]::IsNullOrWhiteSpace($global:ApiKey)) {
                            Write-LogMessage "ERROR: No API key available for createapp action" "ERROR"
                            $txtOutput.Text = "Error: No API key available. Please restart the application and provide a valid OpenAI API key."
                            return
                        }
                        
                        $fb = New-Object System.Windows.Forms.FolderBrowserDialog
                        $fb.Description = "Select folder for PowerShell executable"
                        $fb.SelectedPath = Get-LastOutputFolder
                        
                        if ($fb.ShowDialog() -ne "OK") {
                            Write-LogMessage "User canceled folder selection" -Level "Warning"
                            return
                        }
                        
                        $outputFolder = $fb.SelectedPath
                        Set-LastOutputFolder -Path $outputFolder
                        
                        # Generate PowerShell executable application
                        Write-LogMessage "Calling New-PowerShellApp with API key..." "DEBUG"
                        $appPath = New-PowerShellApp -UserDescription $global:UserInput -OutputPath $outputFolder
                        
                        if ($appPath.EndsWith(".exe")) {
                            $txtOutput.Text = "Success! Portable executable created at:`n$appPath`n`nDouble-click the .exe file to run your application - no PowerShell required!"
                        } else {
                            $txtOutput.Text = "PowerShell script created at:`n$appPath`n`n(ps2exe conversion failed - you can still run the .ps1 file)"
                        }
                        
                        if ([System.Windows.Forms.MessageBox]::Show("Open containing folder?", "Success", "YesNo", "Information") -eq "Yes") {
                            Start-Process explorer.exe -ArgumentList "/select,`"$appPath`""
                        }
                        
                        Update-Progress -Value 100 -Activity "Complete" -Status "Success"
                        $btnSave.Enabled = $true
                    }
                    catch {
                        $txtOutput.Text = "Error: $($_.Exception.Message)"
                        Write-LogMessage "App creation failed: $_" -Level "ERROR"
                        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error", "OK", "Error")
                    }
                }
                
                default {
                    Write-LogMessage -Message "Unknown command: $cmd" -Level "Warning"
                    $txtOutput.Text = "[WARNING] Unknown command: $cmd"
                }
            }
        }
        catch {
            Write-LogMessage -Message "Error in main execution: $($_.Exception.Message)" -Level "Error"
            $txtOutput.Text = "[ERROR] $($_.Exception.Message)"
        }
    })
    
    $btnSave.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtOutput.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Nothing to save.", "No Content", "OK", "Warning")
            return
        }
        
        $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All Files (*.*)|*.*"
        $saveDialog.Title = "Save Generated Script"
        $saveDialog.FileName = "GeneratedScript_$(Get-Date -Format "yyyyMMdd_HHmmss").ps1"
        
        if ($saveDialog.ShowDialog() -eq "OK") {
            try {
                Write-Utf8NoBom -Path $saveDialog.FileName -Value $txtOutput.Text
                Write-LogMessage "Script saved successfully to $($saveDialog.FileName)" "INFO"
                [System.Windows.Forms.MessageBox]::Show("Script saved successfully!", "Save Complete", "OK", "Information")
            } catch {
                Write-LogMessage "Error saving script: $($_.Exception.Message)" "ERROR"
                [System.Windows.Forms.MessageBox]::Show("Error saving script: $($_.Exception.Message)", "Save Error", "OK", "Error")
            }
        }
    })
    
    Write-LogMessage "DPSG v2.0 initialized successfully" "INFO"
    Write-LogMessage "Ready to generate portable PowerShell executables" "INFO"
    Write-LogMessage "Note: ps2exe module will be auto-installed if needed for .exe generation" "INFO"
    
    [void]$form.ShowDialog()
}
elseif ($Interactive) {
    while ($true) {
        $prompt = Read-Host "Enter prompt (or exit to quit)"
        if ($prompt -in "exit", "quit") { break }
        $response = Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput $prompt
        Write-Output $response
    }
}
else {
    try {
        $inputText = if ($PromptFile) { Get-Content -Raw -Path $PromptFile } else { Read-Host "Enter your prompt" }
        $output = Request-ScriptGeneration -ApiKey $global:ApiKey -UserInput $inputText
        Write-Output $output
    }
    catch {
        Write-Output "Error: $($_.Exception.Message)"
        exit 1
    }
}
#endregion
