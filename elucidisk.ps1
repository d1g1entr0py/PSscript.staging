# Download the zip file
function Download-ElucidiskZip {
    param (
        [string]$downloadLink,
        [string]$destination
    )
    Write-Output "Downloading zip"
    Invoke-WebRequest -Uri $downloadLink -OutFile $destination -UseBasicParsing
}

# Extract the zip file
function Extract-Zip {
    param (
        [string]$zipPath,
        [string]$destination
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $destination)
}

# Run the elucidisk executable and wait for completion
function Run-Elucidisk {
    param (
        [string]$executablePath,
        [array]$arguments
    )
    if ($arguments) {
        Start-Process -FilePath $executablePath -ArgumentList $arguments -Wait -NoNewWindow
    } else {
        Start-Process -FilePath $executablePath -Wait -NoNewWindow
    }
}

# Cleanup
function Remove-File {
    param (
        [string]$Path
    )
    try {
        if (Test-Path -Path $Path) {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Output "Removed: $Path"
        }
    } catch {
        #Write-Warning "Unable to remove item: $Path - $_"
    }
}

function Remove-Files {
    param(
        [string]$zipPath,
        [string]$folderPath
    )
    Remove-File -Path $zipPath
    Remove-File -Path $folderPath
}

# Main Script
try {
    $downloadUrl = "https://github.com/chrisant996/elucidisk/releases/download/v1.4/elucidisk-v1.4.zip"
    $tempFolder = $env:TEMP
    $zipFilePath = Join-Path $tempFolder "elucidisk-v1.4.zip"
    $extractFolderPath = Join-Path $tempFolder "elucidisk-v1.4"
    
    # Clean up any existing files first
    Write-Output "Cleaning up any existing files..."
    Remove-Files -zipPath $zipFilePath -folderPath $extractFolderPath
    
    Write-Output "Downloading Elucidisk..."
    Download-ElucidiskZip -downloadLink $downloadUrl -destination $zipFilePath
    
    Write-Output "Extracting Zip File..."
    Extract-Zip -zipPath $zipFilePath -destination $extractFolderPath
    
    $executablePath = Join-Path $extractFolderPath "elucidisk.exe"
    
    # Verify the executable exists
    if (-not (Test-Path $executablePath)) {
        throw "elucidisk.exe not found in extracted files"
    }
    
    Write-Output "Running Elucidisk..."
    Write-Output "Executable path: $executablePath"
    
    # Run elucidisk with any arguments passed to the script
    Run-Elucidisk -executablePath $executablePath -arguments $args
    
    Write-Output "Cleaning up temporary files..."
    Remove-Files -zipPath $zipFilePath -folderPath $extractFolderPath
    
    Write-Output "Done."
} catch {
    Write-Error "An error occurred: $_"
    # Attempt cleanup even if there was an error
    try {
        Remove-Files -zipPath $zipFilePath -folderPath $extractFolderPath
    } catch {
        Write-Warning "Failed to clean up temporary files: $_"
    }
}
