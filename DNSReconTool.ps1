<#
.SYNOPSIS
    DNS RECON TOOL

.DESCRIPTION
    This PowerShell script provides comprehensive DNS information for a domain or IP address,
    including DNS records (with focus on email-related records), WHOIS information, and IP geolocation.
    It's designed as a security tool to quickly analyze domains or IPs with color-coded output
    to highlight potential security issues or misconfigurations.

.PARAMETER Target
    The domain name or IP address to analyze

.EXAMPLE
    .\DNSReconTool.ps1 -Target example.com

.EXAMPLE
    .\DNSReconTool.ps1 -Target 8.8.8.8

.NOTES
    Author: admin@consaul.CLOUD
    Version: 1.2
#>

[CmdletBinding()]
param (
    [string]$Target
)

Write-Host "`n`e[1;36m`r`n`r`n
  ___   ____   _____     ____    ___    __  ___  ____       ______  ___   ___  _     
 |   \ |    \ / ___/    |    \  /  _]  /  ]/   \|    \     |      |/   \ /   \| |    
 |    \|  _  (   \_     |  D  )/  [_  /  /|     |  _  |    |      |     |     | |    
 |  D  |  |  |\__  |    |    /|    _]/  / |  O  |  |  |    |_|  |_|  O  |  O  | |___ 
 |     |  |  |/  \ |    |    \|   [_/   \_|     |  |  |      |  | |     |     |     |
 |     |  |  |\    |    |  .  |     \     |     |  |  |      |  | |     |     |     |
 |_____|__|__| \___|    |__|\_|_____|\____|\___/|__|__|      |__|  \___/ \___/|_____|
                                                                                    
`e[0m`n`r`n`r`n`e[1;33mDNS Recon Tool`e[0m`n`r`n`r`n`e[1;32mEnter domain, URL, or IP to get started:`e[0m`n`r`n`r`n"

#region Configuration
# API Keys
$WhoisXMLAPIKey = "at_ELsWuPy1Huov82h2MecCqvDhM9FSI"
$WhoisJSONAPIKey = "069aa9baf1cbc49f674ad6272430e75bd2137e1db6103834e43d056c971a012b"

# API Endpoints
$WhoisXMLAPIEndpoint = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
$IPGeolocationEndpoint = "http://ip-api.com/json"
$WhoisJSONEndpoint = "https://whoisjson.com/api/v1/whois"

# Common DNS Servers
$DNSServers = @("8.8.8.8", "1.1.1.1", "9.9.9.9")
$DefaultDNSServer = $DNSServers[0]

# Record Types to Check
$DNSRecordTypes = @("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR", "SRV")
$EmailRelatedRecords = @("MX", "TXT", "SPF", "DMARC", "DKIM")

# Security Checks
$SecurityChecks = @{
    "MissingMXRecord" = "No MX records found. This domain may not be configured for email."
    "MissingSPF" = "No SPF record found. Domain is vulnerable to email spoofing."
    "MissingDMARC" = "No DMARC record found. Domain is vulnerable to email spoofing and phishing."
    "WeakSPF" = "Weak SPF configuration detected. Consider strengthening the policy."
    "WeakDMARC" = "Weak DMARC configuration detected. Consider strengthening the policy."
    "MissingCAA" = "No CAA records found. Domain is vulnerable to unauthorized certificate issuance."
    "DNSSECDisabled" = "DNSSEC is not enabled. Domain is vulnerable to DNS spoofing."
    "OpenResolver" = "DNS server appears to be an open resolver. This is a security risk."
}

# Color Configuration
$Colors = @{
    "Title" = "Cyan"
    "Section" = "Yellow"
    "Normal" = "White"
    "Success" = "Green"
    "Warning" = "Yellow"
    "Error" = "Red"
    "Info" = "Blue"
    "Highlight" = "Magenta"
}
#endregion

#region Helper Functions
function Write-ColorOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$ForegroundColor = $Colors.Normal,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoNewLine
    )
    
    if ($NoNewLine) {
        Write-Host $Message -ForegroundColor $ForegroundColor -NoNewline
    }
    else {
        Write-Host $Message -ForegroundColor $ForegroundColor
    }
}

function Write-SectionHeader {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Title
    )
    
    Write-Host ""
    Write-ColorOutput "===== $Title ====="  -ForegroundColor $Colors.Section
    Write-Host ""
}

function Test-IsIPAddress {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputString
    )
    
    $IPRegex = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return $InputString -match $IPRegex
}

function Format-DataTable {
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Data,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Columns,
        
        [Parameter(Mandatory = $false)]
        [int]$Padding = 2,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxValueWidth = 80
    )
    
    # Calculate column widths
    $columnWidths = @{}
    foreach ($column in $Columns) {
        $maxWidth = $column.Length
        foreach ($row in $Data) {
            if ($row.$column -and $row.$column.ToString().Length -gt $maxWidth) {
                # Limit the width of the Value column
                if ($column -eq "Value" -and $row.$column.ToString().Length -gt $MaxValueWidth) {
                    $maxWidth = $MaxValueWidth
                } else {
                    $maxWidth = $row.$column.ToString().Length
                }
            }
        }
        $columnWidths[$column] = $maxWidth + $Padding
    }
    
    # Print header
    $headerLine = ""
    foreach ($column in $Columns) {
        $headerLine += $column.PadRight($columnWidths[$column])
    }
    Write-ColorOutput $headerLine -ForegroundColor $Colors.Highlight
    
    # Print separator
    $separatorLine = ""
    foreach ($column in $Columns) {
        $separatorLine += "-" * ($columnWidths[$column] - 1) + " "
    }
    Write-ColorOutput $separatorLine -ForegroundColor $Colors.Normal
    
    # Print data rows with wrapping for long values
    foreach ($row in $Data) {
        $valueLines = @{}
        
        # Split long values into multiple lines
        foreach ($column in $Columns) {
            $value = if ($row.$column) { $row.$column.ToString() } else { "" }
            
            if ($column -eq "Value" -and $value.Length -gt $columnWidths[$column] - $Padding) {
                # Split long values into chunks
                $chunks = [System.Collections.ArrayList]::new()
                $remainingValue = $value
                
                while ($remainingValue.Length -gt 0) {
                    $chunkSize = [Math]::Min($columnWidths[$column] - $Padding, $remainingValue.Length)
                    $chunk = $remainingValue.Substring(0, $chunkSize)
                    $null = $chunks.Add($chunk)
                    $remainingValue = $remainingValue.Substring([Math]::Min($chunkSize, $remainingValue.Length))
                }
                
                $valueLines[$column] = $chunks
            } else {
                $valueLines[$column] = @($value)
            }
        }
        
        # Determine the maximum number of lines needed
        $maxLines = 1
        foreach ($column in $Columns) {
            if ($valueLines[$column].Count -gt $maxLines) {
                $maxLines = $valueLines[$column].Count
            }
        }
        
        # Print each line of the row
        for ($i = 0; $i -lt $maxLines; $i++) {
            $dataLine = ""
            
            foreach ($column in $Columns) {
                $lineValue = if ($i -lt $valueLines[$column].Count) { $valueLines[$column][$i] } else { "" }
                
                # Only pad with spaces if this isn't the last column or if it's not the Value column
                if ($column -ne "Value" -or $Columns[-1] -ne $column) {
                    $dataLine += $lineValue.PadRight($columnWidths[$column])
                } else {
                    $dataLine += $lineValue
                }
            }
            
            Write-ColorOutput $dataLine -ForegroundColor $Colors.Normal
        }
    }
}

function Get-FormattedDate {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DateString
    )
    
    try {
        $date = [DateTime]::Parse($DateString)
        return $date.ToString("yyyy-MM-dd")
    }
    catch {
        return $DateString
    }
}
#endregion

#region DNS Functions
function Get-DNSRecords {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        
        [Parameter(Mandatory = $false)]
        [string]$DNSServer = $DefaultDNSServer
    )
    
    Write-SectionHeader "DNS Records for $Domain"
    
    $results = [System.Collections.ArrayList]@()
    $securityIssues = [System.Collections.ArrayList]@()
    $hasMX = $false
    $hasSPF = $false
    $hasDMARC = $false
    
    # Check standard DNS records
    foreach ($recordType in $DNSRecordTypes) {
        try {
            Write-ColorOutput "Checking $recordType records..." -ForegroundColor $Colors.Info -NoNewLine
            $records = Resolve-DnsName -Name $Domain -Type $recordType -Server $DNSServer -ErrorAction SilentlyContinue
            
            if ($records) {
                Write-ColorOutput " Found!" -ForegroundColor $Colors.Success
                
                foreach ($record in $records) {
                    $recordData = @{
                        "RecordType" = $recordType
                        "Name" = $record.Name
                        "Value" = ""
                        "TTL" = $record.TTL
                    }
                    
                    # Extract the appropriate value based on record type
                    switch ($recordType) {
                        "A" { $recordData.Value = $record.IPAddress }
                        "AAAA" { $recordData.Value = $record.IPAddress }
                        "MX" { 
                            $recordData.Value = "$($record.NameExchange) (Pref: $($record.Preference))"
                            $hasMX = $true
                        }
                        "TXT" { 
                            $recordData.Value = $record.Strings -join " "
                            # Check for SPF record
                            if ($recordData.Value -like "v=spf1*") {
                                $hasSPF = $true
                                # Check for weak SPF
                                if ($recordData.Value -like "*+all*" -or $recordData.Value -like "*?all*") {
                                    $null = $securityIssues.Add($SecurityChecks.WeakSPF)
                                }
                            }
                        }
                        "NS" { $recordData.Value = $record.NameHost }
                        "SOA" { $recordData.Value = "$($record.PrimaryServer) $($record.NameAdministrator)" }
                        "CNAME" { $recordData.Value = $record.NameHost }
                        "PTR" { $recordData.Value = $record.NameHost }
                        "SRV" { $recordData.Value = "$($record.NameTarget) (Priority: $($record.Priority), Weight: $($record.Weight), Port: $($record.Port))" }
                        default { $recordData.Value = "[Complex Data]" }
                    }
                    
                    $null = $results.Add([PSCustomObject]$recordData)
                }
            }
            else {
                Write-ColorOutput " Not found." -ForegroundColor $Colors.Warning
                
                # Add security issues for missing critical records
                if ($recordType -eq "MX") {
                    $null = $securityIssues.Add($SecurityChecks.MissingMXRecord)
                }
            }
        }
        catch {
            Write-ColorOutput " Error: $($_.Exception.Message)" -ForegroundColor $Colors.Error
        }
    }
    
    # Check for DMARC record
    try {
        Write-ColorOutput "Checking DMARC record..." -ForegroundColor $Colors.Info -NoNewLine
        $dmarcRecords = Resolve-DnsName -Name "_dmarc.$Domain" -Type TXT -Server $DNSServer -ErrorAction SilentlyContinue
        
        if ($dmarcRecords) {
            Write-ColorOutput " Found!" -ForegroundColor $Colors.Success
            $hasDMARC = $true
            
            foreach ($record in $dmarcRecords) {
                $dmarcValue = $record.Strings -join " "
                $null = $results.Add([PSCustomObject]@{
                    "RecordType" = "DMARC"
                    "Name" = "_dmarc.$Domain"
                    "Value" = $dmarcValue
                    "TTL" = $record.TTL
                })
                
                # Check for weak DMARC policy
                if ($dmarcValue -like "*p=none*") {
                    $null = $securityIssues.Add($SecurityChecks.WeakDMARC)
                }
            }
        }
        else {
            Write-ColorOutput " Not found." -ForegroundColor $Colors.Warning
            $null = $securityIssues.Add($SecurityChecks.MissingDMARC)
        }
    }
    catch {
        Write-ColorOutput " Error: $($_.Exception.Message)" -ForegroundColor $Colors.Error
    }
    
    # Check for DKIM records (common selectors)
    $dkimSelectors = @("default", "google", "selector1", "selector2", "k1", "dkim")
    foreach ($selector in $dkimSelectors) {
        try {
            Write-ColorOutput "Checking DKIM record ($selector)..." -ForegroundColor $Colors.Info -NoNewLine
            $dkimRecords = Resolve-DnsName -Name "$selector._domainkey.$Domain" -Type TXT -Server $DNSServer -ErrorAction SilentlyContinue
            
            if ($dkimRecords) {
                Write-ColorOutput " Found!" -ForegroundColor $Colors.Success
                
                foreach ($record in $dkimRecords) {
                    $null = $results.Add([PSCustomObject]@{
                        "RecordType" = "DKIM"
                        "Name" = "$selector._domainkey.$Domain"
                        "Value" = $record.Strings -join " "
                        "TTL" = $record.TTL
                    })
                }
            }
            else {
                Write-ColorOutput " Not found." -ForegroundColor $Colors.Warning
            }
        }
        catch {
            # Silently continue for DKIM checks as many selectors won't exist
        }
    }
    
    # Check for CAA records using type 257 (CAA record type code)
    try {
        Write-ColorOutput "Checking CAA records..." -ForegroundColor $Colors.Info -NoNewLine
        
        # Try with Resolve-DnsName and type 257 (CAA)
        try {
            $caaRecords = Resolve-DnsName -Name $Domain -Type 257 -Server $DNSServer -ErrorAction Stop
            
            if ($caaRecords) {
                Write-ColorOutput " Found!" -ForegroundColor $Colors.Success
                
                foreach ($record in $caaRecords) {
                    $null = $results.Add([PSCustomObject]@{
                        "RecordType" = "CAA"
                        "Name" = $Domain
                        "Value" = $record.RecordData
                        "TTL" = $record.TTL
                    })
                }
            }
            else {
                throw "No CAA records found"
            }
        }
        catch {
            # If PowerShell's Resolve-DnsName fails, try nslookup as fallback
            $caaCheckCommand = "nslookup -type=257 $Domain $DNSServer" # 257 is the type code for CAA
            $caaOutput = Invoke-Expression $caaCheckCommand -ErrorAction SilentlyContinue
            
            if ($caaOutput -match "257" -or $caaOutput -match "CAA" -or $caaOutput -match "issue") {
                Write-ColorOutput " Found!" -ForegroundColor $Colors.Success
                
                # Add a generic CAA record since parsing nslookup output is unreliable
                $null = $results.Add([PSCustomObject]@{
                    "RecordType" = "CAA"
                    "Name" = $Domain
                    "Value" = "CAA record found (see raw output for details)"
                    "TTL" = "N/A"
                })
            }
            else {
                Write-ColorOutput " Not found." -ForegroundColor $Colors.Warning
                $null = $securityIssues.Add($SecurityChecks.MissingCAA)
            }
        }
    }
    catch {
        Write-ColorOutput " Error checking CAA records: $($_.Exception.Message)" -ForegroundColor $Colors.Error
        $null = $securityIssues.Add($SecurityChecks.MissingCAA)
    }
    
    # Display results
    if ($results.Count -gt 0) {
        Write-Host ""
        Write-ColorOutput "DNS Records Found:" -ForegroundColor $Colors.Highlight
        Write-Host ""
        
        # Always display the table, even if output is being redirected
        $originalPreference = $global:ProgressPreference
        $global:ProgressPreference = 'Continue'
        
        Format-DataTable -Data $results -Columns @("RecordType", "Name", "Value", "TTL") -MaxValueWidth 80
        
        $global:ProgressPreference = $originalPreference
    }
    else {
        Write-ColorOutput "No DNS records found for $Domain" -ForegroundColor $Colors.Warning
    }
    
    # Display security issues
    if ($securityIssues.Count -gt 0) {
        Write-Host ""
        Write-ColorOutput "Security Issues Detected:" -ForegroundColor $Colors.Error
        foreach ($issue in $securityIssues) {
            Write-ColorOutput " - $issue" -ForegroundColor $Colors.Warning
        }
    }
    
    return $results
}
#endregion

#region WHOIS Functions
function Get-WhoisInformation {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target
    )
    
    Write-SectionHeader "WHOIS Information for $Target"
    
    try {
        # Determine if target is an IP or domain
        $isIP = Test-IsIPAddress -InputString $Target
        
        # Clean the target to ensure it's a valid hostname/IP without protocol prefixes
        $cleanTarget = $Target -replace "^https?://", "" -replace "/.*$", ""
        
        if ($isIP) {
            # Use WhoisXML API for IP WHOIS
            $uri = "$WhoisXMLAPIEndpoint?apiKey=$WhoisXMLAPIKey&outputFormat=JSON&ip=$cleanTarget"
        }
        else {
            # Use WhoisXML API for domain WHOIS
            $uri = "$WhoisXMLAPIEndpoint?apiKey=$WhoisXMLAPIKey&outputFormat=JSON&domainName=$cleanTarget"
        }
        
        Write-ColorOutput "Querying WHOIS information..." -ForegroundColor $Colors.Info
        $response = Invoke-RestMethod -Uri $uri -Method Get
        
        if ($response.WhoisRecord) {
            $whoisData = $response.WhoisRecord
            
            # Display basic information
            Write-ColorOutput "Domain Information:" -ForegroundColor $Colors.Highlight
            Write-ColorOutput "Domain Name: $($whoisData.domainName)" -ForegroundColor $Colors.Normal
            
            if ($whoisData.registryData) {
                Write-ColorOutput "Registrar: $($whoisData.registryData.registrarName)" -ForegroundColor $Colors.Normal
                
                # Format dates
                $createdDate = Get-FormattedDate -DateString $whoisData.registryData.createdDate
                $updatedDate = Get-FormattedDate -DateString $whoisData.registryData.updatedDate
                $expiresDate = Get-FormattedDate -DateString $whoisData.registryData.expiresDate
                
                Write-ColorOutput "Created Date: $createdDate" -ForegroundColor $Colors.Normal
                Write-ColorOutput "Updated Date: $updatedDate" -ForegroundColor $Colors.Normal
                Write-ColorOutput "Expires Date: $expiresDate" -ForegroundColor $Colors.Normal
                
                # Check for recently created domains (potential phishing)
                $createdDateTime = [DateTime]::Parse($whoisData.registryData.createdDate)
                $daysSinceCreation = (Get-Date) - $createdDateTime
                if ($daysSinceCreation.TotalDays -lt 30) {
                    Write-ColorOutput "WARNING: Domain was created recently ($([int]$daysSinceCreation.TotalDays) days ago)" -ForegroundColor $Colors.Warning
                }
                
                # Check for domains about to expire
                $expiresDateTime = [DateTime]::Parse($whoisData.registryData.expiresDate)
                $daysUntilExpiration = $expiresDateTime - (Get-Date)
                if ($daysUntilExpiration.TotalDays -lt 30) {
                    Write-ColorOutput "WARNING: Domain is about to expire in $([int]$daysUntilExpiration.TotalDays) days" -ForegroundColor $Colors.Warning
                }
            }
            
            # Display nameservers
            if ($whoisData.nameServers -and $whoisData.nameServers.hostNames) {
                Write-Host ""
                Write-ColorOutput "Nameservers:" -ForegroundColor $Colors.Highlight
                foreach ($ns in $whoisData.nameServers.hostNames) {
                    Write-ColorOutput " - $ns" -ForegroundColor $Colors.Normal
                }
            }
            
            # Display registrant information if available
            if ($whoisData.registrant) {
                Write-Host ""
                Write-ColorOutput "Registrant Information:" -ForegroundColor $Colors.Highlight
                Write-ColorOutput "Organization: $($whoisData.registrant.organization)" -ForegroundColor $Colors.Normal
                Write-ColorOutput "Country: $($whoisData.registrant.country)" -ForegroundColor $Colors.Normal
                
                # Check for privacy protection
                if ($whoisData.registrant.organization -match "privacy|protect|proxy|redact|private" -or 
                    $whoisData.registrantContact.organization -match "privacy|protect|proxy|redact|private") {
                    Write-ColorOutput "NOTE: Domain appears to use WHOIS privacy protection" -ForegroundColor $Colors.Info
                }
            }
            
            # Display raw WHOIS text if available
            if ($whoisData.rawText) {
                Write-Host ""
                Write-ColorOutput "Raw WHOIS Data:" -ForegroundColor $Colors.Highlight
                Write-ColorOutput "$($whoisData.rawText)" -ForegroundColor $Colors.Normal
            }
        }
        else {
            Write-ColorOutput "No WHOIS information found for $Target" -ForegroundColor $Colors.Warning
        }
    }
    catch {
        #Write-ColorOutput "Error retrieving WHOIS information: $($_.Exception.Message)" -ForegroundColor $Colors.Error
        
        # Try alternative API
        try {
            Write-ColorOutput "Trying alternative WHOIS API..." -ForegroundColor $Colors.Info
            
            $headers = @{
                "Authorization" = "TOKEN=$WhoisJSONAPIKey"
            }
            
            # Clean the target to ensure it's a valid hostname without protocol prefixes
            $cleanTarget = $Target -replace "^https?://", "" -replace "/.*$", ""
            
            $uri = "$WhoisJSONEndpoint?domain=$cleanTarget"
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
            
            if ($response.domain) {
                Write-ColorOutput "Domain Information:" -ForegroundColor $Colors.Highlight
                Write-ColorOutput "Domain Name: $($response.domain)" -ForegroundColor $Colors.Normal
                Write-ColorOutput "Registrar: $($response.registrar)" -ForegroundColor $Colors.Normal
                Write-ColorOutput "Created Date: $($response.created_date)" -ForegroundColor $Colors.Normal
                Write-ColorOutput "Updated Date: $($response.updated_date)" -ForegroundColor $Colors.Normal
                Write-ColorOutput "Expires Date: $($response.expiry_date)" -ForegroundColor $Colors.Normal
                
                # Display nameservers
                if ($response.nameservers) {
                    Write-Host ""
                    Write-ColorOutput "Nameservers:" -ForegroundColor $Colors.Highlight
                    foreach ($ns in $response.nameservers) {
                        Write-ColorOutput " - $ns" -ForegroundColor $Colors.Normal
                    }
                }
            }
            else {
                Write-ColorOutput "No WHOIS information found from alternative API" -ForegroundColor $Colors.Warning
            }
        }
        catch {
            #Write-ColorOutput "Error with alternative WHOIS API: $($_.Exception.Message)" -ForegroundColor $Colors.Error
        }
    }
}
#endregion

#region IP Geolocation Functions
function Get-IPGeolocation {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    
    Write-SectionHeader "IP Geolocation for $IPAddress"
    
    try {
        Write-ColorOutput "Querying IP geolocation information..." -ForegroundColor $Colors.Info
        $uri = "$IPGeolocationEndpoint/$IPAddress"
        $response = Invoke-RestMethod -Uri $uri -Method Get
        
        if ($response.status -eq "success") {
            Write-ColorOutput "Location Information:" -ForegroundColor $Colors.Highlight
            Write-ColorOutput "IP Address: $($response.query)" -ForegroundColor $Colors.Normal
            Write-ColorOutput "Country: $($response.country) ($($response.countryCode))" -ForegroundColor $Colors.Normal
            Write-ColorOutput "Region: $($response.regionName) ($($response.region))" -ForegroundColor $Colors.Normal
            Write-ColorOutput "City: $($response.city)" -ForegroundColor $Colors.Normal
            Write-ColorOutput "Zip Code: $($response.zip)" -ForegroundColor $Colors.Normal
            Write-ColorOutput "Coordinates: $($response.lat), $($response.lon)" -ForegroundColor $Colors.Normal
            Write-ColorOutput "Timezone: $($response.timezone)" -ForegroundColor $Colors.Normal
            
            Write-Host ""
            Write-ColorOutput "Network Information:" -ForegroundColor $Colors.Highlight
            Write-ColorOutput "ISP: $($response.isp)" -ForegroundColor $Colors.Normal
            Write-ColorOutput "Organization: $($response.org)" -ForegroundColor $Colors.Normal
            Write-ColorOutput "AS: $($response.as)" -ForegroundColor $Colors.Normal
            
            # Check for potentially suspicious locations
            $suspiciousCountries = @("RU", "CN", "IR", "KP", "SY")
            if ($suspiciousCountries -contains $response.countryCode) {
                Write-Host ""
                Write-ColorOutput "SECURITY ALERT: IP is from a potentially high-risk country ($($response.country))" -ForegroundColor $Colors.Error
            }
            
            # Generate Google Maps link
            $mapsUrl = "https://www.google.com/maps?q=$($response.lat),$($response.lon)"
            Write-Host ""
            Write-ColorOutput "Google Maps Link: $mapsUrl" -ForegroundColor $Colors.Info
        }
        else {
            Write-ColorOutput "Failed to retrieve geolocation information" -ForegroundColor $Colors.Warning
        }
    }
    catch {
        Write-ColorOutput "Error retrieving IP geolocation: $($_.Exception.Message)" -ForegroundColor $Colors.Error
    }
}
#endregion

#region Main Execution
function Start-DNSLookup {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target
    )
    
    # Clear screen and show title
    Clear-Host
    Write-ColorOutput "===================================" -ForegroundColor $Colors.Title
    Write-ColorOutput "     DNS Reconnaissance TOOL       " -ForegroundColor $Colors.Title
    Write-ColorOutput "===================================" -ForegroundColor $Colors.Title
    Write-Host ""
    Write-ColorOutput "Target: $Target" -ForegroundColor $Colors.Highlight
    Write-ColorOutput "Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $Colors.Normal
    Write-Host ""
    
    # Determine if target is an IP or domain
    $isIP = Test-IsIPAddress -InputString $Target
    
    if ($isIP) {
        # For IP addresses, get geolocation and reverse DNS
        Get-IPGeolocation -IPAddress $Target
        
        # Try to get reverse DNS
        try {
            Write-SectionHeader "Reverse DNS for $Target"
            $reverseDNS = Resolve-DnsName -Name $Target -Type PTR -ErrorAction SilentlyContinue
            
            if ($reverseDNS) {
                Write-ColorOutput "Hostname: $($reverseDNS.NameHost)" -ForegroundColor $Colors.Success
                
                # If we got a hostname, also check its DNS records
                $hostname = $reverseDNS.NameHost
                Get-DNSRecords -Domain $hostname
            }
            else {
                Write-ColorOutput "No reverse DNS record found for $Target" -ForegroundColor $Colors.Warning
            }
        }
        catch {
            Write-ColorOutput "Error retrieving reverse DNS: $($_.Exception.Message)" -ForegroundColor $Colors.Error
        }
        
        # Get WHOIS information for the IP
        Get-WhoisInformation -Target $Target
    }
    else {
        # For domains, get DNS records, WHOIS, and IP geolocation
        $dnsRecords = Get-DNSRecords -Domain $Target
        Get-WhoisInformation -Target $Target
        
        # Get IP geolocation for A records
        $aRecords = $dnsRecords | Where-Object { $_.RecordType -eq "A" }
        if ($aRecords) {
            foreach ($record in $aRecords) {
                Get-IPGeolocation -IPAddress $record.Value
            }
        }
    }
    
    Write-Host ""
    Write-ColorOutput "===================================" -ForegroundColor $Colors.Title
    Write-ColorOutput "          SCAN COMPLETE           " -ForegroundColor $Colors.Title
    Write-ColorOutput "===================================" -ForegroundColor $Colors.Title
}

# Execute the main function

# If no target is provided as a command-line argument, prompt the user
if (-not $Target) {
    $Target = Read-Host "Enter domain, URL, or IP to get started"
}

# Remove any http/https prefixes or trailing slashes from the target
$Target = $Target.Replace("http://", "").Replace("https://", "").TrimEnd('/')

Start-DNSLookup -Target $Target
#endregion