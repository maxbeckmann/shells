#!/usr/bin/pwsh
# Get the template path from command-line arguments
param(
    [string]$TemplatePath
)

if (-not $TemplatePath) {
    Write-Error "Usage: .\generate.ps1 -TemplatePath <path_to_template.aspx>"
    exit 1
}

if (-Not (Test-Path $TemplatePath)) {
    Write-Error "Error: Template file '$TemplatePath' not found. Please provide a valid template path."
    exit 1
}

# Generate a secure alphanumeric password
$length = 20
$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" -split ''
$password = -join (1..$length | ForEach-Object { Get-Random -InputObject $chars })

# Define a random salt
$salt = -join (1..16 | ForEach-Object { Get-Random -InputObject $chars })

# Compute the salted SHA-256 hash
$bytes = [System.Text.Encoding]::UTF8.GetBytes($password + $salt)
$hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
$hashBase64 = [Convert]::ToBase64String($hash)

# Output the password
Write-Output "Generated Password: $password"

# Read the ASPX template file
$aspxContent = Get-Content -Path $TemplatePath -Raw

# Replace placeholders with generated values
$aspxPatched = $aspxContent -replace "__SALT__", $salt -replace "__HASH__", $hashBase64

# Write the patched ASPX file
$aspxFile = "$PWD/stored_auth.aspx"
$aspxPatched | Set-Content -Path $aspxFile

Write-Output "ASPX file with patched credentials stored in: $aspxFile"

# Allow running without password if needed
if ($false) { # Change to $true to enforce password requirement
    $password = ""
    $salt = ""
    $hashBase64 = ""
}
