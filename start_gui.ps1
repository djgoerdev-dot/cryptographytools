# PowerShell launcher for RSA Encryption/Decryption Tool
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Starting RSA Private Encrypt & Public Decrypt Tool... " -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
python "$ScriptDir\server.py" --port 5000
