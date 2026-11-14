# limpiar_windows.ps1 - Maxyohan Montas Pena - 2025-0813
# Deshace lo que hizo preparar_windows.ps1 (IP 10.20.25.100 y ruta a 10.8.13.0/30).
#
# Uso (PowerShell COMO ADMINISTRADOR):
#   powershell -ExecutionPolicy Bypass -File scripts\limpiar_windows.ps1

param(
    [string]$IpAdmin     = "10.20.25.100",
    [string]$RedTransito = "10.8.13.0"
)

Get-NetIPAddress -IPAddress $IpAdmin -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false
route delete $RedTransito 2>$null | Out-Null
Write-Host "Listo: se quitaron la IP $IpAdmin y la ruta a $RedTransito." -ForegroundColor Green
