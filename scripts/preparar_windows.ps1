# preparar_windows.ps1 - Maxyohan Montas Pena - 2025-0813
# Deja la PC Windows como "PC-ADMIN" del laboratorio:
#   1) agrega la IP 10.20.25.100/24 al adaptador solo-anfitrion de VirtualBox
#   2) agrega la ruta hacia el enlace router-firewall (10.8.13.0/30)
#
# Uso (PowerShell COMO ADMINISTRADOR, dentro de la carpeta del repositorio):
#   powershell -ExecutionPolicy Bypass -File scripts\preparar_windows.ps1
#
# Para deshacerlo:  powershell -ExecutionPolicy Bypass -File scripts\limpiar_windows.ps1

param(
    [string]$IpAdmin     = "10.20.25.100",
    [string]$RedGns3     = "192.168.56.",      # red solo-anfitrion donde vive la GNS3 VM
    [string]$Gateway     = "10.20.25.1",       # R-0813
    [string]$RedTransito = "10.8.13.0",
    [string]$MascTrans   = "255.255.255.252"
)

$esAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $esAdmin) {
    Write-Host "Abre PowerShell como Administrador y vuelve a ejecutar." -ForegroundColor Red
    exit 1
}

# Adaptadores solo-anfitrion de VirtualBox; se prefiere el que esta en la red de la GNS3 VM
$candidatos = Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -like "*VirtualBox Host-Only*" -and $_.Status -eq "Up" }
if (-not $candidatos) {
    Write-Host "No hay un adaptador 'VirtualBox Host-Only' activo. Abre VirtualBox y revisa la red solo-anfitrion." -ForegroundColor Red
    exit 1
}
$adaptador = $candidatos | Where-Object {
    Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -like "$RedGns3*" } } | Select-Object -First 1
if (-not $adaptador) { $adaptador = $candidatos | Select-Object -First 1 }
Write-Host "Adaptador: $($adaptador.Name)  ($($adaptador.InterfaceDescription))"

if (Get-NetIPAddress -IPAddress $IpAdmin -ErrorAction SilentlyContinue) {
    Write-Host "La IP $IpAdmin ya estaba configurada."
} else {
    New-NetIPAddress -InterfaceIndex $adaptador.ifIndex -IPAddress $IpAdmin -PrefixLength 24 `
        -ErrorAction Stop | Out-Null
    Start-Sleep -Seconds 3      # Windows tarda un momento en activar la direccion
    Write-Host "IP $IpAdmin/24 agregada." -ForegroundColor Green
}

route delete $RedTransito 2>$null | Out-Null
route -p add $RedTransito mask $MascTrans $Gateway | Out-Null
Write-Host "Ruta $RedTransito/30 via $Gateway agregada." -ForegroundColor Green

Write-Host ""
Write-Host "Prueba ahora:  ping 10.20.25.1   ping 10.20.25.2   ping 10.8.13.1"
