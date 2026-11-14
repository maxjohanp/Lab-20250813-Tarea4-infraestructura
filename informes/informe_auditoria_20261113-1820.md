# Informe de auditoría CIS

- **Estudiante:** Maxyohan Montas Peña · matrícula 2025-0813 · Seguridad de Redes
- **Fecha y hora:** 13/11/2026 18:20:42 · PC: Iso
- **Modo:** AUDITAR

## Resumen

| Equipo | Benchmark | Cumplimiento |
|---|---|---|
| R-0813 | CIS Cisco IOS 15 Benchmark v4.1.1 | 12 % (3 de 24) |
| SW-0813 | CIS Cisco IOS 15 Benchmark v4.1.1 | 21 % (5 de 24) |
| FW-0813 | CIS Fortigate 7.0.x Benchmark v1.3.0 | 17 % (2 de 12) |

## R-0813 · Router Cisco 7200 (IOS 15.2) (10.20.25.1)

| ID | Recomendación CIS | Estado | Evidencia |
|---|---|---|---|
| 1.1.1 | Enable 'aaa new-model' | ❌ No cumple | no aaa new-model |
| 1.1.2 | Enable 'aaa authentication login' | ❌ No cumple | (no está en la configuración) |
| 1.2.2 | Set 'transport input ssh' for 'line vty' connections | ❌ No cumple | line vty 0 4: transport input telnet ssh |
| 1.2.3 | Set 'no exec' for 'line aux 0' | ❌ No cumple | line aux 0 permite sesiones (exec) |
| 1.2.4 | Create 'access-list' for use with 'line vty' | ❌ No cumple | ACL 113: no existe o está incompleta |
| 1.2.5 | Set 'access-class' for 'line vty' | ❌ No cumple | line vty 0 4: sin access-class |
| 1.2.7 | Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0' | ❌ No cumple | line con 0: exec-timeout 0 0 |
| 1.2.9 | Set 'exec-timeout' to less than or equal to 10 minutes 'line vty' | ✅ Cumple | line vty 0 4: valor por defecto (10 min) |
| 1.3.2 | Set the 'banner-text' for 'banner login' | ❌ No cumple | sin banner login |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | ❌ No cumple | sin banner motd |
| 1.4.1 | Set 'password' for 'enable secret' | ✅ Cumple | enable secret presente |
| 1.4.2 | Enable 'service password-encryption' | ❌ No cumple | (no está en la configuración) |
| 1.4.3 | Set 'username secret' for all local users | ✅ Cumple | usuarios con secret: admin |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | ❌ No cumple | valor por defecto (120 s) |
| 2.1.1.2 | Set version 2 for 'ip ssh version' | ❌ No cumple | sin 'ip ssh version' (acepta v1 y v2) |
| 2.1.2 | Set 'no cdp run' | ❌ No cumple | falta 'no cdp run' |
| 2.1.3 | Set 'no ip bootp server' | ❌ No cumple | falta 'no ip bootp server' |
| 2.1.4 | Set 'no service dhcp' | ❌ No cumple | falta 'no service dhcp' |
| 2.1.6 | Set 'service tcp-keepalives-in' | ❌ No cumple | falta 'service tcp-keepalives-in' |
| 2.1.7 | Set 'service tcp-keepalives-out' | ❌ No cumple | falta 'service tcp-keepalives-out' |
| 2.1.8 | Set 'no service pad' | ❌ No cumple | falta 'no service pad' |
| 2.2.2 | Set 'buffer size' for 'logging buffered' | ❌ No cumple | falta 'logging buffered 64000' |
| 2.2.3 | Set 'logging console critical' | ❌ No cumple | falta 'logging console critical' |
| 3.1.1 | Set 'no ip source-route' | ❌ No cumple | falta 'no ip source-route' |

## SW-0813 · Switch Cisco IOSvL2 (IOS 15.2) (10.20.25.2)

| ID | Recomendación CIS | Estado | Evidencia |
|---|---|---|---|
| 1.1.1 | Enable 'aaa new-model' | ❌ No cumple | no aaa new-model |
| 1.1.2 | Enable 'aaa authentication login' | ❌ No cumple | (no está en la configuración) |
| 1.2.2 | Set 'transport input ssh' for 'line vty' connections | ❌ No cumple | line vty 0 4: transport input telnet ssh; line vty 5 15: transport input telnet ssh |
| 1.2.3 | Set 'no exec' for 'line aux 0' | ❌ No cumple | line aux 0 permite sesiones (exec) |
| 1.2.4 | Create 'access-list' for use with 'line vty' | ❌ No cumple | ACL 113: no existe o está incompleta |
| 1.2.5 | Set 'access-class' for 'line vty' | ❌ No cumple | line vty 0 4: sin access-class; line vty 5 15: sin access-class |
| 1.2.7 | Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0' | ✅ Cumple | line con 0: valor por defecto (10 min) |
| 1.2.9 | Set 'exec-timeout' to less than or equal to 10 minutes 'line vty' | ✅ Cumple | line vty 0 4: valor por defecto (10 min); line vty 5 15: valor por defecto (10 min) |
| 1.3.2 | Set the 'banner-text' for 'banner login' | ✅ Cumple | banner login configurado |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | ❌ No cumple | sin banner motd |
| 1.4.1 | Set 'password' for 'enable secret' | ✅ Cumple | enable secret presente |
| 1.4.2 | Enable 'service password-encryption' | ❌ No cumple | no service password-encryption |
| 1.4.3 | Set 'username secret' for all local users | ✅ Cumple | usuarios con secret: admin |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | ❌ No cumple | valor por defecto (120 s) |
| 2.1.1.2 | Set version 2 for 'ip ssh version' | ❌ No cumple | sin 'ip ssh version' (acepta v1 y v2) |
| 2.1.2 | Set 'no cdp run' | ❌ No cumple | falta 'no cdp run' |
| 2.1.3 | Set 'no ip bootp server' | ❌ No cumple | falta 'no ip bootp server' |
| 2.1.4 | Set 'no service dhcp' | ❌ No cumple | falta 'no service dhcp' |
| 2.1.6 | Set 'service tcp-keepalives-in' | ❌ No cumple | falta 'service tcp-keepalives-in' |
| 2.1.7 | Set 'service tcp-keepalives-out' | ❌ No cumple | falta 'service tcp-keepalives-out' |
| 2.1.8 | Set 'no service pad' | ❌ No cumple | falta 'no service pad' |
| 2.2.2 | Set 'buffer size' for 'logging buffered' | ❌ No cumple | falta 'logging buffered 64000' |
| 2.2.3 | Set 'logging console critical' | ❌ No cumple | falta 'logging console critical' |
| 3.1.1 | Set 'no ip source-route' | ❌ No cumple | falta 'no ip source-route' |

## FW-0813 · Firewall FortiGate-VM 7.0.9 (10.8.13.1)

| ID | Recomendación CIS | Estado | Evidencia |
|---|---|---|---|
| 1.3 | Disable all management related services on WAN port | ❌ No cumple | port1 allowaccess: ping https ssh http fgfm |
| 2.1.1 | Ensure 'Pre-Login Banner' is set | ❌ No cumple | pre-login-banner disable |
| 2.1.2 | Ensure 'Post-Login-Banner' is set | ❌ No cumple | post-login-banner disable |
| 2.1.3 | Ensure timezone is properly configured | ❌ No cumple | timezone 04 (esperado 15) |
| 2.1.5 | Ensure hostname is set | ✅ Cumple | hostname FW-0813 |
| 2.2.1 | Ensure 'Password Policy' is enabled | ❌ No cumple | password-policy status disable, minimum-length 8 |
| 2.2.2 | Ensure administrator password retries and lockout time are configured | ❌ No cumple | admin-lockout-threshold 3, admin-lockout-duration 60 |
| 2.4.2 | Ensure all the login accounts having specific trusted hosts enabled | ❌ No cumple | sin trusted hosts: admin |
| 2.4.4 | Ensure idle timeout time is configured | ✅ Cumple | admintimeout 5 |
| 2.4.5 | Ensure only encrypted access channels are enabled | ❌ No cumple | port1: ping https ssh http fgfm; port2: ping https ssh http |
| 3.2 | Ensure that policies do not use "ALL" as Service | ❌ No cumple | políticas con ALL: 1 |
| 3.4 | Ensure logging is enabled on all firewall policies | ❌ No cumple | políticas sin 'logtraffic all': 1 |
