# Informe póstumo de hardening CIS

- **Estudiante:** Maxyohan Montas Peña · matrícula 2025-0813 · Seguridad de Redes
- **Fecha y hora:** 13/11/2026 19:48:20 · PC: Iso
- **Modo:** APLICAR

## Resumen

| Equipo | Benchmark | Antes | Después |
|---|---|---|---|
| R-0813 | CIS Cisco IOS 15 Benchmark v4.1.1 | 100 % | 100 % |

## R-0813 · Router Cisco 7200 (IOS 15.2) (10.20.25.1)

| ID | Recomendación CIS | Antes | Después | Comandos aplicados |
|---|---|---|---|---|
| 1.1.1 | Enable 'aaa new-model' | ✅ Cumple | ✅ Cumple |  |
| 1.1.2 | Enable 'aaa authentication login' | ✅ Cumple | ✅ Cumple |  |
| 1.2.2 | Set 'transport input ssh' for 'line vty' connections | ✅ Cumple | ✅ Cumple |  |
| 1.2.3 | Set 'no exec' for 'line aux 0' | ✅ Cumple | ✅ Cumple |  |
| 1.2.4 | Create 'access-list' for use with 'line vty' | ✅ Cumple | ✅ Cumple |  |
| 1.2.5 | Set 'access-class' for 'line vty' | ✅ Cumple | ✅ Cumple |  |
| 1.2.7 | Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0' | ✅ Cumple | ✅ Cumple |  |
| 1.2.9 | Set 'exec-timeout' to less than or equal to 10 minutes 'line vty' | ✅ Cumple | ✅ Cumple |  |
| 1.3.2 | Set the 'banner-text' for 'banner login' | ✅ Cumple | ✅ Cumple |  |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | ✅ Cumple | ✅ Cumple |  |
| 1.4.1 | Set 'password' for 'enable secret' | ✅ Cumple | ✅ Cumple |  |
| 1.4.2 | Enable 'service password-encryption' | ✅ Cumple | ✅ Cumple |  |
| 1.4.3 | Set 'username secret' for all local users | ✅ Cumple | ✅ Cumple |  |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | ✅ Cumple | ✅ Cumple |  |
| 2.1.1.2 | Set version 2 for 'ip ssh version' | ✅ Cumple | ✅ Cumple |  |
| 2.1.2 | Set 'no cdp run' | ✅ Cumple | ✅ Cumple |  |
| 2.1.3 | Set 'no ip bootp server' | ✅ Cumple | ✅ Cumple |  |
| 2.1.4 | Set 'no service dhcp' | ✅ Cumple | ✅ Cumple |  |
| 2.1.6 | Set 'service tcp-keepalives-in' | ✅ Cumple | ✅ Cumple |  |
| 2.1.7 | Set 'service tcp-keepalives-out' | ✅ Cumple | ✅ Cumple |  |
| 2.1.8 | Set 'no service pad' | ✅ Cumple | ✅ Cumple |  |
| 2.2.2 | Set 'buffer size' for 'logging buffered' | ✅ Cumple | ✅ Cumple |  |
| 2.2.3 | Set 'logging console critical' | ✅ Cumple | ✅ Cumple |  |
| 3.1.1 | Set 'no ip source-route' | ✅ Cumple | ✅ Cumple |  |
