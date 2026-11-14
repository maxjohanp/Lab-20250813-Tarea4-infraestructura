# Informe póstumo de hardening CIS

- **Estudiante:** Maxyohan Montas Peña · matrícula 2025-0813 · Seguridad de Redes
- **Fecha y hora:** 13/11/2026 19:58:31 · PC: Iso
- **Modo:** APLICAR

## Resumen

| Equipo | Benchmark | Antes | Después |
|---|---|---|---|
| R-0813 | CIS Cisco IOS 15 Benchmark v4.1.1 | 100 % | 100 % |
| SW-0813 | CIS Cisco IOS 15 Benchmark v4.1.1 | 21 % | 100 % |
| FW-0813 | CIS Fortigate 7.0.x Benchmark v1.3.0 | 100 % | 100 % |

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

## SW-0813 · Switch Cisco IOSvL2 (IOS 15.2) (10.20.25.2)

| ID | Recomendación CIS | Antes | Después | Comandos aplicados |
|---|---|---|---|---|
| 1.1.1 | Enable 'aaa new-model' | ❌ No cumple | ✅ Cumple | `aaa new-model` |
| 1.1.2 | Enable 'aaa authentication login' | ❌ No cumple | ✅ Cumple | `aaa authentication login default local` |
| 1.2.2 | Set 'transport input ssh' for 'line vty' connections | ❌ No cumple | ✅ Cumple | `line vty 0 4`<br>`transport input ssh`<br>`line vty 5 15`<br>`transport input ssh` |
| 1.2.3 | Set 'no exec' for 'line aux 0' | ❌ No cumple | ✅ Cumple | `line aux 0`<br>`no exec` |
| 1.2.4 | Create 'access-list' for use with 'line vty' | ❌ No cumple | ✅ Cumple | `no access-list 113`<br>`access-list 113 remark CIS 1.2.4 - SSH solo desde la PC de administracion`<br>`access-list 113 permit tcp host 10.20.25.100 any`<br>`access-list 113 deny ip any any log` |
| 1.2.5 | Set 'access-class' for 'line vty' | ❌ No cumple | ✅ Cumple | `line vty 0 4`<br>`access-class 113 in`<br>`line vty 5 15`<br>`access-class 113 in` |
| 1.2.7 | Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0' | ✅ Cumple | ✅ Cumple |  |
| 1.2.9 | Set 'exec-timeout' to less than or equal to 10 minutes 'line vty' | ✅ Cumple | ✅ Cumple |  |
| 1.3.2 | Set the 'banner-text' for 'banner login' | ✅ Cumple | ✅ Cumple |  |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | ❌ No cumple | ✅ Cumple | `banner motd ^ACCESO RESTRINGIDO: solo personal autorizado. Toda la actividad queda registrada.^` |
| 1.4.1 | Set 'password' for 'enable secret' | ✅ Cumple | ✅ Cumple |  |
| 1.4.2 | Enable 'service password-encryption' | ❌ No cumple | ✅ Cumple | `service password-encryption` |
| 1.4.3 | Set 'username secret' for all local users | ✅ Cumple | ✅ Cumple |  |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | ❌ No cumple | ✅ Cumple | `ip ssh time-out 60` |
| 2.1.1.2 | Set version 2 for 'ip ssh version' | ❌ No cumple | ✅ Cumple | `ip ssh version 2` |
| 2.1.2 | Set 'no cdp run' | ❌ No cumple | ✅ Cumple | `no cdp run` |
| 2.1.3 | Set 'no ip bootp server' | ❌ No cumple | ✅ Cumple | `no ip bootp server` |
| 2.1.4 | Set 'no service dhcp' | ❌ No cumple | ✅ Cumple | `no service dhcp` |
| 2.1.6 | Set 'service tcp-keepalives-in' | ❌ No cumple | ✅ Cumple | `service tcp-keepalives-in` |
| 2.1.7 | Set 'service tcp-keepalives-out' | ❌ No cumple | ✅ Cumple | `service tcp-keepalives-out` |
| 2.1.8 | Set 'no service pad' | ❌ No cumple | ✅ Cumple | `no service pad` |
| 2.2.2 | Set 'buffer size' for 'logging buffered' | ❌ No cumple | ✅ Cumple | `logging buffered 64000` |
| 2.2.3 | Set 'logging console critical' | ❌ No cumple | ✅ Cumple | `logging console critical` |
| 3.1.1 | Set 'no ip source-route' | ❌ No cumple | ✅ Cumple | `no ip source-route` |

## FW-0813 · Firewall FortiGate-VM 7.0.9 (10.8.13.1)

| ID | Recomendación CIS | Antes | Después | Comandos aplicados |
|---|---|---|---|---|
| 1.3 | Disable all management related services on WAN port | ✅ Cumple | ✅ Cumple |  |
| 2.1.1 | Ensure 'Pre-Login Banner' is set | ✅ Cumple | ✅ Cumple |  |
| 2.1.2 | Ensure 'Post-Login-Banner' is set | ✅ Cumple | ✅ Cumple |  |
| 2.1.3 | Ensure timezone is properly configured | ✅ Cumple | ✅ Cumple |  |
| 2.1.5 | Ensure hostname is set | ✅ Cumple | ✅ Cumple |  |
| 2.2.1 | Ensure 'Password Policy' is enabled | ✅ Cumple | ✅ Cumple |  |
| 2.2.2 | Ensure administrator password retries and lockout time are configured | ✅ Cumple | ✅ Cumple |  |
| 2.4.2 | Ensure all the login accounts having specific trusted hosts enabled | ✅ Cumple | ✅ Cumple |  |
| 2.4.4 | Ensure idle timeout time is configured | ✅ Cumple | ✅ Cumple |  |
| 2.4.5 | Ensure only encrypted access channels are enabled | ✅ Cumple | ✅ Cumple |  |
| 3.2 | Ensure that policies do not use "ALL" as Service | ✅ Cumple | ✅ Cumple |  |
| 3.4 | Ensure logging is enabled on all firewall policies | ✅ Cumple | ✅ Cumple |  |
