# Informe póstumo de hardening CIS

- **Estudiante:** Maxyohan Montas Peña · matrícula 2025-0813 · Seguridad de Redes
- **Fecha y hora:** 13/11/2026 19:10:47 · PC: Iso
- **Modo:** APLICAR

## Resumen

| Equipo | Benchmark | Antes | Después |
|---|---|---|---|
| R-0813 | CIS Cisco IOS 15 Benchmark v4.1.1 | 12 % | 0 % |
| SW-0813 | CIS Cisco IOS 15 Benchmark v4.1.1 | 21 % | 100 % |
| FW-0813 | CIS Fortigate 7.0.x Benchmark v1.3.0 | 17 % | 100 % |

## R-0813 · Router Cisco 7200 (IOS 15.2) (10.20.25.1)

> **Problema:** ReadTimeout: Pattern not detected: 'R\\-0813\\#' in output. Things you might try to fix this: 1. Explicitly set your pattern using the expect_string argument. 2. Increase the read_timeout to a larger value. You can also look at the Netmiko session_log or debug log for more information.

| ID | Recomendación CIS | Antes | Después | Comandos aplicados |
|---|---|---|---|---|
| 1.1.1 | Enable 'aaa new-model' | ❌ No cumple | ❌ No cumple |  |
| 1.1.2 | Enable 'aaa authentication login' | ❌ No cumple | ❌ No cumple |  |
| 1.2.2 | Set 'transport input ssh' for 'line vty' connections | ❌ No cumple | ❌ No cumple |  |
| 1.2.3 | Set 'no exec' for 'line aux 0' | ❌ No cumple | ❌ No cumple |  |
| 1.2.4 | Create 'access-list' for use with 'line vty' | ❌ No cumple | ❌ No cumple |  |
| 1.2.5 | Set 'access-class' for 'line vty' | ❌ No cumple | ❌ No cumple |  |
| 1.2.7 | Set 'exec-timeout' to less than or equal to 10 minutes 'line console 0' | ❌ No cumple | ❌ No cumple |  |
| 1.2.9 | Set 'exec-timeout' to less than or equal to 10 minutes 'line vty' | ✅ Cumple | ✅ Cumple |  |
| 1.3.2 | Set the 'banner-text' for 'banner login' | ❌ No cumple | ❌ No cumple |  |
| 1.3.3 | Set the 'banner-text' for 'banner motd' | ❌ No cumple | ❌ No cumple |  |
| 1.4.1 | Set 'password' for 'enable secret' | ✅ Cumple | ✅ Cumple |  |
| 1.4.2 | Enable 'service password-encryption' | ❌ No cumple | ❌ No cumple |  |
| 1.4.3 | Set 'username secret' for all local users | ✅ Cumple | ✅ Cumple |  |
| 2.1.1.1.4 | Set 'seconds' for 'ip ssh timeout' | ❌ No cumple | ❌ No cumple |  |
| 2.1.1.2 | Set version 2 for 'ip ssh version' | ❌ No cumple | ❌ No cumple |  |
| 2.1.2 | Set 'no cdp run' | ❌ No cumple | ❌ No cumple |  |
| 2.1.3 | Set 'no ip bootp server' | ❌ No cumple | ❌ No cumple |  |
| 2.1.4 | Set 'no service dhcp' | ❌ No cumple | ❌ No cumple |  |
| 2.1.6 | Set 'service tcp-keepalives-in' | ❌ No cumple | ❌ No cumple |  |
| 2.1.7 | Set 'service tcp-keepalives-out' | ❌ No cumple | ❌ No cumple |  |
| 2.1.8 | Set 'no service pad' | ❌ No cumple | ❌ No cumple |  |
| 2.2.2 | Set 'buffer size' for 'logging buffered' | ❌ No cumple | ❌ No cumple |  |
| 2.2.3 | Set 'logging console critical' | ❌ No cumple | ❌ No cumple |  |
| 3.1.1 | Set 'no ip source-route' | ❌ No cumple | ❌ No cumple |  |

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
| 1.3 | Disable all management related services on WAN port | ❌ No cumple | ✅ Cumple | `config system interface`<br>`edit port1`<br>`unset allowaccess`<br>`next`<br>`end` |
| 2.1.1 | Ensure 'Pre-Login Banner' is set | ❌ No cumple | ✅ Cumple | `config system global`<br>`set pre-login-banner enable`<br>`end` |
| 2.1.2 | Ensure 'Post-Login-Banner' is set | ❌ No cumple | ✅ Cumple | `config system global`<br>`set post-login-banner enable`<br>`end` |
| 2.1.3 | Ensure timezone is properly configured | ❌ No cumple | ✅ Cumple | `config system global`<br>`set timezone 15`<br>`end` |
| 2.1.5 | Ensure hostname is set | ✅ Cumple | ✅ Cumple |  |
| 2.2.1 | Ensure 'Password Policy' is enabled | ❌ No cumple | ✅ Cumple | `config system password-policy`<br>`set status enable`<br>`set apply-to admin-password ipsec-preshared-key`<br>`set minimum-length 8`<br>`set min-lower-case-letter 1`<br>`set min-upper-case-letter 1`<br>`set min-non-alphanumeric 1`<br>`set min-number 1`<br>`set expire-status enable`<br>`set expire-day 90`<br>`set reuse-password disable`<br>`end` |
| 2.2.2 | Ensure administrator password retries and lockout time are configured | ❌ No cumple | ✅ Cumple | `config system global`<br>`set admin-lockout-threshold 3`<br>`set admin-lockout-duration 900`<br>`end` |
| 2.4.2 | Ensure all the login accounts having specific trusted hosts enabled | ❌ No cumple | ✅ Cumple | `config system admin`<br>`edit "admin"`<br>`set trusthost1 10.20.25.100 255.255.255.255`<br>`next`<br>`end` |
| 2.4.4 | Ensure idle timeout time is configured | ✅ Cumple | ✅ Cumple |  |
| 2.4.5 | Ensure only encrypted access channels are enabled | ❌ No cumple | ✅ Cumple | `config system interface`<br>`edit port1`<br>`unset allowaccess`<br>`next`<br>`edit port2`<br>`set allowaccess ping https ssh`<br>`next`<br>`end` |
| 3.2 | Ensure that policies do not use "ALL" as Service | ❌ No cumple | ✅ Cumple | `config firewall policy`<br>`edit 1`<br>`set service "DNS" "HTTP" "HTTPS" "PING" "NTP"`<br>`next`<br>`end` |
| 3.4 | Ensure logging is enabled on all firewall policies | ❌ No cumple | ✅ Cumple | `config firewall policy`<br>`edit 1`<br>`set logtraffic all`<br>`next`<br>`end` |
