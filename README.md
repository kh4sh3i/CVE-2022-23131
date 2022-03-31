# CVE-2022-23131
Zabbix - SAML SSO Authentication Bypass

## Description
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified.

 ## Dork:
  ```
  shodan-query: http.favicon.hash:892542951
  ```
  
  ```
  fofa-query: app="ZABBIX-监控系统" && body="saml"
 ```
 
 
 ## usage
 ````
 python3 zabbix_session_exp.py  -t https:target.com -u Admin
 ````
 
 
 ### refrences
 * https://nvd.nist.gov/vuln/detail/CVE-2022-23131
 * https://blog.sonarsource.com/zabbix-case-study-of-unsafe-session-storage
 * https://github.com/Mr-xn/cve-2022-23131
 * https://github.com/projectdiscovery/nuclei-templates
