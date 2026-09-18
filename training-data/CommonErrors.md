# Common Suricata Rules Errors from AWS Validation

[All Suricata Errors](suricata_errors.txt) contains all the Suricata Errors extracted from [Suricata Source Code](https://github.com/OISF/suricata/tree/main/src). Below are some of the Suricata Errors.

1) Protocol `http_any` cannot be used in a signature.  Either detection for this protocol is not yet supported OR detection has been disabled for protocol through the yaml option app-layer.

```suricata
alert http_any $EXTERNAL_NET any -> $HOME_NET any (msg:"EmproviseBlockStrictOrder: Possible exploitation of Simply Schedule Appointments vulnerability"; flow:established,to_server; content:"GET"; http_method; content:"/wp-json/ssa/v1/users"; http_uri; reference:cve,CVE-2022-2373; reference:url,https://vedas.arpsyndicate.io/?vuln=CVE-2022-2373; sid:1565531; rev:26; gid:1234567890;)
```

2) Protocol Mismatch: When using the `http1` or `http2` protocol header , but you are using detection keywords like http_uri, http_method, and http_cookie, it causes mismatch. The http_* keywords are specifically tied to the original http (HTTP/1.1) parser. When you specify http2 in the header but use http_uri in the options, the engine sees a conflict between two different Application Layer Protocols (alprotos).

```suricata
alert http2 $EXTERNAL_NET any -> $HOME_NET any (msg:"EmproviseBlockStrictOrder: Temenos T24 XSS Attempt"; flow:established,to_server; content:"routineName|3d|"; http_uri; content:"<script>"; http_uri; reference:url,https://vedas.arpsyndicate.io/?vuln=CVE-2023-24367; reference:cve,CVE-2023-24367; sid:8578252; rev:48; gid:1234567890;)
```

3) The error `stateful rule is invalid, reason: rule contains conflicting alprotos set` is a common validation failure in AWS Network Firewall. It occurs when a Suricata rule contradicts itself by defining one application-layer protocol in the header while using keywords or modifiers that belong to a different application-layer protocol in the body.

Suricata's modern "Sticky Buffer" architecture requires that if you use a protocol-specific buffer (like the HTTP Header), the rule must be structured to explicitly point to that buffer before the match. AWS Network Firewall is stricter than standard Suricata; it sees the /H modifier attempting to set an "ALPROTO" (Application Layer Protocol) context that it feels is already defined or improperly scoped by the combination of the http header and the http_user_agent keyword. Replace http_user_agent with http.user_agent and Removed the /H modifier from PCRE.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any ( msg:"EmproviseBlockStrictOrder: ET INFO SUSPICIOUS Java request to UNI.ME Domain Set 2"; flow:to_server,established; content:"Java/1."; http_user_agent; pcre:"/^Host\:[^\r\n]+?\.(?:f(?:(?:a(?:c(?:ultyexplained|e-bok)|(?:ncy-font|ke-nail)s|ir(?:explained|fuse)|shion-wallpaper|lterguide)|i(?:nanc(?:i(?:al|ng)explained|epets)|rm(?:explained|s24)|lter-coffee)|o(?:r(?:umexplained|ecastbooks|ceestate)|x-drama)|udaninfo)\.com|re(?:e(?:-(?:(?:(?:foodcoupon|angrybird)s|s(?:oundclips|tock)|photoeditor)\.com|music-download\.net)|(?:p(?:owerpointthem|roduct-sampl)es|dom-ofspeech)\.com|fileconverter\.net)|snoever\.com)|l(?:a(?:shplayerdownload\.net|tbelly-diet\.com)|oridaunemploymentclaim\.com|v-downloader\.net)|e(?:rtility-calculator\.net|stivalexplained\.com)|b(?:-smileys\.com|skins\.net))|l(?:(?:i(?:n(?:k(?:explained|master)|colnsbirthdaytea)|(?:ability|ver)explained|(?:berty-saf|ftmov)e|stings(?:biz|red)|teraturemulti)|u(?:ng(?:explained|abscess)|ggageboom)|o(?:cationssecure|ndon-riots|gback))\.com|e(?:(?:a(?:singexplained|ther-trousers)|(?:edsunited-new|d-candle)s|cturer(?:explained|info)|nd(?:ing|er)explained|isure-diving)\.com|u(?:kemiaexplained\.com|e\.biz)|tup\.org)|a(?:guay\.(?:com|es)|-gazzetta\.com)|6\.org)|i(?:n(?:s(?:(?:ur(?:er(?:s(?:explained|24)|explained)|ancesexplained)|ide-film)\.com|(?:pection-camera|taflex)\.net)|d(?:e(?:pendenceday(?:portal|realty)|mnityexplained)\.com|ividual-healthinsurance\.net)|t(?:er(?:estexplained\.com|trigo\.net)|ranet(?:explained|pm)\.com)|(?:(?:vestment|centive)explained|expensivehyper)\.com|f(?:ections?explained\.com|o\.se))|(?:(?:mmersio|sd)nexplained|ronmancom|pone-5)\.com|i(?:nkai|lg)\.biz)|m(?:(?:e(?:tropolis(?:(?:cruis|fac|mov)e|pixel)|(?:lanoma|dical)explained|r(?:idiantotal|cedes-cls)|ntal-healthjobs|morialdaycon|ssenger-mac|ansgift)|i(?:ami(?:-holidays|what)|di-editor)|baexplained)\.com|a(?:r(?:(?:tial-empires|ket-hq)\.com|iogames-online\.net)|n(?:(?:agejoin|ualzap)\.com|ipal-university\.net)|(?:lignanthypertension|gazinedownload)\.net|s(?:on(?:wave|car)|tersexplained)\.com|c2\.org))|e(?:(?:s(?:ta(?:tes(?:mob|fx)|blishstyle)|lexplained)|mploy(?:e(?:eexplained|r24)|mentexplained))\.com|n(?:(?:(?:gagement-photo|able-cookie)s|rollexplained)\.com|trepreneur-ideas\.net)|x(?:(?:(?:hibition|po)explained|ecutive-decision)\.com|tremedeal\.net)|l(?:ect(?:ronicexplained|orate123)\.com|guay\.(?:com|es))|q(?:uityexplained\.com|8\.biz))|g(?:(?:o(?:a(?:d(?:minister|vertize|just)|cademic|llocate)|(?:thic-literatur|handl)e|(?:bailou|conduc)t|govern)|r(?:a(?:duate(?:explained|sinfo)|ndparentsdayplan)|oceryexplained|4)|ym(?:glas|car)s|m[69])\.com|a(?:(?:(?:llaudet|te)explained|mevelocity|rnerguide)\.com|511\.net)|cwsa\.org)|h(?:o(?:(?:me(?:made-biscuits|pageexplained)|(?:nours|tline|using)explained|6)\.com|stel-barcelona\.net)|a(?:r(?:dback(?:city|yoga)|vardexplained)|n(?:dlechange|ukkahbio)|lloweenorange)\.com|y(?:perthyroidsymptoms\.net|d\.me)|ellokittypictures\.net)|j(?:(?:o(?:urnalism(?:explained|info)|hn-grisham|ker-tattoo)|query-examples)\.com|a(?:cksonvillepath\.com|vacollection\.net)|(?:vvg|6)\.org)|k(?:ilometersreach|udosexplained|jyg)\.com)(\x3a\d{1,5})?\r?$/Hmi"; classtype:bad-unknown; sid:2017458; rev:3;)
```

4) Suricata (and AWS Network Firewall) cannot use an HTTP/1 parser keyword inside an HTTP/2 protocol rule. This creates a "conflict" because the engine thinks you are trying to use two different application-layer protocols at once. We get the error `rule contains conflicting alprotos set`. Keywords like http_uri, http_method, http_cookie, etc. belong to the HTTP/1.1 parser. 

- In modern Suricata, http is a dual-stack protocol that handles both versions. It will correctly apply your uricontent or http_uri matches regardless of whether the traffic is version 1.1 or 2.
- If you strictly want to inspect HTTP/2 traffic only, you must use the newer "sticky buffer" syntax designed for HTTP/2. Keywords like http_uri (modifier style) are replaced by http.uri (sticky style).

```suricata
pass http2 $EXTERNAL_NET any -> $HOME_NET any (msg:"EmproviseBlockStrictOrder: pyLoad Vulnerability Exploitation Attempt"; flow:established,to_server; uricontent:"/render/info.html"; nocase; reference:url,https://vedas.arpsyndicate.io/?vuln=CVE-2024-21644; reference:cve,CVE-2024-21644; sid:2557949; rev:20; gid:1234567890;)
```

If the rule uses `http.` sticky buffers, the header should be http (the version-agnostic parser). We get the error `can't set rule app proto to http: already set to http2`.

```suricata
pass http2 $HOME_NET any -> $EXTERNAL_NET any (msg:"EmproviseBlockStrictOrder: ET ADWARE_PUP Win32/Adware.Qjwmonkey.H Variant CnC Activity M2"; flow:established,to_server; http.start; content:"POST /qy/g"; depth:10; http.content_type; content:"application/x-www-form-urlencoded"; http.request_body; content:"js=|7b 22|appid|22 3a|"; startswith; fast_pattern; content:"|2c 22|avs|22 3a|"; distance:0; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2020_06_04, deployment Perimeter, performance_impact Low, signature_severity Minor, updated_at 2020_06_04;
```

```suricata
drop http2 $EXTERNAL_NET any -> $HOME_NET any (msg:"EmproviseBlockStrictOrder: ET WEB_SERVER c99 Shell Backdoor Var Override Cookie"; flow:to_server,established; content:"c99shcook"; nocase; fast_pattern; pcre:"/c99shcook/Ci"; metadata:created_at 2014_06_24, updated_at 2019_10_08; reference:url,thehackerblog.com/every-c99-php-shell-is-backdoored-aka-free-shells/; sid:8555400; rev:39; gid:1234567890;)

alert http2 $HOME_NET any -> $EXTERNAL_NET any (msg:"EmproviseBlockStrictOrder: ET CURRENT_EVENTS Angler EK Landing URI Struct Jun 11 M2"; flow:to_server,established; urilen:>22; content:"/?"; offset:12; depth:86; fast_pattern; pcre:"/^\/[a-z]{3,20}(?P<sep>[_-])[a-z]{3,20}(?P=sep)[a-z]{3,20}(?:(?P=sep)[a-z]{3,20}\/\?[a-z]{6,}=\d{15,20}|(?:(?P=sep)[a-z]{3,20})?\/\?[a-z]{6,}=\d{10,13})$/U"; pcre:"/Host\x3a\x20(?!www\.)(?P<refhost>[^\x3a\r\n]+).*?\r\nReferer\x3a\x20https?\x3a\x2f\x2f(?!(?P=refhost))/Hsi"; flowbits:set,AnglerEK; sid:6890823; rev:1; gid:1234567890;)
```

5) Rule has port as `!any` (meaning not everything which is nothing) or `!!8080` which are both invalid. We get the error `Complete port space is negated`.

```suricata
drop tcp any [21,22,23,25,53,80,443,8080] -> any !any (msg:"EmproviseBlockStrictOrder: [QUADRANT] RDP HANDSHAKE [Tunneled msts] - Possible RDP bypass attempt"; stateful rule is invalid, reason: Complete port space is negated

alert tcp any any -> any !any (msg:"EmproviseBlockStrictOrder: ET CHAT IRC USER Off-port Likely bot with 0 0 colon checkin"; flow:to_server,established; content:"USER|20|"; nocase; content:" 0 0 |3a|"; within:40; content:"|0a|"; within:40; flowbits:set,is_proto_irc; metadata:created_at 2013_07_13, updated_at 2019_07_26; sid:2834923; rev:21; gid:1234567890;)
```

6) Protocol and Options Mismatch: The Suricata rule already is set to a given protocol using protocol option in the rule configuration, but setting the rule to different protocol gives this error. For example, in the below rule TLS protocol is already being used using `tls.sni;` so setting the protocol to dns is invalid giving the error `can't set rule app proto to tls: already set`.

```suricata
alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"EmproviseBlockStrictOrder: ET EXPLOIT_KIT Balada Domain in TLS SNI (rdntocdns .com)"; flow:established,to_server; tls.sni; dotprefix; content:".rdntocdns.com"; endswith; fast_pattern; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, created_at 2024_06_05, deployment Perimeter, malware_family BALADA, performance_impact Low, confidence High, signature_severity Minor, tag Exploit_Kit, updated_at 2024_06_05; reference:url,blog.sucuri.net/2024/01/thousands-of-sites-with-popup-builder-compromised-by-balada-injector.html; sid:1194214; rev:69; gid:1234567890;)
```

Similarly we have below protocol mismatch:

`can't set rule app proto to dns: already set to http_any`: Suricata rule has `dns.query` which set it to use DNS protocol.

```suricata
pass http $HOME_NET any -> any any (msg:"EmproviseBlockStrictOrder: ET MALWARE APT33 CnC Domain in DNS Lookup"; dns.query; content:"srvhost.servehttp.com"; nocase; endswith; metadata:affected_product Web_Browsers, attack_target Client_Endpoint, created_at 2019_06_28, deployment Perimeter, signature_severity Major, updated_at 2020_09_17; reference:url,go.recordedfuture.com/hubfs/reports/cta-2019-0626.pdf; sid:5648428; rev:25; gid:1234567890;)
```

`can't set rule app proto to http: already set to tls`: The rule has `http.start`, `startswith` and `http.host`, hence it is already set to HTTP, hence protocol cannot be set to TLS.

`can't set rule app proto to smtp: already set to tls`: The rule contains config `flowint:smtp.anomaly.count,+,1;` indicating its already been using SMTP, hence cannot be set to TLS.

`The 'file_data' keyword cannot be used with TCP protocol tls`: The file_data keyword cannot be used when the header is set to tls. It is designed for reassembled payloads (HTTP, SMTP, etc.).

`can't set rule app proto to dns: already set to dhcp`: We started the rule with alert dhcp, but used the dns.query keyword. DHCP and DNS are different protocols.

`can't set rule app proto to tls: already set to quic`: We used alert quic, but the rule contains tls.sni. While QUIC uses TLS 1.3 for encryption, Suricata treats them as distinct app-layer protocols.

`can't set rule app proto to dns: already set to ntp`: We used alert ntp, but the rule contains dns.query.

`can't set rule app proto to http: already set to http2`: We used alert http2 (or similar), but used http.request_body or http.user_agent. In some Suricata versions/configurations, standard HTTP keywords are not always cross-compatible with the http2 header.

`can't set rule app proto to ssh: already set to rfb`: The rule header is rfb (VNC), but the content uses ssh_proto. These cannot exist in the same signature.

`can't set rule app proto to smtp: already set to tls`: We are triggering an SMTP event in a TLS rule. Ensure the header protocol matches the event prefix.

```suricata
pass tls any any -> any any (msg:"EmproviseBlockStrictOrder: SURICATA SMTP tls rejected"; flow:established; app-layer-event:smtp.tls_rejected; flowint:smtp.anomaly.count,+,1; sid:5020078; rev:3; gid:1234567890;)
```

`already set to ftp`: We are using http.uri which indicates the rule to be using http, but its protocol is set to ftp.

```suricata
pass ftp any any -> $HOME_NET any (msg:"EmproviseBlockStrictOrder: WIFICAM RCE Exploit Attempt"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/set_ftp.cgi"; nocase; distance:0; reference:url,https://vedas.arpsyndicate.io/?vuln=CVE-2017-8224; reference:cve,CVE-2017-8224; sid:4745216; rev:59; gid:1234567890;)
```

`Signature can use ip_proto keyword only when we use alert ip, in which case the _ANY flag is set on the sig and the if condition should match`: The rule is set to icmp, but then tries to use ip_proto:132 (SCTP). You cannot check for a different IP protocol inside an ICMP header.

```suricata
drop icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"EmproviseBlockStrictOrder: ET MALWARE BPFDoor V2 SCTP Magic Packet Inbound"; ip_proto:132; content:"|44 30 cd 9f 5e 14 27 66|"; target:dest_ip; metadata:attack_target Client_Endpoint, created_at 2023_05_11, deployment Perimeter, performance_impact Low, confidence High, signature_severity Major, updated_at 2023_05_11; reference:url,www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game; sid:4052774; rev:54; gid:1234567890;)
```

7) In Suricata, tcp-stream tells the engine to inspect the reassembled stream (as if the data were one continuous file). However, dsize (payload size) is a packet-level keyword. Hence we get the error `can't mix packet keywords with tcp-stream or flow:only_stream`. We cannot ask the engine to measure the size of a single packet while simultaneously telling it to ignore packet boundaries via the tcp-stream protocol.

```suricata
alert tcp-stream $HOME_NET any -> $EXTERNAL_NET 33343 (msg:"EmproviseBlockStrictOrder: ET COINMINER Win32/Repl_it Coin Miner CnC Checkin"; flow:established,to_server; dsize:<45; content:"Repl|2e|it|20|Miner|20|v1|2e|2"; endswith; threshold:type limit,track by_src,count 1,seconds 3600; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2023_06_30, deployment Perimeter, confidence High, signature_severity Critical, updated_at 2023_06_30; reference:url,twitter.com/Jane_0sint/status/1674824454185312257; reference:md5,46c84a61af20b2d225810487ba14be4d; sid:6416410; rev:95; gid:1234567890;)
```

8) get the error `protocol "ssl" cannot be used in a signature`. Either detection for this protocol is not yet supported OR detection has been disabled for protocol through the yaml option app-layer.protocols.ssl.detection-enabled. 

```suricata
any any (msg:"EmproviseBlockStrictOrder: SURICATA TRAFFIC-ID: bing"; tls_sni; content:"bing.com"; isdataat:!1,relative; flow:to_server,established; flowbits: set,traffic/id/bing; flowbits:set,traffic/label/search; noalert; sid:4835339; rev:27; gid:1234567890;)
```

9) If the Suricata rule does not have terminating semicolon `;` at its end then it is invalid as we get the error `detect-parse: no terminating ";" found` from Suricata 8.0.3 CLI. Ideally Suricata rule's options should have a terminating semi-colon before the ending brackets `;)` without any space.

```suricata
alert http any any -> any any (msg:"检测到敏感后缀.inc文件访问";flow:to_server,established; content:".inc";http_uri;nocase;priority:3; sid:1000131;rev:1)
```

The terminating semicolon can also be present just after the ending brackets e.g. `);` but then it causes AWS rule group validation failure `invalid character as arg to rev keyword`. Recommended to have semilcolon after every option field before ending bracket. Below is the failing AWS modified rule for validation (AWS adds `gid` for every suricata rule ).

```suricata
alert http any any -> any any (msg:"检测到XSS攻击特征--命中规则104"; flow:to_server,established; content:"onmouseup"; content:"POST"; nocase; priority:2; sid:1967448; rev:1); gid:1234567890;)
```

10) When the uses http.uri; (dot notation) but the rest of the rule uses http_uri; (underscore) then it causes issues. While modern Suricata supports both, mixing them can be problematic depending on the version.

11) The `flowbits:set,name;` is invalid. You must provide a specific name for the bit (e.g., `flowbits:set,sliver.session;`).

12) These use content:"POST"; without the http_method modifier. This means Suricata will look for the string "POST" anywhere in the payload, which is much slower than checking just the method buffer.

13) The `threshold` is deprecated in favor of the `detection_filter` or `event_filter` keywords in modern versions, though `threshold` is often kept for backward compatibility.

14) In Suricata, sticky buffers (like http_client_body or http_uri) change the context for everything that follows. If we call a buffer, then a `content` match, then a `pcre` match with the /R flag, they must all be explicitly tied to the same buffer. The /R flag tells the PCRE engine: "Start looking for this regex relative to the end of the last successful content match."

By grouping the buffer keyword directly with the content match and immediately following it with the PCRE match, we maintain the "pointer" context.

Always place the buffer keyword (e.g., http_client_body;) immediately before the content and pcre matches that belong to it.
The /R Rule: If using /R in a PCRE, the match immediately preceding it must be a content match in the exact same buffer.
If rule has `fast_pattern` then move it to ensure the sequence of buffer -> content -> pcre is uninterrupted.

`pcre with /R (relative) needs preceding match in the same buffer`

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Quanta LTE Router RDE Exploit Attempt 1 (ping)"; flow:to_server,established; content:"POST"; http_method; content:"/webpost.cgi"; http_uri; content:"|7b 22 43 66 67 54 79 70 65 22 3a 22 70 69 6e 67 22 2c 22 63 6d 64 22 3a 22 70 69 6e 67 22 2c 22 75 72 6c 22 3a 22|"; http_client_body; fast_pattern; pcre:"/^[^\x22]*[\x24\x60]+/Ri"; reference:url,pierrekim.github.io/blog/2016-04-04-quanta-lte-routers-vulnerabilities.html; sid:2022700; rev:2;)
```

15) Ambiguous Method Matching: You are using `content:"GET";` and `content:"POST";` without specifying where to look for them. Add the `http_method` sticky buffer modifier immediately after the method string to avoid Suricata from finding the word "GET" inside the middle of a file download or a URI.

16) In Suricata rules, the semicolon is a reserved character used to separate different rule options (like msg, content, sid, etc.). The error `bad option value formatting (possible missing semicolon) for keyword content: '"database('`. To include a literal semicolon inside a content match, you must escape it using its hex code. The hex value for a semicolon (;) is 3b

```suricata
alert http any any -> any any (msg:"检测到SQL注入攻击特征8"; flow:to_server,established; content:"database(; )"; content:"GET"; nocase; priority:1; sid:1000321; rev:1;)
```

17) Suricata attaches modifiers such as "distance" and "within" to the "content" on their left.Listing them twice is like giving someone two different sets of coordinates for the same destination—the engine gets confused and stops. We see the error `can't use multiple distances or withins for the same content.`
For every content match, you can parse the subsequent modifiers into a set. If you see a duplicate, discard it before rebuilding the rule string.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Linux/LuaBot CnC Beacon Response"; flow:established,from_server; file_data; content:"script|7c|"; within:7; content:"|7c|endscript"; distance:0; fast_pattern; distance:0; reference:url,blog.malwaremustdie.org/2016/09/mmd-0057-2016-new-elf-botnet-linuxluabot.html; sid:2023156; rev:2;)

alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Backdoor.Win32.PcClient.bal CnC (OUTBOUND) 2"; flow:to_server,established; content:"|12 12|"; offset:2; depth:2; content:!"|12 12|"; within:2; distance:2; within:2; within:2; content:"|12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12 12|"; pcre:"/[^\x12][^\x4e\x38\x39\x2f\x6e\x28\x29\x30\x2d\x2e\x2c\x3e\x31\x18][\x40-\x48\x4a-\x4d\x31-\x34\x3a-\x3c\x3f\x50-\x5f\x60-\x6c\x6f\x73-\x7f\x70\x71\x20-\x27\x2a\x2b]{1,14}\x12/R"; reference:md5,00ccc1f7741bb31b6022c6f319c921ee; sid:2019202; rev:3;)
```

18) The pcre field should not contain semicolon. Convert the semicolon to hex to fix the error `bad option value formatting (possible missing semicolon) for keyword pcre: '"/href\s*=\s*[\"']?\s*(j\s*a\s*v\s*a\s*&#(?:0*115|0*73`.

```suricata
alert http any any -> any any (msg:"检测到XSS攻击特征--命中规则154"; flow:to_server,established; pcre:"/href\s*=\s*[\"']?\s*(j\s*a\s*v\s*a\s*&#(?:0*115|0*73;)\;?\s*c\s*r\s*i\s*p\s*t\s*;):/i"; content:"GET"; priority:2; sid:8769508; rev:1;)
```

19) In Suricata, the /R (Relative) modifier in a pcre tells the engine to start matching from the end of the previous content match. However, for this to work, both the pcre and the preceding content must be in the same data buffer. When you use a sticky buffer (like http_uri, http_header, or http_client_body), it sets the "context" for everything before it. If a pcre has /R but follows a sticky buffer that doesn't match the buffer of the preceding content, or if the preceding content was "consumed" by a sticky buffer keyword, the relative link breaks. We get the error `detect-pcre: pcre with /R (relative) needs preceding match in the same buffer`.

The sticky buffer keyword (e.g., http_client_body;) is placed after the content but before the PCRE. This "clears" the relative pointer. Place the sticky buffer before the content that the PCRE needs to be relative to.

20) The `ja3.hash` only exists in traffic coming from the client and `ja3s.hash` only exists in traffic coming from the server. 
When the suricata rule contains `ja3.hash;` and flow keyword value is `flow:to_client` or when the suricata rule contains `ja3s.hash;` and flow keyword value is `flow:to_server` then we get the error `rule xxx mixes keywords with conflicting directions`. To fix this issue replace `to_client` with `to_server` in the flow keyword value when rule has `ja3.hash;` and replace `to_server` with `to_client` in the flow keyword value when rule has `ja3s.hash;`.

```suricata
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"Sliver JA3 特征"; flow:to_client,established; ja3.hash; content:"19e29534fd49dd27d09234e639c4057e"; nocase; priority:1; sid:1000840; rev:1;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Sliver JA3s 特征"; flow:to_server,established; ja3s.hash; content:"f4febc55ea12b31ae17cfb7e614afda8"; nocase; priority:1; sid:1000843; rev:1;)
```

21) Suricata has strict requirement for pipe handling were the `\|` is not a valid escape sequence within a content string. Suricata treats the pipe | as a toggle switch between Plain Text Mode and Hexadecimal Mode.When the parser encounters \|3b|, it treats the backslash as literal text and then interprets the pipe as the start of a hex block. However, if that hex block is not closed correctly or if the backslash is positioned in a way that breaks the toggle logic, the parser throws the "has to be escaped" error—which is a slightly confusing way of saying "the pipe is being used as a literal character when it should be denoting hex.".
By removeing the escape before the pipe in content value makes it from `content:"_\|3b| domain=";` to `content:"_|3b| domain=";`. 

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS TDS Sutra - redirect received"; flow:established,to_client; content:"302"; http_stat_code; content:"=_"; content:"_\|3b| domain="; distance:1; within:10; pcre:"/^[a-z]{5}[0-9]{1,2}=_[0-9]{1,2}_/"; sid:2014547; rev:5;)

alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"ET TROJAN Conficker.b Shellcode"; flow:established,to_server; content:"|e8 ff ff ff ff c2|_|8d|O|10 80|1|c4|Af|81|9MSu|f5|8|ae c6 9d a0|O|85 ea|O|84 c8|O|84 d8|O|c4|O|9c cc|Ise|c4 c4 c4|,|ed c4 c4 c4 94|&<O8|92|\|3b||d3|WG|02 c3|,|dc c4 c4 c4 f7 16 96 96|O|08 a2 03 c5 bc ea 95|\|3b||b3 c0 96 96 95 92 96|\|3b||f3|\|3b||24 |i|95 92|QO|8f f8|O|88 cf bc c7 0f f7|2I|d0|w|c7 95 e4|O|d6 c7 17 cb c4 04 cb|{|04 05 04 c3 f6 c6 86|D|fe c4 b1|1|ff 01 b0 c2 82 ff b5 dc b6 1f|O|95 e0 c7 17 cb|s|d0 b6|O|85 d8 c7 07|O|c0|T|c7 07 9a 9d 07 a4|fN|b2 e2|Dh|0c b1 b6 a8 a9 ab aa c4|]|e7 99 1d ac b0 b0 b4 fe eb eb|"; reference:url,www.honeynet.org/node/388; sid:2009201; rev:6;)
```

22) When you use the within keyword, you are telling Suricata that the entirety of the current content match must be found within X bytes after the previous match. If your content string is longer than the within value, it is physically impossible to match, so Suricata invalidates the rule. The reason for this issue is we wrongfully converted `\|3b|` to `|7c 3b|` increasing the content length.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET CURRENT_EVENTS TDS Sutra - redirect received"; flow:established,to_client; content:"302"; http_stat_code; content:"=_"; content:"_|7c 3b| domain="; distance:1; within:10; pcre:"/^[a-z]{5}[0-9]{1,2}=_[0-9]{1,2}_/"; sid:2014547; rev:5;)
```

23) In Suricata rules, the semicolon is a reserved character used to separate different rule options (like msg, flow, content, etc.). Even if it is inside double quotes, Suricata's parser often interprets a semicolon as the end of the msg field. Because you have a closing parenthesis ) after the semicolon but before the actual closing quote of the option, the parser gets confused and thinks the formatting is broken. To include a literal semicolon inside a text field like msg, you must escape it with a backslash (\;).Without escaping the semicolon we get the error `bad option value formatting (possible missing semicolon) for keyword msg: '"检测到 Cobalt Strike Client JA3 特征`.

```suricata
alert tls any any -> any any (msg:"检测到 Cobalt Strike Client JA3 特征 (4d5efa96609dc906f796e63cff009c2a; )"; flow:established,to_server; ja3.hash; content:"4d5efa96609dc906f796e63cff009c2a"; reference:url,github.com/salesforce/ja3; priority:1; sid:2950641; rev:1; metadata:created_at 2025_08_04, threat_type C2;)
```

24) If the Suricata rule contains any legacy HTTP modifier (http_client_body, http_header, http_uri, http_cookie) between the content: and pcre:/R: (i.e. the pcre with value containing `/R`) then converting the legacy HTTP modifiers to sticky buffer syntax (http.header) for entire Suricata rule, and ensuring the Sticky Buffer keyword (e.g., http.uri;) is placed before the content match that the PCRE is supposed to be relative to, solves the Suricata error `detect-pcre: pcre with /R (relative) needs preceding match in the same buffer`.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Oracle Event Processing FileUploadServlet Arbitrary File Upload"; flow:established,to_server; content:"POST"; http_method; content:"/wlevs/visualizer/upload"; http_uri; content:"filename"; http_client_body; pcre:"/^\s*?=\s*?[\x22\x27]?[^&]*?(?:%(?:25)?2e(?:%(?:(?:25)?2e(?:%(?:25)?5c|\/|\\)|2e(?:25)?%(?:25)?2f)|\.(?:%(?:25)?(?:2f|5c)|\/|\\))|\.(?:%(?:25)?2e(?:%(?:25)?(?:2f|5c)|\/|\\)|\.(?:%(?:25)?(?:2f|5c)|\/|\\)))/Ri"; reference:url,www.exploit-db.com/exploits/33989/; sid:2018652; rev:3;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS Invalid/Suspicious User-Agent (PHP)"; flow:to_server,established; content:"User-Agent|3a 20|PHP/5."; http_header; pcre:"/^\{\d(\|\d){1,}\}\.\{\d(\|\d){1,}\}\{\d(\|\d){1,}\}/R"; sid:2022350; rev:3;)

alert http $EXTERNAL_NET 27017 -> $HOME_NET any (msg:"ET TROJAN Possible Compromised Host Sinkhole Cookie Value Snkz"; flow:established,to_client; content:"snkz="; http_cookie; pcre:"/^\d{1,3}\x2E\d{1,3}\x2E\d{1,3}\x2E\d{1,3}/R"; sid:2018141; rev:2;)
```

25) If the Suricata rule contains below values in PCRE keyword value and the below value is outside square brackets [], then

 `\|3b|)` is replaced with `\)`
 `\|3b|` is replaced with `\;`
`|3b|` is replaced with `\;`.

```suricata
alert http any any -> any any (msg:"检测到SQL注入攻击特征29"; flow:to_server,established; pcre:"/sleep\s*\(\s*[\d.]+\s*\|3b|)/i"; content:"POST"; priority:1; sid:1000605; rev:1;)

alert http any any -> any any (msg:"检测到XSS攻击特征--命中规则154"; flow:to_server,established; pcre:"/href\s*=\s*[\"']?\s*(j\s*a\s*v\s*a\s*&#(?:0*115|0*73|3b|)\|3b|?\s*c\s*r\s*i\s*p\s*t\s*|3b|):/i"; content:"GET"; priority:2; sid:4404089; rev:1;)
```

26) When we use the `fast_pattern:only;` modifier, you are telling Suricata: "Use this specific string for the initial hardware/software pre-filtering, but do not actually look for it during the inspection phase.". Hence the engine "discards" the fast_pattern:only content during full inspection, any subsequent content that uses relative keywords (like `distance` or `within`) has no "anchor" to measure from. Suricata cannot calculate a distance of 0 bytes from a match it didn't officially record. We get the error `previous keyword has a fast_pattern:only; set. Can't have relative keywords around a fast_pattern only content`. To fix this remove the `:only` portion of the `fast_pattern` modifier. By changing it to just `fast_pattern;`, we allow Suricata to use the string for pre-filtering and keep it as a reference point for the relative distance and within calculations.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Moose CnC Response"; flow:from_server,established; content:"200"; http_stat_code; content:"PP|3b 20|expires="; fast_pattern:only; content:"PHPSESSID="; http_cookie; content:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; distance:0; content:"WL="; distance:0; content:"Content-Type|3a 20|text/html"; http_header; file_data; content:"<html><body><h1>It works!</h1>"; nocase; depth:30; reference:url,gosecure.net/2016/11/02/exposing-the-ego-market-the-cybercrime-performed-by-the-linux-moose-botnet/; sid:2023478; rev:2;)
```

27) Suricata logic forbids mixing Absolute modifiers and Relative modifiers on the exact same `content` keyword.

 - **Absolute Modifiers** (`offset`, `depth`): Engine looks at a fixed position from the start of the buffer.
 - **Relative Modifiers** (`distance`, `within`): Engine looks at a position relative to the end of the previous match.

 When we provide both modifiers for same content then Suricata doesn't know whether to start counting from the beginning of the file or from the last match. Hence we get the error `detect-within: can't use a relative keyword like within/distance with a absolute relative keyword like depth/offset for the same content`.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN FrameworkPOS CnC Server Reporting IP Address To Agent"; flow:established,to_client; file_data; content:"=="; depth:2; within:17; fast_pattern; pcre:"/^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:={2})/R"; reference:url,threatstream.com/blog/three-month-frameworkpos-malware-campaign-nabs-43000-credits-cards-from-point-of-sale-systems; sid:2022552; rev:2;)

alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"ET POLICY Outgoing Chromoting Session Response"; content:"|63 68 72 6F 6D 6F 74 69 6E 67|"; depth:170; distance:39; reference:url,xinn.org/Chromoting.html; sid:2013800; rev:3;)
```
The Relative Keyword Conflict: In below suricata rule we have `offset:1; distance:0;`. `offset` is an absolute position, while `distance` is relative to a previous match. Using both on the same `content` keyword is logically impossible for the engine. Hence we get the error `detect-distance: can't use a relative keyword like within/distance with a absolute relative keyword like depth/offset for the same content`. Remove relative keywords when absolute keyword exits for same content.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Emotet Checkin"; flow:established,to_server; http.method; content:"POST"; http.header; content:!"Accept-"; content:!"Referer|3a|"; http.uri; content:"/"; offset:1; distance:0; http.user_agent; content:"MSIE 7.0|3b|"; fast_pattern; content:"Windows NT 6.0"; within:15; pcre:"/^\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/$/"; pcre:"/^[\x20-\x7e\r\n]{0,20}[^\x20-\x7e\r\n]/"; reference:md5,3083b68cb5c2a345972a5f79e735c7b9; sid:2019693; rev:5;)
```

28) In Suricata, a sticky buffer like `http.uri;` stays active for every subsequent content or pcre modifier until a new sticky buffer (like http.header;) is declared. If `http.uri;` was the last declared buffer, then Suricata assumes next `content` which is even not related to URI is also part of the URI. Ideally we must declare sticky buffer to  attach to each content.

The `urilen` applies to entire URI buffer as a whole of that HTTP transaction. Suricata rule can have `urilen` without any content. When the HTTP parser extracts the URI, Suricata checks its length. If the length satisfies the urilen condition, the rule continues to evaluate other options. Any and all content matches that you target at that URI (using http.uri; or uricontent:) must fit inside the URI length. We get below error `detect-urilen: depth or urilen 4 smaller than content len 11`. Increase urilen to a range or remove the upper limit. Since the PCRE length can vary, `urilen:>4` is safer.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Win32/Agent.WVW CnC Beacon 3"; flow:to_server,established; urilen:4; http.method; content:"GET"; http.uri; content:"/cl1"; fast_pattern:only; content:"Referer|3a 20|1|3a|"; pcre:"/^\d\.\d_(?:64|32)_\d\x3a/R"; http.header; content:"Empty|0d 0a|"; reference:md5,1de834aca8905124e1abcd4f71dea062; sid:2021259; rev:3;)
```

29) PCRE2 Compile issue: Suricata uses the [PCRE2 library](https://github.com/PCRE2Project/pcre2), which is strict about how character classes and parentheses are handled. For example placing the hyphen (`-`) which indicates range between `w` and `_` or un-escapted parenthesis.

We get errors such as `detect-pcre: pcre2 compile of "/sleep\s*\(\s*[\d.]+\s*\;)/i" failed at offset 25: unmatched closing parenthesis`.

E: detect: error parsing signature "alert http any any -> any any (msg:"检测到SQL注入攻击特征29"; flow:to_server,established; pcre:"/sleep\s*\(\s*[\d.]+\s*\;)/i"; content:"POST"; priority:1; sid:7431933; rev:1;)" from file bad.rules at line 36

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"TThreatHunter Rule - "CobaltStrike download.windowsupdate.com C2 Profile"; flow: established; http.uri; content:"msdownload"; pcre:"/\/c\/msdownload\/update\/others\/[\d]{4}/\d{2}/\d{7,8}_[\d\w-_]{50,}\.cab/R"; reference:url,github.com/bluscreenofjeff/MalleableC2Profiles/blob/master/microsoftupdate_getonly.profile; sid: 3016002; rev: 1; metadata:created_at 2018_09_25,by al0ne;)

alert http any any -> any any (msg:"检测到SQL注入攻击特征29"; flow:to_server,established; pcre:"/sleep\s*\(\s*[\d.]+\s*\;)/i"; content:"GET"; priority:1; sid:5372914; rev:1;)
```

30) In PCRE, `|` is a logic "OR". The regex engine sees `|?`, which means "OR followed by a question mark." Since there's nothing before the `?` to make optional, it crashes.

The error `detect-pcre: pcre2 compile of "/href\s*=\s*[\"']?\s*(j\s*a\s*v\s*a\s*&#(?:0*115|0*73\;)\|3b|?\s*c\s*r\s*i\s*p\s*t\s*\;):/i" failed at offset 61: quantifier does not follow a repeatable item`.

If the `|3b|` does not contain inside square brackets [] which is Character Class in the PCRE value string, then replace it with `\;` which is semicolon with an escape since it's inside the pcre string.

```suricata
alert http any any -> any any (msg:"检测到XSS攻击特征--命中规则154"; flow:to_server,established; pcre:"/href\s*=\s*[\"']?\s*(j\s*a\s*v\s*a\s*&#(?:0*115|0*73\;)\|3b|?\s*c\s*r\s*i\s*p\s*t\s*\;):/i"; content:"GET"; priority:2; sid:1000285; rev:1;)
```

31) The error `Invalid unescaped double quote within content section` indicates missing quotes for the content option field.

```suricata
alert http any any -> any any (msg:"检测到XSS攻击特征--命中规则65"; flow:to_server,established; content:"onloadeddat|3b|content:"GET"; nocase; priority:2; sid:2271575; rev:1;)
```

32) The error `"http_uri" keyword seen with a sticky buffer still set.  Reset sticky buffer with pkt_data before using the modifier.`

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible Cisco Subscriber Edge Services Manager Cross Site Scripting/HTML Injection Attempt"; flow:to_server,established; http.uri; content:"/servlet/JavascriptProbe"; nocase; content:"documentElement=true"; http_uri; content:"regexp=true"; nocase; content:"frames=true"; reference:url,www.securityfocus.com/bid/34454/info; sid:2010622; rev:4;)
```

33) When using a sticky buffer (like `http.uri`), the engine expects all subsequent pcre or content matches to belong to that buffer unless we explicitly switch to a new one or use the correct PCRE flag. 

If we activate `http.uri` and then run a `pcre` without a modifier (like `/U`), Suricata gets confused because it doesn't know if the regex should apply to the URI or the whole packet data. Hence we get the error `Expression seen with a sticky buffer still set; either (1) reset sticky buffer with pkt_data or (2) use a sticky buffer providing "raw http uri"`.

Ensure the legacy rule's pcre modifiers (like /U for URI or /H for Header) are updated with corresponding pcre values for sticky buffer and the pcre flag matches the current sticky buffer (e.g., U for URI, H for Header, P for Request Body).
In legacy rules, if a pcre had no buffer flag (like /U), it defaulted to the packet payload. In modern Suricata, if a sticky buffer is active, we need to explicitly reset to pkt_data; or switch to the correct buffer before that match.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any ( msg:"ET TROJAN Medfos Connectivity Check"; flow:established,to_server; content:"/uploading/id="; http_uri; fast_pattern:only; content:!"Referer|3a 20|"; http_header; pcre:"/^\/uploading\/id=\d{2,20}&u=(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/I"; classtype:misc-activity; sid:2016800; rev:6;)
```

Similarly need to switch `http.user_agent` explicitly for `/V` Modifier for the error `Expression seen with a sticky buffer still set... use a sticky buffer providing http user agent`.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN LoadMoney Checkin 3"; flow:established,to_server; http.method; content:"POST"; http.header; content:"User-Agent|3a 20|Downloader|20|"; http.request_body; content:"|0a|Content-Disposition|3a 20|form-data|3b 20|name=|22|data|22 0d 0a|"; http.user_agent; pcre:"/^Downloader\s\d+\.\d+$/V"; reference:md5,a8c63492e36bac23a9afa512e08f3fa6; sid:2022987; rev:2;)
```

34) The error `detect-parse: "http_uri" keyword seen with a sticky buffer still set.  Reset sticky buffer with pkt_data before using the modifier.`.

```suricata
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SERVER Possible Cisco Subscriber Edge Services Manager Cross Site Scripting/HTML Injection Attempt"; flow:to_server,established; http.uri; content:"/servlet/JavascriptProbe"; nocase; content:"documentElement=true"; http_uri; content:"regexp=true"; nocase; content:"frames=true"; reference:url,www.securityfocus.com/bid/34454/info; sid:2010622; rev:4;)

alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET WEB_SPECIFIC_APPS PhotoSmash action Parameter Cross Site Scripting Attempt"; flow:established,to_server; http.uri; content:"/plugins/photosmash-galleries/index.php?"; nocase; content:"action="; nocase; http_uri; pcre:"/action\x3d.+(script|onmouse[a-z]+|onkey[a-z]+|onload|onunload|ondragdrop|onblur|onfocus|onclick|ondblclick|onsubmit|onreset|onselect|onchange|style\x3D)/i"; reference:url,packetstormsecurity.org/files/view/99089/photosmash-xss.txt; sid:2012670; rev:3;)
```

35) The `/R` flag in PCRE tells Suricata to perform a relative match. For a relative match to work, the PCRE must look in the exact same data buffer where the previous content match occurred. If the `pcre` is trying to be relative to a `content` match in a different buffer (e.g., `content` is in `http_uri`, but `pcre` is looking in the general payload or a different sticky buffer) or trying to be relative when the buffer has been "reset" or shifted by a new buffer keyword without a fresh content anchor. The error `detect-pcre: pcre with /R (relative) needs preceding match in the same buffer`.

If using `/R` in `pcre`, the keyword immediately preceding the pcre (excluding modifiers like nocase) should be the content it is relative to, and they must be in the same buffer. If you change buffers (e.g., calling http_client_body;), you must match a content string in that new buffer before you can use /R.
Better to convert legacy http modifiers into modern sticky buffers.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Neutrino Checkin 2"; flow:to_server,established; content:"POST"; http_method; content:!"Referer|3a|"; http_header; content:"auth=1"; http_client_body; pcre:"/^$/R"; reference:md5,25bd222c947fcbb7e1fb9f6e176ea53f; sid:2022462; rev:2;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET CURRENT_EVENTS Upatre redirector GET Sept 29 2014"; flow:established,to_server; content:".php?h="; http_uri; pcre:"/^\d+&w=\d+&ua=.+&e=1$/R"; flowbits:set,et.exploitkitlanding; sid:2019311; rev:3;)
```

36) In a Suricata rule, the semicolon (;) is a reserved character used as a keyword terminator. When the Suricata parser reads the pcre string and hits a semicolon, it assumes the pcre option has ended. If the regex inside `pcre` contains literal semicolons (like in vbscript; or &#73;) that cannot be escaped then the parser cuts the pcre value short. Hence we get the error `bad option value formatting (possible missing semicolon) for keyword pcre: '"/(href|src|on\w+'`. To fix these, you must escape every semicolon inside the pcre string with a backslash (\;).

```suricata
alert http any any -> any any (msg:"检测到XSS攻击特征--命中规则1"; flow:to_server,established; pcre:"/(href|src|on\w+;)\s*=\s*[\"']?\s*(javascript|data|vbscript;):/i"; content:"GET"; priority:2; sid:2435476; rev:1;)
```

37) When using `fast_pattern:only;` modifier, we are telling Suricata engine to use this specific string for the initial hardware/software pre-filtering, but do not actually look for it during the inspection phase. Because the engine "discards" the `fast_pattern:only` content during full inspection, any subsequent content that uses relative keywords (like `distance` or `within`) has no "anchor" to measure from. Suricata cannot calculate a distance of 0 bytes from a match it didn't officially record. The error `detect-distance: previous keyword has a fast_pattern:only; set. Can't have relative keywords around a fast_pattern only content`.

Fic this by replacing `fast_pattern:only` with `fast_pattern` option, thus allowing Suricata to use the string for pre-filtering and keep it as a reference point for the relative distance and within calculations.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Executable Download from dotted-quad Host"; flow:established,to_server; content:".exe"; http_uri; content:".exe HTTP/1."; fast_pattern:only; content:"Host|3A 20|"; http_header; content:"|2E|"; distance:1; within:3; pcre:"/^Host\x3A\x20[0-9]{1,3}\x2E[0-9]{1,3}\x2E[0-9]{1,3}\x2E[0-9]{1,3}(\x3A|\x0D\x0A)/i"; sid:2016141; rev:4;)

alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Moose CnC Request M1"; flow:to_server,established; urilen:1; content:"GET"; http_method; content:!"Referer|3a 20|"; http_header; content:"PP|3b 20|nhash="; fast_pattern:only; content:"PHPSESSID="; http_cookie; content:"AAAAAAAAAAAAAAA"; distance:0; content:"|3b 20|chash="; distance:0; reference:url,gosecure.net/2016/11/02/exposing-the-ego-market-the-cybercrime-performed-by-the-linux-moose-botnet/; sid:2023477; rev:2;)
```

38) Move the sticky buffers (like `http.header` or `http.cookie`) **before** the content they are supposed to match.

The error `detect-parse: rule 2018119 setup buffer http_cookie but didn't add matches to it`.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Banking Trojan HTTP Cookie"; flow:established,to_server; content:"tcpopunder"; fast_pattern:only; http.cookie; reference:url,www.secureworks.com/cyber-threat-intelligence/threats/updates-to-the-citadel-trojan/; sid:2018119; rev:2;)
```

39) HTTP Method Traps (Leading/Trailing Space): Insert `pkt_data;` immediately after the Method match to break out of the method buffer so Suricata can see the "HTTP/1.1" or spaces. The error `detect-http-method: http_method pattern with leading space`.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Zeus Bot GET to Google checking Internet connectivity"; flow:established,to_server; http.method; content:"GET"; nocase; pkt_data; content:" HTTP/1."; content:"|0d 0a|Accept|3a| */*|0d 0a|Connection|3a| Close|0d 0a|User-Agent|3a| "; distance:1; within:46; content:"|0d 0a|Host|3a| "; distance:0; http.header; content:!"|0d 0a|Referer|3a| "; nocase; http.uri; content:"/webhp"; reference:url,www.secureworks.com/research/threats/zeus/?threat=zeus; sid:2013076; rev:7;)
```

Similarly the error `detect-http-method: http_method pattern with trailing space` for the below Suricata rule.

```suricata
alert tcp $HOME_NET any -> $EXTERNAL_NET 5432 (msg:"ET TROJAN TROJAN Drop.Agent.bfsv HTTP Activity (UsER-AgENt)"; flow:established,to_server; http.method; content:"GeT"; content:"HttP"; depth:200; content:"|0d 0a|HoST|3a| "; http.header; content:"UsER-AgENt|3a| |0d 0a|"; reference:url,doc.emergingthreats.net/2010129; sid:2010129; rev:6;)
```

40) PCRE / RAW Encoding: In Suricata sticky buffers (like http.uri, http.header, and http.uri.raw) tell the detection engine exactly which part of the traffic to inspect. When we use a PCRE (Perl Compatible Regular Expression) after a content match, the PCRE inherits the buffer context of whatever keyword immediately preceded it.

The solution is to insert `http.uri.raw;` immediately before PCREs that look for encoded characters (like `%25` or `%2e`), or where the buffer context was lost.

***Whenever you see a rule that jumps between different parts of a packet (Method $\rightarrow$ URI $\rightarrow$ Header $\rightarrow$ Body), always ensure that your PCRE is preceded by the specific buffer keyword it is intended to inspect.***

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Tendrit CnC Beacon 2"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/favicon?"; depth:9; http.header; content:!"Referer|3a|"; http.uri.raw; pcre:"/^\/favicon\?[a-z]{2,}=(?:%[A-F0-9]{2})+&/I"; reference:md5,755dad1f37a9d3fae1352dbbc409102c; sid:2019986; rev:2;)
```

41) Legacy Content Modifiers: In older Suricata syntax, you write `content:"abc"; http_uri;`. The keyword modifies the preceding content. In modern Suricata (and AWS Network Firewall), we write `http_uri; content:"abc";`. The keyword sets the buffer for everything following it. Hence we get the error `detect-parse: "http_client_body" keyword found inside the rule without a content context.  Please use a "content" keyword before using the "http_client_body" keyword`.

To satisfy both the "Relative PCRE" requirement and the "Content Context" requirement, you must use the modern dot-notation sticky buffers (e.g., http.cookie) instead of the underscore legacy versions.

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Win32.Fareit.A/Pony Downloader Checkin (2)"; flow:to_server,established; content:"ch=1"; http_uri; http_client_body; pcre:"/ch=1$/"; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=PWS%3aWin32%2fFareit.A; sid:2015799; rev:6;)
```

---

## AWS Rule Group Errors

1) "Orphaned" Flowbit Problem: When the Suricata rule contains `flowbits:isset,snake-a8` or `flowbits:unset,snake-a8` but there is no other rule which contains `flowbits:set,snake-a8`. If we don't include the specific rule containing `flowbits:set,snake-a8` in the same rule group, AWS service throws a validation error. Even if it passes validation, the rules will never fire because the initial trigger condition is never met.

```suricata
alert tcp-pkt $EXTERNAL_NET any -> $HOME_NET any ( msg:"EmproviseBlockStrictOrder: ET MALWARE FSB Snake CnC Activity Inbound via TCP (AA23-129A) M3"; flow:established,to_client; content:"|00 00 00 04|"; startswith; dsize:4; flowbits:isset,snake-b8; flowbits:unset,snake-b8; flowbits:set,snake-b41; flowbits:noalert; reference:url,cisa.gov/news-events/cybersecurity-advisories/aa23-129a; sid:2045642; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2023_05_11, deployment Perimeter, malware_family Snake, performance_impact Moderate, confidence Medium, signature_severity Major, tag AA23_129A, updated_at 2023_05_11;)

alert http $HOME_NET any -> $EXTERNAL_NET any ( msg:"EmproviseBlockStrictOrder: ET MALWARE Conficker/MS08-067 Worm Traffic Outbound"; flowbits:isset,ET.ms08067_header; flow:established,to_server; content:"If-None-Match|3A| |22|60794|2D|12b3|2D|e4169440|22|"; nocase; sid:2008739; rev:8; metadata:created_at 2010_07_30, updated_at 2019_07_26;)
```

2) Rules with ClassType: When Suricata rule contains `classtype` field with any value e.g. `classtype:protocol-command-decode;`, `classtype:trojan-activity;`, the PMR code validation service throws error.

```
ClientError: An error occurred (InvalidRequestException) when calling the StartRuleAnalysis operation: null null
```

Below are the sample rules with classtype which gives the above error.

```suricata
alert http any any -> any any ( msg:"EmproviseBlockStrictOrder: ET INFO WinHttp AutoProxy Request wpad.dat Possible BadTunnel"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/wpad.dat"; fast_pattern; endswith; reference:url,tools.ietf.org/html/draft-ietf-wrec-wpad-01; reference:url,ietf.org/rfc/rfc1002.txt; classtype:protocol-command-decode; sid:2022913; rev:5; metadata:created_at 2016_06_23, updated_at 2020_09_14;)
```

3) AWS currently does not officially supports `reject` action, and will fail when using UDP and reject action.

```suricata
reject udp any any -> any 15763 (msg:"MalwareBlockStrictOrder: Achat Buffer Overflow Exploit Attempt"; flow:to_server,established; content:"|3b|55|2a|55|6e|58|6e|05|14|11|6e|2d|13|11|6e|50|6e|58|43|59|39|"; nocase; distance:0; sid:9068619; rev:78; reference:cve,CVE-2025-34127; reference:url,https://vedas.arpsyndicate.io/?vuln=CVE-2025-34127;)
```

4) AWS does not allow list of IP addresses to have spaces between the comma.

```suricata
drop http $EXTERNAL_NET any -> [84.248.217.130, 90.215.180.63] any ( msg:"EmproviseBlockStrictOrder: MOVEit Transfer Session Cookie Set"; flow:established,to_server; content:"machine.aspx"; http_uri; content:"siLockLongTermInstID=0"; http_cookie; content:"ASP.NET_SessionId="; http_cookie; reference:cve,CVE-2023-36934; reference:url,https://vedas.arpsyndicate.io/?vuln=CVE-2023-36934; sid:8244936; rev:59;)
```

5) AWS Rules which have variables other than `$HOME_NET` and `$EXTERNAL_NET` are not allowed e.g. $HTTP_SERVERS, $HTTP_PORTS, $FTP_PORTS etc.

```suricata
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS ( msg:"EmproviseBlockStrictOrder: FILE-IDENTIFY OLE Document upload detected"; flow:to_server,established; file_data; content:"Content-Disposition|3A|"; nocase; content:"Form-data|3B|"; within:20; nocase; content:"|D0 CF 11 E0 A1 B1 1A E1|"; within:200; fast_pattern; flowbits:set,file.ole; flowbits:noalert; metadata:policy balanced-ips alert, policy connectivity-ips alert, policy max-detect-ips alert, policy security-ips alert, ruleset community, service http; classtype:misc-activity; sid:36058; rev:10;)
```

6) POP3 Unsupported: AWS Network Firewall has the pop3 parser disabled or unsupported. Rules targeting mail traffic must use tcp as a fallback. We get the error `protocol 'pop3' cannot be used`, either detection for this protocol is not yet supported OR detection has been disabled for protocol through the yaml option app-layer.protocols.pop3.detection-enabled.

```suricata
pass pop3 $EXTERNAL_NET any -> $HOME_NET any (msg:"EmproviseBlockStrictOrder: ET SMTP Abuseat.org Block Message"; flow:established,from_server; content:"abuseat.org"; metadata:created_at 2011_06_10, updated_at 2019_07_26; sid:3416942; rev:24; gid:1234567890;)
```

7) Heavy Rule: Rule lacks a flow direction and uses any any -> any any. It will inspect every single packet on the network (even non-DNS traffic) for that string. If the rule is very heavy `any any -> any any`, then change it `dns $HOME_NET any -> any 53` were add random port number i.e. port number 53.

8) JA3 hashes are MD5 digests. By convention and implementation in Suricata, these are handled as lowercase hexadecimal strings. The nocase modifier tells the inspection engine to treat "A" and "a" as the same. Since the JA3 buffer is already normalized to lowercase, adding nocase forces the engine to perform extra, unnecessary CPU cycles to verify a case-insensitivity that isn't needed. AWS rule group error `ja3.hash should not be used together with nocase, since the rule is automatically lowercased anyway which makes nocase redundant`.

```suricata
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"Sliver JA3 特征"; flow:to_server,established; ja3.hash; content:"19e29534fd49dd27d09234e639c4057e"; nocase; priority:1; sid:1000841; rev:1;)
```

9) In Suricata, pcre (Perl Compatible Regular Expressions) is "expensive" in terms of CPU usage. To prevent the engine from trying to run a complex regex against every single byte of every packet, AWS requires you to "anchor" the PCRE to a specific sticky buffer or a content match. When you provide a content match or a protocol-specific buffer alongside pcre, Suricata uses the fast "pattern matcher" first. If the content isn't found, it skips the pcre entirely, saving massive amounts of processing power. AWS rule group service gives an error `Using "pcre" without one of the following options is not allowed: [tls.sni, http.host, dns.query, http.uri, content]` if pcre does not have any content or protocol-specific buffer.

```suricata
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"检测到 Cobalt Strike Client JA3 特征"; ja3s.hash; pcre:"/b742b407517bac9536a77a7b0fee28e9|fd4bc6cea4877646ccd62f0792ec0b62/"; priority:1; sid:9253064; rev:1;)
```

10) [Datasets](https://docs.suricata.io/en/latest/rules/datasets.html) (which allow you to match traffic against large external lists of IPs, strings, or md5s stored in a separate file) is not supported by AWS. Hence we get the error `RuleOptions dataset is not supported...`. The dataset keyword tells Suricata to look up the destination IP (ip.dst) in a memory-efficient list called ipv6-list. Since AWS Network Firewall manages the rule evaluation environment, it does not have a mechanism for you to "upload" or "reference" these separate dataset files within a standard Suricata Rule Group.

[IP Reputation](https://docs.suricata.io/en/latest/rules/ip-reputation-rules.html) feature is a system that assigns a "score" or "category" to an IP address based on external intelligence (e.g., whether it's a known botnet, a spam relay, or a Tor exit node). We define a reputation file (CSV) that maps IPs to categories and threat scores in self-hosted Suricata setup. You then use the iprep keyword in your rules to match traffic based on those scores:

```suricata
alert icmp any any -> any any (itype:8; ip.dst; dataset:set,ipv6-list,type ipv6; sid:226;)
alert ip any any -> any any (msg:"Match Botnet IP"; iprep:src,Botnet,>,50; sid:1;)
```

11) Content Duplication: Duplicate content values in a single rule is syntactically legal, but it can lead to two major issues: performance degradation and logic errors (specifically regarding relative matching). If you have two identical content strings, the engine may perform the same search twice on the same packet buffer.

Suricata uses a "last match" pointer to track where a content match ended. If you have duplicate content, subsequent relative modifiers (like distance, within, or pcre /R) will anchor themselves to the most recent match.

```suricata
alert tcp any 1024:65535 -> any any ( msg:"36243: HTTP: Trojan.Win32.Dtrack.A Runtime Detection"; content:"name=\"upf"; nocase; offset:0; fast_pattern; content:"name=\"upf"; nocase; offset:0; content:"name=\"upfile\"\; filename=\"template.bmp\"|0d 0a|Content-Type: application/octet-stream"; nocase; offset:0; depth:768; sid:10036243; rev:1;)
```

---
## Unresolved Suricata Errors from Rule Fixer

ERROR: `detect-tcp-flags: pcre match failed`

```suricata
alert tcp any any -> $HOME_NET any (msg:"Possible DDoS attack"; sid:1000111; flags:PA);" from file bad.rules at line 1
```

ERROR: `detect-parse: invalid formatting or malformed option to content keyword: 'content'`

```suricata
alert tcp any any -> any any (msg:"contains RAT communication init "; content; to_lowercase; pcre: "/asyncratserver.*asyncratserver/" content:; sid:3179711;)
```

ERROR: `detect: unknown decode event "decoder.etag.header_too_small"`

```suricata
alert pkthdr any any -> any any (msg:"SURICATA ETAG header too small"; decode-event:etag.header_too_small; sid:2200123; rev:1);" from file bad.rules at line 5
```

ERROR: `detect: unknown decode event "decoder.etag.unknown_type"`

```suricata
alert pkthdr any any -> any any (msg:"SURICATA ETAG unknown type"; decode-event:etag.unknown_type; sid:2200124; rev:1);" from file bad.rules at line 6
```

ERROR: `detect-pcre: pcre2 compile of "/\/c\/msdownload\/update\/others\/[\d]{4}/\d{2}/\d{7,8}_[\d\w-_]{50,}\.cab/R" failed at offset 61: invalid range in character class`

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"TThreatHunter Rule - "CobaltStrike download.windowsupdate.com C2 Profile"; flow: established; http.uri; content:"msdownload"; pcre:"/\/c\/msdownload\/update\/others\/[\d]{4}/\d{2}/\d{7,8}_[\d\w-_]{50,}\.cab/R"; reference:url,github.com/bluscreenofjeff/MalleableC2Profiles/blob/master/microsoftupdate_getonly.profile; sid: 3016002; rev: 1; metadata:created_at 2018_09_25,by al0ne);" from file bad.rules at line 8
```

ERROR: `detect-parse: quotes on ssh.softwareversion keyword that doesn't support them: 'ssh.softwareversion'`

```suricata
alert ssh $EXTERNAL_NET any -> $HOME_NET any (msg:"ET SCAN SSH BruteForce Tool with fake PUTTY version"; flow:established,to_server; ssh.softwareversion:"PUTTY"; threshold: type limit, track by_src, count 1, seconds 30; sid:2019876; rev:4);" from file bad.rules at line 9
```

ERROR: `detect-parse: "http_client_body" keyword found inside the rule without a content context. Please use a "content" keyword before using the "http_client_body" keyword`

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Win32.Fareit.A/Pony Downloader Checkin (2)"; flow:to_server,established; content:"ch=1"; http_uri; http_client_body; pcre:"/ch=1$/"; reference:url,www.microsoft.com/security/portal/Threat/Encyclopedia/Entry.aspx?Name=PWS%3aWin32%2fFareit.A; sid:2015799; rev:6);" from file bad.rules at line 12
```

ERROR: `detect-parse: unknown rule keyword 'contnet'`

```suricata
alert http any any -> any any (msg:"检测到Fastjson反序列化流量特征"; flow:to_server,established; content:"Lcom.sun.rowset.JdbcRowSetImpl"; contnet:"dataSourceName"; content:"ldap"; content:"@type"; nocase; priority:1; sid:1000750; rev:1);" from file bad.rules at line 23
```

ERROR: `detect-parse: unknown rule keyword '"test"'`

```suricata
alert dns any any -> any any ("test"; sid:9973571; content:"detectme.foobar");" from file bad.rules at line 27
```
ERROR: `detect-content: '\' has to be escaped`

```suricata
alert http any any -> any any (msg:"检测到Fastjson反序列化流量特征"; flow:to_server,established; content:"\u0040\u0074\u0079\u0070\u0065":"\u0063\u006f\u006d\u002e\u0073\u0075\u006e\u002e\u0072\u006f\u0077\u0073\u0074\u002e\u004a\u0064\u0062\u0063\u0052\u006f\u0077\u0053\u0065\u0049\u006d\u0070\u006c","\u0064\u0061\u0074\u0061\u0053\u006f\u0075\u0072\u0063\u0065\u004e\u0061\u006d\u0065"; priority:1; sid:1000749; rev:1);" from file bad.rules at line 22
```

ERROR: `detect-content: Invalid unescaped double quote within content section`

```suricata
alert http any any -> any any (msg:"检测到XSS攻击特征--命中规则65"; flow:to_server,established; content:"onloadeddat|3b|content:"GET"; nocase; priority:2; sid:2271575; rev:1);" from file bad.rules at line 26
```
