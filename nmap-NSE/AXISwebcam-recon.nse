---
-- Nmap NSE AXISwebcam-recon.nse - Version 1.10
-- Copy to: /usr/share/nmap/scripts/AXISwebcam-recon.nse
-- Update NSE database: sudo nmap --script-updatedb
-- execute: nmap --script-help AXISwebcam-recon.nse
---

description = [[

Module Author: r00t-3xp10it & Cleiton Pinheiro
NSE script to detect if target [ip]:[port][/url] its an AXIS Network Camera transmiting (live).
This script also allow is users to send a fake User-Agent in the tcp packet <agent=User-Agent-String>
and also allow is users to input a diferent uri= [/url] link to be scan, IF none uri= value its inputed, then
this script tests a List of AXIS default [/url's] available in our database to brute force the HTML TITLE tag.
'Remark: This nse script will NOT execute againts webcams found that require authentication logins'

Some Syntax examples:
nmap --script-help AXISwebcam-recon.nse
nmap -sS -T4 -p 80-86,92,8080-8082 --open --script AXISwebcam-recon 216.99.115.136
nmap -sS -T4 -p 80-86,92,8080-8082 --script AXISwebcam-recon --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" 50.93.227.204
nmap -sS -T4 -p 80,8080-8082 --open --script AXISwebcam-recon --script-args "agent=Mozilla/5.0 (compatible),uri=/fd" 194.150.15.187
nmap -sS -T4 -p 80-86,8080-8082 --open --script AXISwebcam-recon --script-args "uri=/CgiStart?page=Single&Mode=Motion&Language=1" 217.78.137.43
nmap -sS -vv -T5 -iR 700 -p 8080-8086 --open --script http-headers,AXISwebcam-recon -D 65.49.82.3 -oN webcam_reports.txt

]]

---
-- @usage
-- nmap --script-help AXISwebcam-recon.nse
-- nmap -sS -T4 -p 80-86,92,8080-8082 --open --script AXISwebcam-recon 216.99.115.136
-- nmap -sS -T4 -p 80,8080-8082 --open --script AXISwebcam-recon --script-args "agent=Mozilla/5.0 (compatible),uri=/fd" 194.150.15.187
-- nmap -sS -T4 -p 80-86,92,8080-8082 --script AXISwebcam-recon --script-args "agent=Mozilla/5.0 (compatible; EvilMonkey)" 50.93.227.204
-- nmap -sS -Pn -p 80-86,92,8080-8082 --open --script AXISwebcam-recon.nse --script-args "agent=Mozilla/5.0 (compatible),uri=/" 194.150.15.187
-- nmap -sS -vv -T5 -iR 700 -p 8080-8086 --open --script http-headers,AXISwebcam-recon -D 65.49.82.3 -oN webcam_reports.txt
-- @output
-- PORT     STATE SERVICE VERSION
-- 8080/tcp open  http    Boa httpd
-- | AXISwebcam-recon:
-- |   STATUS: AXIS WEBCAM FOUND
-- |     TITLE: Live view  - AXIS 211 Network Camera version 4.11
-- |       WEBCAM ACCESS: http://216.99.115.136:8080/view/index.shtml
-- |       Module Author: r00t-3xp10it & Cleiton Pinheiro
-- |_
-- @args payload.uri the path name to search. Default: /view/index.shtml
-- @args payload.agent User-agent to send in request - Default: iPhone,safari
---

author = "r00t-3xp10it & Cleiton Pinheiro"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}


local stdnse = require ('stdnse')
local shortport = require "shortport"
local string = require "string"
local http = require "http"

-- define loop limmit(s)
f = 0
limmit = 0

portrule = shortport.port_or_service({80, 81, 82, 83, 84, 85, 86, 92, 8080, 8081, 8082, 8083, 55752, 55754}, "http, http-proxy", "tcp", "open")

action = function(host, port)
print("|AXISwebcam-recon:")
print("|  Brute force AXIS network camera URL:")

uri = stdnse.get_script_args(SCRIPT_NAME..".uri") or "/indexFrame.shtml"

-- Check User Input uri response
local check_uri = http.get(host, port, uri)
if ( check_uri.status == 401 ) then
  print("|    ["..check_uri.status.."] => http://"..host.ip..":"..port.number..uri.." (AUTH LOGIN FOUND)")
  print("|")
  print("|  STATUS: AXIS WEBCAM FOUND")
  print("|    WEBCAM ACCESS: http://"..host.ip..":"..port.number..uri.." [LOGIN]")
  print("|      ABORT SCANS: webcam access require authentication login")
  print("|        Module Author: r00t-3xp10it & Cleiton Pinheiro")
  print("|_\n")
elseif ( check_uri.status == 404 ) then
  print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)

  uril = {"/webcam_code.php", "/view/view.shtml", "/indexFrame.shtml", "/view/index.shtml", "/view/index2.shtml", "/webcam/view.shtml", "/ViewerFrame.shtml", "/RecordFrame?Mode=", "/MultiCameraFrame?Mode=", "/view/viewer_index.shtml", "/visitor_center/i-cam.html", "/index.shtml", "/stadscam/Live95j.asp", "/sub06/cam.php", "/CgiStart"}

  -- loop Through {table} of uri url's
  for i, intable in pairs(uril) do
     local res = http.get(host, port, intable)
     if ( res.status == 200 ) then
        print("|    ["..res.status.."] "..host.ip..":"..port.number.." => "..uri)
        uri = intable
        break
     else
       limmit = limmit+1
       print("|    ["..res.status.."] "..host.ip..":"..port.number.." => "..uri)
        if ( limmit == 15 ) then --> why 15? Because its the number of URI links present in the {table} list.
           print("|")
           print("|  STATUS: NONE AXIS WEBCAM FOUND")
           print("|    REASON: none uri match found in AXISwebcam DB")
           print("|      Module Author: r00t-3xp10it & Cleiton Pinheiro")
           print("|_\n")
           return 
       end
     end
  end

-- Diferent error codes (mosquito needs this seting)
elseif ( check_uri.status == 400 or check_uri.status == 403 or check_uri.status == 405 or check_uri.status == 500 or check_uri.status == 502 or check_uri.status == 503 or check_uri.status == 307 or check_uri.status == 302 or check_uri.status == 301 or check_uri.status == nil ) then
   print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
   do return end
else
   print("|    ["..check_uri.status.."] "..host.ip..":"..port.number.." => "..uri)
end


local options = {header={}}
-- Manipulate TCP packet 'header' with false information about attacker :D
options['header']['User-Agent'] = stdnse.get_script_args(SCRIPT_NAME..".agent") or "Mozilla/5.0 (iPhone; CPU iPhone OS 6_1_4 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10B350 Safari/8536.25"
options['header']['Accept-Language'] = "en-GB,en;q=0.8,sv"
options['header']['Cache-Control'] = "no-store"

-- Read response from target (http.get)
local response = http.get(host, port, uri, options)
  if ( response.status == 200 ) then
     local title = string.match(response.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

     -- List {table} of HTTP TITLE tags
     tbl = {"TL-WR740N", 
     "AXIS Video Server", 
     "Live View / - AXIS", 
     "AXIS 2400 Video Server", 
     "Network Camera TUCCAM1", 
     "AXIS 243Q(2) Blade 4.45", 
     "Network Camera Capitanía", 
     "AXIS P5514 Network Camera", 
     "AXIS Q1615 Network Camera", 
     "AXIS P1357 Network Camera", 
     "AXIS M5013 Network Camera", 
     "AXIS M3026 Network Camera", 
     "AXIS M1124 Network Camera", 
     "Network Camera Hwy285/cr43",
     "Login - Residential Gateway",  
     "Axis 2420 Video Server 2.32", 
     "AXIS Q6045-E Network Camera", 
     "AXIS Q6044-E Network Camera", 
     "Network Camera NetworkCamera", 
     "AXIS P1435-LE Network Camera", 
     "AXIS P1425-LE Network Camera", 
     "Axis 2120 Network Camera 2.34", 
     "Axis 2420 Network Camera 2.30", 
     "Axis 2420 Network Camera 2.31", 
     "Axis 2420 Network Camera 2.32", 
     "AXIS P1365 Mk II Network Camera", 
     "AXIS F34 Network Camera 6.50.2.3", 
     "AXIS 214 PTZ Network Camera 4.49", 
     "Axis 2130 PTZ Network Camera 2.30", 
     "Axis 2130 PTZ Network Camera 2.31", 
     "Axis 2130 PTZ Network Camera 2.32", 
     "AXIS P5635-E Mk II Network Camera", 
     "AXIS Q7401 Video Encoder 5.51.5.1", 
     "AXIS Q6045-E Mk II Network Camera", 
     "AXIS P1353 Network Camera 6.50.2.3", 
     "AXIS M3004 Network Camera 5.51.5.1", 
     "AXIS M1145-L Network Camera 6.50.3", 
     "AXIS M2025-LE Network Camera 8.50.1", 
     "Live view / - AXIS 205 version 4.03", 
     "Live view  - AXIS 240Q Video Server", 
     "Live view  - AXIS 221 Network Camera", 
     "Live view  - AXIS 211 Network Camera", 
     "AXIS Q1765-LE Network Camera 5.55.2.3", 
     "Live view  - AXIS P1354 Network Camera",  
     "Live view  - AXIS P1344 Network Camera", 
     "Live view  - AXIS M1114 Network Camera", 
     "Live view  - AXIS M1103 Network Camera", 
     "Live view  - AXIS M1025 Network Camera", 
     "AXIS P1354 Fixed Network Camera 6.50.3", 
     "AXIS P1354 Fixed Network Camera 5.60.1", 
     "AXIS V5914 PTZ Network Camera 5.75.1.11", 
     "Live view - AXIS P5534-E Network Camera", 
     "Live view  - AXIS 215 PTZ Network Camera", 
     "Live view  - AXIS 214 PTZ Network Camera", 
     "Live view  - AXIS 213 PTZ Network Camera", 
     "AXIS P5534 PTZ Dome Network Camera 5.51.5", 
     "AXIS Q6034-E PTZ Dome Network Camera 5.41.4", 
     "AXIS P3354 Fixed Dome Network Camera 5.40.17", 
     "AXIS Q6042-E PTZ Dome Network Camera 5.70.1.4", 
     "AXIS Q3505 Fixed Dome Network Camera 6.30.1.1", 
     "Live view - AXIS 206M Network Camera version 4.11", 
     "Live view  - AXIS 211 Network Camera version 4.11", 
     "Live view  - AXIS 211 Network Camera version 4.10", 
     "Live view / - AXIS 205 Network Camera version 4.04", 
     "Live view / - AXIS 205 Network Camera version 4.05", 
     "AXIS P5635-E Mk II PTZ Dome Network Camera 8.40.2.2", 
     "Live view / - AXIS 205 Network Camera version 4.05.1", 
     "Live view - AXIS 213 PTZ Network Camera version 4.12"}

     -- Loop Through {table} of HTTP TITLE tags
     for i, intable in pairs(tbl) do
       local validar = string.match(title, intable)
       if ( validar ~= nil or title == intable ) then
           print("|\n|   STATUS: AXIS WEBCAM FOUND\n|     TITLE: "..intable.."\n|       WEBCAM ACCESS: http://"..host.ip..":"..port.number..uri.."\n|      Module Author: r00t-3xp10it & Cleiton Pinheiro\n|_\n")
           break
        else
           print("|  TESTING: "..intable)
           f = f+1
           if (f == 68) then
             return "|\n|   STATUS: NONE AXIS WEBCAM FOUND\n|     Module Author: r00t-3xp10it & Cleiton Pinheiro\n|_\n"
           end
        end
     end
  end
end
