
This is a simple single-file python program that can find basic XSS (cross-site scripting) vulnerabilities in a target url. Most XSS discovery tools use a payload refelection strategy in which payloads are injected in url parameters and the GET response is inspected for places where the payload content is reflected. This is a very low precision XSS detection strategy because most reflection does not support execution.

This program uses a different approach, and instead opens the target url in a browser, tests `alert(...)` payloads directly in the browser context, and listens for an alert being triggered. This means that any XSS spotted by this program is extremely unlikely to be a false positive. 

This program can be used with the command
```
  python main.py \
    --target_url "https://xss-game.appspot.com/level1/frame?query=test" \
    --payload_list_file_path lists/xss_payloads_with_alert_message_signal.txt
```
