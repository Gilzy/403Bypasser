## 403Bypasser
A Burp Suite extension made to automate the process of bypassing 403 pages. Heavily based on Orange Tsai's talk [Breaking Parser Logic: Take Your Path Normalization off and Pop 0days Out!
](https://www.youtube.com/watch?v=CIhHpkybYsY)

![Sample Issue](https://raw.githubusercontent.com/Gilzy/403Bypasser/c7d53696089ed2e80191c003fd992a21dd9858f4/Sample%20Issue.jpg)

### Features
- Runs with every possible permutation for query-based payloads. 
For instance `https://www.example.com/api/v1/users` with payload `..;` will result in testing the following:
  ```
  https://www.example.com..;/api/v1/users
  https://www.example.com/api..;/v1/users
  https://www.example.com/api/v1..;/users
  https://www.example.com/..;api/v1/users
  https://www.example.com/api/..;v1/users
  https://www.example.com/api/v1/..;users
  https://www.example.com/api/v1/users/..;
  https://www.example.com/api/v1/users/..;/
  ```
- Header payloads are added to the original request. In case the header already exists in the original request its value is replaced.
- For GET requests the extension will try to bypass Forbidden pages by changing the method to POST with an empty body.
- The extension will attempt to downgrade HTTP/1.1 to HTTP/1.0 and remove all headers as shown by [Abbas.heybati](https://infosecwriteups.com/403-bypass-lyncdiscover-microsoft-com-db2778458c33)
- Supports manual activation through context menu.
- Payloads are supplied by the user under dedicated tab, default values are stored in `query payloads.txt` and `header payloads.txt`.
- Issues are added under the Issue Activity tab.
