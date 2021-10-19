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
- ~~Automatically detects and tries to bypass requests with 403 responses.~~ If you want auto detection use [this version](https://github.com/Gilzy/403Bypasser/tree/8a821dcf11c7f2fb9974361cbb16072b51b7cf15).
- Supports manual activation through context menu.
- Payloads are supplied by the user under dedicated tab, default values are stored under `query payloads.txt` and `header payloads.txt`.
- Issues are added under the Issue Activity tab.

### TODO
- [x] Add support for header-based payloads.
- [x] Add support for manual activation via context menu.
- [ ] Add support for replacing GET requests with POST and empty content-length.
- [x] Show relevant requests/responses when adding a new issue.
- [ ] Automate detection for special cases shown in Orange Tsai's talk.
- [ ] Improve detection algorithm to reduce false-positives.
