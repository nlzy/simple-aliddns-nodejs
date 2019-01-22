# Simple Aliyun DDNS Client

一个简单的阿里云解析 DDNS 脚本，可以新建、修改 A 记录为本机 IP。脚本仅有一个 .js 文件，不需要安装其他依赖。

## 系统需求
node >= 8.0

## 设置选项
直接修改脚本中的 config

- `rr & domain`
例如你有一个 example.com 域名，你想修改 ddns.example.com，那么 rr 就是 `ddns`，domain 就是 `example.com`

- `accessKeyId & accessKeySecret`
没什么好说的，在阿里云控制台里找。

- `interval`
自动更新 DNS 记录的时间间隔。0 表示不自动更新，运行一次后立即退出。单位：秒，默认：0

- `alidnsAPI & ipAPI`
脚本用到的两个 API，不用改。

## 授权协议
MIT
