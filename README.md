# ys-dcur
该工具用于获取 query_cur_region HTTP 响应的内容。

该工具将会使用 Keys 文件夹的 RSA 密钥进行解密 query_cur_region ，并反序列化 QueryCurrRegionHttpRsp 的数据。

如果您使用时遇到解密失败，则 Keys 文件夹的 RSA 密钥与生成 query_cur_region 内容的 Dispatch 服务器使用的密钥并不匹配

使用方法：
1. 保存 query_cur_region 到 data.txt中
2. 运行 ys-dcur.exe
