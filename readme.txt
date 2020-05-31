一年多前写的一个模拟dns多层级域名查询的代码
client和server之间利用tcp和udp连接
每个server需要单独开一个terminal来运行，模拟多主机
细节看detail.pdf（For more details, please see "Detail.pdf"）

- Code(In the "Project" file)
  - "dnsClient.c" is the code of Client.
  - "dnsLocalServer.c" is the code of Local Server.
  - "dnsRootServer.c" is the code of Root Server.
  - "dnsTLDCAServer.c" is the code of TLD of 中国&美国.
  - "dnsBOServer.c" is the code of TLD of 商业&组织.
  - "dns2LDEDUServer" is the code of 2LD of 教育.中国.
  - "dns2LDGOVServer" is the code of 2LD of 政府.美国.

- Database(In the "Project" file)
  - "localconfig.txt" is the cache of Local Server.
  - "rootconfig.txt" is the database of Root Server.
  - "tldcaconfig.txt" is the database of TLD of 中国&美国.
  - "tldboconfig.txt" is the database of TLD of 商业&组织.
  - "2ldeduconfig.txt" is the database of 2LD of 教育.中国.
  - "2ldgovconfig.txt" is the database of 2LD of 政府.美国.
