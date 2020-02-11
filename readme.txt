一年多前写的一个模拟dns多层级域名查询的代码
client和server之间利用tcp和udp连接
每个server需要单独开一个terminal来运行，模拟多主机
细节看detail.pdf 

1). Code(In the "Project" file)

1. "dnsClient.c" is the code of Client.

2. "dnsLocalServer.c" is the code of Local Server.

3. "dnsRootServer.c" is the code of Root Server.

4. "dnsTLDCAServer.c" is the code of TLD of 中国&美国.

5. "dnsBOServer.c" is the code of TLD of 商业&组织.

6. "dns2LDEDUServer" is the code of 2LD of 教育.中国.

7. "dns2LDGOVServer" is the code of 2LD of 政府.美国.



2). Database(In the "Project" file)

1. "localconfig.txt" is the cache of Local Server.

2. "rootconfig.txt" is the database of Root Server.

3. "tldcaconfig.txt" is the database of TLD of 中国&美国.

4. "tldboconfig.txt" is the database of TLD of 商业&组织.

5. "2ldeduconfig.txt" is the database of 2LD of 教育.中国.

6. "2ldgovconfig.txt" is the database of 2LD of 政府.美国.


