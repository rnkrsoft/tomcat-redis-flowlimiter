使用方法
找到tomncat目录/conf/server.xml
```xml
 <Valve className="com.rnkrsoft.tomcat.flowlimit.RedisFlowLimitHandlerValve"
                host="192.168.0.1"
                port="6379"
                password="password"
                database="1"
                timeout="6000"
                maxThresholdPreMin="2"
                ipdbFileName="ip.ipdb"
                strictCheckIp="true"
                showDenyLog="true"
                allowProvinces="四川"
                iptablesFileName="iptables.properties"/>

        <!--这个Valve为Tomcat自带的，在他的前面添加-->
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />

```

| 参数名 | 描述 |      |
| ---- | --------------- | ---- |
| host | 填写redis的地址 |      |
| port | 填写redis的端口号|      |
| password | 填写redis的密码|      |
| database | 填写redis的数据库序号|      |
| timeout |  填写redis连接超时时间|      |
| maxThresholdPreMin |  填写每分钟同一ip的最大访问阈值|      |
| ipdbFileName |  填写ip库文件名|      |
| strictCheckIp |    如果填写为true则开启必须经过IP库检测的IP才能访问，否则都认为是恶意访问|      |
| showDenyLog  |   如果填写为true则访问被黑名单拒绝的显示日志，否则什么也无显示|      |
| allowProvinces |   填写允许访问省的值，多个值使用英文分号分隔|      |
| iptablesFileName | 填写黑名单规则配置文件，用于人工配置允许的IP或者拒绝的IP，同时IP限流达到2倍阈值后自动添加到拒绝IP中|      |