# 区块链网络安全
## 运行指令
mvn clean javafx:run
## 证书管理
证书生成指令：
> 在resources/ssl文件夹下用cmd执行以下指令

A端：

`keytool -genkeypair -alias nodeA -keyalg RSA -keysize 2048 -dname "CN=NodeA, OU=Sim, O=Example, L=City, ST=State, C=US" -keystore keystoreA.jks -storepass passwordA -validity 365`

`keytool -export -alias nodeA -file nodeA.crt -keystore keystoreA.jks -storepass passwordA`

`keytool -import -alias nodeA -file nodeA.crt -keystore truststoreB.jks -storepass passwordB -noprompt`

B端：

`keytool -genkeypair -alias nodeB -keyalg RSA -keysize 2048 -dname "CN=NodeB, OU=Sim, O=Example, L=City, ST=State, C=US" -keystore keystoreB.jks -storepass passwordB -validity 365`

`keytool -export -alias nodeB -file nodeB.crt -keystore keystoreB.jks -storepass password`

`keytool -import -alias nodeB -file nodeB.crt -keystore truststoreA.jks -storepass passwordA -noprompt`

测试：

`keytool -list -keystore keystoreA.jks -storepass passwordA`

`keytool -list -keystore truststoreA.jks -storepass passwordA`
