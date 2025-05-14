# 构建
首先，配置好maven包管理，我用的是jdk1.8来执行的。
修改\src\main\resources目录下的配置文件application.yml，修改其中的server port，p2pport,address.
在程序根目录，即与.xml平级的目录，执行`mvn package`
然后修改\src\main\resources目录下的配置文件application.yml和根目录下的pom.xml build标签下的名字
执行`mvn package`

# 运行
在.\target目录下，打开两个cmd窗口，分别输入java -jar 文件名_1.jar 和 java -jar 文件名_2.jar
