package com.d208.blockchain;

import com.d208.blockchain.gui.NodeGUI;
import com.d208.blockchain.network.Node;
import com.d208.blockchain.utils.CertificateManager; // 引入 CertificateManager

import java.io.*;
import java.net.SocketException;
import java.security.KeyPair; // 引入 KeyPair
import java.security.PrivateKey; // 引入 PrivateKey
import java.security.cert.Certificate; // 引入 Certificate
import java.security.cert.X509Certificate; // 引入 X509Certificate
import java.util.ArrayList;
import java.util.List;
import java.util.Properties; // 引入 Properties

public class NodeStarter {

    int nodeIdx;
    int port;
    Node node;
    Boolean mine;
    int[] portList;

    // 新增 KeyStore 相关属性
    private String keyStoreFile;
    private char[] keyStorePassword; // 密码建议更安全地处理，例如从环境变量或安全存储读取
    private String keyAlias;
    private String certificateDN;
    private int certificateValidityDays = 365; // 证书有效期（天）

    private PrivateKey privateKey;
    private Certificate certificate;


    //Port, mine or not
    public NodeStarter(String idx, String portNum, String miner) throws Exception {
        this.nodeIdx = Integer.valueOf(idx);
        this.port = Integer.valueOf(portNum);
        if (miner != null && miner.equalsIgnoreCase("yes")) { // 检查 miner 是否为 null
            this.mine = true;
        } else {
            this.mine = false;
        }
        this.portList = getPortList();

        // ---- KeyStore 和证书初始化 ----
        // 定义 KeyStore 文件名、别名和证书主题 DN
        this.keyStoreFile = "keystores/node_" + this.nodeIdx + ".jks"; // 将 KeyStore 存放在 keystores 目录下
        this.keyStorePassword = ("password" + this.nodeIdx).toCharArray(); // **注意：这是不安全的示例密码！**
        this.keyAlias = "node_" + this.nodeIdx + "_key";
        // 构建证书的 Subject Distinguished Name
        this.certificateDN = String.format("CN=Node-%d, OU=BlockchainNetwork, O=MyOrg, L=City, ST=State, C=CN", this.nodeIdx);

        // 确保 keystores 目录存在
        File keyStoreDir = new File("keystores");
        if (!keyStoreDir.exists()) {
            keyStoreDir.mkdirs();
        }

        // 检查 KeyStore 文件是否存在，如果不存在则创建
        File ksFile = new File(this.keyStoreFile);
        if (!ksFile.exists()) {
            System.out.println("KeyStore file not found. Generating new KeyPair and Certificate for Node " + this.nodeIdx + "...");
            // 1. 生成密钥对
            KeyPair keyPair = CertificateManager.generateKeyPair();
            // 2. 生成自签名证书
            X509Certificate cert = CertificateManager.generateSelfSignedCertificate(
                    keyPair,
                    this.certificateDN,
                    this.certificateValidityDays
            );
            // 3. 保存到 KeyStore
            CertificateManager.saveKeyAndCertificate(
                    this.keyStoreFile,
                    this.keyStorePassword,
                    this.keyAlias,
                    keyPair.getPrivate(),
                    cert
            );
            System.out.println("Successfully generated and saved KeyPair and Certificate to " + this.keyStoreFile);
        } else {
            System.out.println("Loading KeyPair and Certificate from " + this.keyStoreFile + " for Node " + this.nodeIdx);
        }

        // 从 KeyStore 加载私钥和证书
        try {
            this.privateKey = CertificateManager.loadPrivateKey(this.keyStoreFile, this.keyStorePassword, this.keyAlias);
            this.certificate = CertificateManager.loadCertificate(this.keyStoreFile, this.keyStorePassword, this.keyAlias);
            System.out.println("Successfully loaded identity for Node " + this.nodeIdx);
            System.out.println("Certificate Subject: " + ((X509Certificate)this.certificate).getSubjectX500Principal());
        } catch (Exception e) {
            System.err.println("Failed to load identity from KeyStore: " + this.keyStoreFile);
            throw new RuntimeException("Failed to load node identity", e);
        }
        // ---- 初始化结束 ----

        // 将加载的私钥和证书传递给 Node 构造函数 (需要修改 Node 构造函数)
        node = new Node(nodeIdx, port, mine, portList, privateKey, certificate);
    }

    //默认不挖
    public NodeStarter(String idx, String portNum) throws Exception {
        this(idx, portNum, "no"); // 明确指定 "no" 或其他非 "yes" 的值
    }


    public static void main(String[] args) throws Exception { // 修改 main 方法签名以抛出 Exception
        // 示例：确保至少提供了索引和端口号
        if (args.length < 2) {
            System.err.println("Usage: NodeStarter <nodeIndex> <portNumber> [miner? yes/no]");
            // 为了测试，可以在没有参数时使用默认值启动一个节点
            System.out.println("No arguments provided, starting Node 0 on port 1111 as miner...");
            new NodeStarter("0", "1111", "yes").startApp();
            return;
        }

        String minerArg = (args.length > 2) ? args[2] : "no";
        new NodeStarter(args[0], args[1], minerArg).startApp();

        // 删除或注释掉旧的硬编码启动方式
//        new NodeStarter("0","8081", "yes").startApp();
//        new NodeStarter("1","8080").startApp();
    }

    public void startApp() throws SocketException, InterruptedException {
        if (this.node == null) {
            System.err.println("Node object is null. Initialization failed.");
            return;
        }
        new NodeGUI(this.node);
        this.node.initNode();
    }

    public int[] getPortList() throws IOException {
        // 尝试从类路径加载配置文件，以便在打包后也能找到
        InputStream inputStream = getClass().getClassLoader().getResourceAsStream("portList.cfg");
        if (inputStream == null) {
            // 如果类路径中找不到，尝试从文件系统加载（保持原有逻辑）
            File cfgFile = new File("etc/portList.cfg");
            if (!cfgFile.exists()) {
                throw new FileNotFoundException("portList.cfg not found in etc/ or classpath");
            }
            inputStream = new FileInputStream(cfgFile);
        }

        List<Integer> list = new ArrayList<>();
        // 使用 try-with-resources 确保流被关闭
        try (BufferedReader in = new BufferedReader(new InputStreamReader(inputStream))) {
            String contentLine;
            while ((contentLine = in.readLine()) != null) {
                try {
                    list.add(Integer.valueOf(contentLine.trim())); // trim() 移除空白字符
                } catch (NumberFormatException e) {
                    System.err.println("Skipping invalid port number: " + contentLine);
                }
            }
        } // inputStream 会在此自动关闭

        // 将 List<Integer> 转换为 int[]
        int[] out = list.stream().mapToInt(i -> i).toArray();
        return out;
    }
}