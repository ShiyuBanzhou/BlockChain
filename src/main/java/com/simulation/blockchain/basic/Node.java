package com.simulation.blockchain.basic;

import com.simulation.blockchain.security.SecurityUtils;

import javax.net.ssl.*;
import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Node {
    public final List<Block> blockchain = new ArrayList<>();

    private final SSLServerSocket serverSocket;
    private final SSLSocketFactory socketFactory;

    // --------- 持久化的服务端流 与 客户端流 ---------
    private ObjectInputStream  in;   // B 端读流
    private ObjectOutputStream out;  // A 端写流

    public final PrivateKey privKey;
    public final X509Certificate cert;

    public Node(int listenPort,
                String keyStorePath, String keyStorePwd,
                String trustStorePath, String trustStorePwd) throws Exception {
        // 初始化 TLS 上下文
        SSLContext ctx = SecurityUtils.initSSLContext(
                keyStorePath, keyStorePwd,
                trustStorePath, trustStorePwd
        );
        this.socketFactory = ctx.getSocketFactory();
        this.serverSocket  = (SSLServerSocket)
                ctx.getServerSocketFactory().createServerSocket(listenPort);

        // 从 keystore 提取私钥 & 证书
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keyStorePath)) {
            ks.load(fis, keyStorePwd.toCharArray());
        }
        String alias = ks.aliases().nextElement();
        Key key = ks.getKey(alias, keyStorePwd.toCharArray());
        this.privKey = (PrivateKey) key;
        this.cert    = (X509Certificate) ks.getCertificate(alias);
    }

    /**
     * B 端调用，后台启动一次 accept()：
     * - 接受来自 A 的唯一连接
     * - 建立一个 ObjectInputStream
     * - 无限循环 readObject() 来处理所有后续 broadcast
     */
    public void startServerListener() {
        Thread listener = new Thread(() -> {
            try {
                // 只 accept 一次
                SSLSocket sock = (SSLSocket) serverSocket.accept();
                in = new ObjectInputStream(sock.getInputStream());
                // 持续循环读取新块
                while (true) {
                    Block block = (Block) in.readObject();
                    String lastHash = blockchain.isEmpty()
                            ? "0" : blockchain.get(blockchain.size()-1).hash;
                    if (block.isValid() && block.previousHash.equals(lastHash)) {
                        blockchain.add(block);
                    } else {
                        System.err.println("Invalid block rejected");
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }, "Node-Listener");
        listener.setDaemon(true);
        listener.start();
    }

    /**
     * A 端调用，建立一次到 B 的长连接：
     * - 创建 SSLSocket
     * - 建立一个 ObjectOutputStream
     * 后续 broadcast() 都往这个 out 写
     */
    public void connectToPeer(String host, int port) throws IOException {
        SSLSocket sock = (SSLSocket) socketFactory.createSocket(host, port);
        out = new ObjectOutputStream(sock.getOutputStream());
    }

    /** 写入同一个 out 流，不再关闭它 */
    public void broadcast(Block block) throws IOException {
        out.writeObject(block);
        out.flush();
    }
}
