package com.simulation.blockchain.basic;

import com.google.gson.GsonBuilder;
import com.simulation.blockchain.security.SecurityUtils;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class NoobChain {

    public static void main(String[] args) throws Exception {
        // 1) 启动 A（5000）和 B（5001）
        Node nodeA = new Node(
                5000,
                "src/main/resources/ssl/keystoreA.jks","passwordA",
                "src/main/resources/ssl/truststoreA.jks","passwordA"
        );
        Node nodeB = new Node(
                5001,
                "src/main/resources/ssl/keystoreB.jks","passwordB",
                "src/main/resources/ssl/truststoreB.jks","passwordB"
        );

        // 2) B 端先监听（后台线程立即返回）
        nodeB.startServerListener();
        Thread.sleep(200);  // 保证 accept() 就绪

        // 3) A 端建立到 B 的长连接
        nodeA.connectToPeer("localhost", 5001);

        // 4) 创世块
        Block genesis = new Block("Genesis", "0", nodeA.privKey, nodeA.cert);
        nodeA.blockchain.add(genesis);
        nodeA.broadcast(genesis);
        Thread.sleep(200);  // 等 B 端处理

        printChain("A", nodeA.blockchain);
        printChain("B", nodeB.blockchain);

        // 5) 交互式添加
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("\n输入新块数据（exit 结束）：");
            String data = scanner.nextLine();
            if ("exit".equalsIgnoreCase(data)) break;

            Block newBlock = new Block(
                    data,
                    nodeA.blockchain.get(nodeA.blockchain.size() - 1).hash,
                    nodeA.privKey,
                    nodeA.cert
            );
            nodeA.blockchain.add(newBlock);
            nodeA.broadcast(newBlock);
            Thread.sleep(200);

            printChain("A", nodeA.blockchain);
            printChain("B", nodeB.blockchain);
        }
        scanner.close();
        System.out.println("结束。");
    }

    private static void printChain(String nodeName, List<Block> chain) throws Exception {
        System.out.println("\n=== 节点 " + nodeName + " 链长: " + chain.size() + " ===");
        System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(chain));
        for (int i = 0; i < chain.size(); i++) {
            Block b = chain.get(i);
            X509Certificate cert = SecurityUtils.loadCertificate(b.certificate);
            String sigPrefix = Base64.getEncoder().encodeToString(
                    Arrays.copyOf(Base64.getDecoder().decode(b.signature), 16)
            );
            System.out.printf(
                    "块 %d:\n  hash = %s\n  签名前16字节(Base64) = %s...\n  证书颁发给 = %s\n",
                    i, b.hash, sigPrefix, cert.getSubjectX500Principal().getName()
            );
        }
    }
}
