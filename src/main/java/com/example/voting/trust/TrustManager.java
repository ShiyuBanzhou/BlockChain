package com.example.voting.trust;

import java.util.HashSet;
import java.util.Set;

/**
 * 简单节点信任/黑名单管理
 */
public class TrustManager {
    private String ownerNode;          // 本地节点 ID
    private Set<String> blacklist = new HashSet<>();

    public TrustManager(String nodeId) {
        this.ownerNode = nodeId;
    }

    /** 将节点加入黑名单 */
    public void blacklistNode(String nodeId) {
        blacklist.add(nodeId);
        System.out.println("节点 " + nodeId + " 已被黑名单！");
    }

    /** 检查节点是否在黑名单 */
    public boolean isBlacklisted(String nodeId) {
        return blacklist.contains(nodeId);
    }
}
