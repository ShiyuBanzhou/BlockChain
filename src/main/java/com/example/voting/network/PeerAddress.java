package com.example.voting.network;

import java.io.Serializable;
import java.util.Objects;

/**
 * Represents the network address of a peer node.
 * 代表对等节点的网络地址。
 */
public class PeerAddress implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String host;
    private final int port;

    public PeerAddress(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    @Override
    public String toString() {
        return host + ":" + port;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PeerAddress that = (PeerAddress) o;
        return port == that.port && Objects.equals(host, that.host);
    }

    @Override
    public int hashCode() {
        return Objects.hash(host, port);
    }
}