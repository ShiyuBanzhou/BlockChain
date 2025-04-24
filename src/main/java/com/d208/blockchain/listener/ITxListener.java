package com.d208.blockchain.listener;

import com.d208.blockchain.event.NewTxEvent;

import java.util.EventListener;

public interface ITxListener extends EventListener {
    public void newTxEvent(NewTxEvent event);
}
