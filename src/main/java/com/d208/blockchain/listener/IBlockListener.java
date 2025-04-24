package com.d208.blockchain.listener;

import com.d208.blockchain.event.NewBlockEvent;

import java.util.EventListener;

public interface IBlockListener extends EventListener {
    public void newBlockEvent(NewBlockEvent event);
}
