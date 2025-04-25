package com.bjut.blockchain.web.model;

import java.io.Serializable;

/**
 * 业务数据模型
 * 
 * @author Jared Jia
 *
 */
public class Transaction implements Serializable {

	private static final long serialVersionUID = 1L;
	/**
	 * 唯一标识
	 */
	private String id;
	/**
	 * 业务数据
	 */
	private String businessInfo;
	
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getBusinessInfo() {
		return businessInfo;
	}
	public void setBusinessInfo(String businessInfo) {
		this.businessInfo = businessInfo;
	}

}
