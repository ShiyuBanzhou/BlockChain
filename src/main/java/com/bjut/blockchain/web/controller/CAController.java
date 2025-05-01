package com.bjut.blockchain.web.controller;

import com.bjut.blockchain.web.service.CAImpl;

import com.bjut.blockchain.web.util.KeyAgreementUtil;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.CrossOrigin;



@Controller
@CrossOrigin
public class CAController {

    @GetMapping("/ca")
    @ResponseBody
    public String getCA() throws Exception {
       return CAImpl.getCertificateMap();
    }


    @GetMapping("/password")
    @ResponseBody
    public String getPassword() throws Exception {
        return KeyAgreementUtil.keyAgreementValue;
    }
}
