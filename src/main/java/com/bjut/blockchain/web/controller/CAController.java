package com.bjut.blockchain.web.controller;

import com.bjut.blockchain.web.service.CAImpl;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;



@Controller
public class CAController {

    @GetMapping("/ca")
    @ResponseBody
    public String getCA() throws Exception {
       return CAImpl.getCertificateMap();
    }
}
