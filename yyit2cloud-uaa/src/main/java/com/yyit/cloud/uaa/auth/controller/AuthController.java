package com.yyit.cloud.uaa.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/oauth2")
public class AuthController {

    @GetMapping("/consent")
    public String consent(){
        return "consent";
    }

}
