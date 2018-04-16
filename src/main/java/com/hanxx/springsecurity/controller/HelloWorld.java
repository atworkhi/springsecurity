package com.hanxx.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author hanxx
 * @Date 2018/4/1617:34
 */
@RestController
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class HelloWorld {

    @RequestMapping("/")
    public String Hello(){
        return "Hello Spring boot + Spring security!";
    }

    @RequestMapping("/home")
    public String Home(){
        return "我是需要输入账号密码的！";
    }
    /**
     *  角色权限验证 注意：@PreAuthorize("hasRole('ROLE_ADMIN')")
     *  必须定义 ROLE_ 前缀
     * @return
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping("/role")
    public String Role(){
        return "我是需要ADMIN管理员登陆的！";
    }
}
