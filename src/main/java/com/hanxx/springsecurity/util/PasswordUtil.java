package com.hanxx.springsecurity.util;

import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 *  密码加密
 */
public class PasswordUtil implements PasswordEncoder{

    private final static String SALT = "123456";    //密码盐
    // 加密方法 Md5PasswordEncoder只有springsecurity5.x以下存在
    @Override
    public String encode(CharSequence charSequence) {
        // md5加密密码
        Md5PasswordEncoder encoder = new Md5PasswordEncoder();
        // 加密需要一个密码盐
        return encoder.encodePassword(charSequence.toString(),SALT);
    }

    // 匹配方法
    @Override
    public boolean matches(CharSequence charSequence, String s) {
        Md5PasswordEncoder encoder =new Md5PasswordEncoder();
        return encoder.isPasswordValid(s,charSequence.toString(),SALT);
    }
}
