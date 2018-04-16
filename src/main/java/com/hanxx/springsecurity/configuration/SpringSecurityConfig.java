package com.hanxx.springsecurity.configuration;

import com.hanxx.springsecurity.service.UserService;
import com.hanxx.springsecurity.util.PasswordUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @Author hanxx
 * @Date 2018/4/1617:37
 */
@Configuration
// 添加web支持
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    private UserService userService;
    // 基于系统内存的登陆 设置用户名 密码 与角色
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // ADMIN 权限
        auth.inMemoryAuthentication().withUser("admin").password("123456").roles("ADMIN");
        // USER权限
        auth.inMemoryAuthentication().withUser("user01").password("123456").roles("USER");

        auth.userDetailsService(userService).passwordEncoder(new PasswordUtil());
        auth.jdbcAuthentication().usersByUsernameQuery("").passwordEncoder(new PasswordUtil());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // http请求需要拦截
        http.authorizeRequests()
                // 主路径不拦截
                .antMatchers("/").permitAll()
                // 其他的需要验证
                .anyRequest().authenticated()
                // 注销可以不拦截
                .and().logout().permitAll()
                // 允许form 表单登陆
                .and().formLogin();
        // 关闭默认的csrf验证
        http.csrf().disable();
    }
    // 过滤掉不拦截的资源文件
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**","/css/**","/img/**");
    }
}
