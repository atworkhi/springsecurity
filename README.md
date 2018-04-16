## springsecurity 权限管理
### 环境搭建：
spring boot 1.5x + spring security 4.x
### Hello world：
cotroller 访问提示输入账户密码：
### 配置spring security
@Configuration
// 添加web支持
@EnableWebSecurity
SpringSecurityConfig 继承 WebSecurityConfigurerAdapter
```$xslt
// 过滤掉不拦截的资源文件
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**","/css/**","/img/**");
    }
```

配置http拦截策略：
```$xslt
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
```
基于系统内存的登陆 设置用户名 密码 与角色
```$xslt
/**
             * springsecurity 5.0版本需要设置 如此的密码验证方法，不然就会出错：
             * There is no PasswordEncoder mapped for the id “null”
             * @return
             */
           @Bean
            public static NoOpPasswordEncoder passwordEncoder() {
                return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
            }
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            // ADMIN 权限
            auth.inMemoryAuthentication().withUser("admin").password("123456").roles("ADMIN");
            // USER权限
            auth.inMemoryAuthentication().withUser("user01").password("123456").roles("USER");
        }
```
使用角色管理：
 ```$xslt
  //设置需要角色验证才能访问的界面的
   @EnableGlobalMethodSecurity(prePostEnabled = true)
    ```
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
```
@EnableAutoConfiguration：作用：

启用Spring应用程序上下文的自动配置
exculd="""忽略某选项的自动配置

使用UserDetails：
```$xslt
继承UserDetailsService

密码加密工具类(springscurity5.x以下)
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
使用：
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(new PasswordUtil());
        auth.jdbcAuthentication().usersByUsernameQuery("").passwordEncoder(new PasswordUtil());
    }
```
判断是否为登陆用户
```$xslt
@preAuthorize(principal.username,equals(#username) and #user.username.equals("xxx"))
public Object user(String username, User user){
}
```
@preFilter()  @postFilter @preAuthorize @postAuthorize