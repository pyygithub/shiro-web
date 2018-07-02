### 什么是Shiro？
>Apache Shiro是一个强大且易用的Java安全框架,执行身份验证、授权、密码学和会话管理。相比较Spring Security，shiro有小巧、简单、易上手等的优点。所以很多框架都在使用shiro。


* Apache的强大的灵活的开源安全框架
* 认证、授权、企业会话管理、安全加密
* 使用Shiro可以方便快捷完成项目中的权限管理开发。
###Shior安全框架简介
![](https://upload-images.jianshu.io/upload_images/11464886-e106ffa55e2972f2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

**综述:**
个人认为现阶段需求，权限的操作粒度能控制在路径及按钮上，数据粒度通过sql实现。Shrio简单够用。

至于OAuth，OpenID 站点间统一登录功能，现租户与各个产品间单点登录已经通过cookies实现，所以Spring Security的这两个功能可以不考虑。

SpringSide网站的权限也是用Shrio做的。

###Shiro整体架构

![](https://upload-images.jianshu.io/upload_images/11464886-da46b00850d529aa.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
Shiro包含了三个核心组件：Subject, SecurityManager 和 Realms。
- Subject代表了当前用户的安全操作。

- SecurityManager则管理所有用户的安全操作。它是Shiro框架的核心，典型的Facade模式，Shiro通过SecurityManager来管理内部组件实例，并通过它来提供安全管理的各种服务。

- Realm充当了Shiro与应用安全数据间的“桥梁”或者“连接器”。也就是说，当对用户执行认证（登录）和授权（访问控制）验证时，Shiro会从应用配置的Realm中查找用户及其权限信息。

###Shiro认证

![](https://upload-images.jianshu.io/upload_images/11464886-412b712e646660df.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
  ```
/**
 * Copyright (C), 2015-2018, XXX有限公司
 * 项目名称:
 * 文件名称:
 * 作者: wolf
 * 日期: 2018/6/18 22:15
 * 描述:
 * 版本: V1.0
 */
package com.pyy.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;


/**
 * Shiro认证测试
 *
 * @author wolf
 * @create 2018/6/18
 * @since 1.0.0
 */
public class AuthenticationTest {

    SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();

    @Before
    public void before() {
        simpleAccountRealm.addAccount("admin", "123456");
    }

    @Test
    public void testAuthentication() {
        //1. 构建SecurityManager 环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);

        //2. 主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("admin", "123456");
        subject.login(token);

        System.out.println("是否认证通过：" + subject.isAuthenticated());

        subject.logout();

        System.out.println("是否认证通过：" + subject.isAuthenticated());
    }
}
```

###Shiro授权
![](https://upload-images.jianshu.io/upload_images/11464886-65c607fea65e797d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

```
/**
 * Copyright (C), 2015-2018, XXX有限公司
 * 项目名称:
 * 文件名称:
 * 作者: wolf
 * 日期: 2018/6/18 22:15
 * 描述:
 * 版本: V1.0
 */
package com.pyy.test;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;


/**
 * Shiro认证测试
 *
 * @author wolf
 * @create 2018/6/18
 * @since 1.0.0
 */
public class AuthenticationTest {

    SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();

    @Before
    public void before() {
        simpleAccountRealm.addAccount("admin", "123456", "admin", "user");
    }

    @Test
    public void testAuthentication() {
        //1. 构建SecurityManager 环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);

        //2. 主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("admin", "123456");
        subject.login(token);

        System.out.println("是否认证通过：" + subject.isAuthenticated());

        //3. 验证是否拥有指定角色
        subject.checkRole("admin");
        subject.checkRoles("admin", "user");
    }
}
```
### Subject认证主体包含两个信息
Principals : 身份，可以是用户名、邮箱、手机号等，用来标识一个登录主体身份。
Credentials : 凭证，常见有密码，数字证书。
###Realm
Realm 意思是域，Shiro 从 Realm 中获取验证数据。

Realm 有很多种类，常见的有 Ini realm , Jdbc realm , text realm

##### IniRealm配置使用
在资源路径下创建user.ini文件：
```
[users]
admin=123456,admin
[roles]
admin=user:delete
```
编写测试方法：
```
public class IniRealmTest {
    @Test
    public void testAuthentication() {
        IniRealm iniRealm = new IniRealm("classpath:user.ini");

        //1. 构建SecurityManager 环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(iniRealm);

        //2. 主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("admin", "123456");
        subject.login(token);

        System.out.println("是否认证通过：" + subject.isAuthenticated());

        //3. 验证是否拥有指定角色
        subject.checkRole("admin");

        //4. 验证用户权限
        subject.checkPermissions("user:update");
    }
}
```
参考：[安全认证框架Shiro (一）- ini配置文件](https://blog.csdn.net/achenyuan/article/details/70477818)

#### 重点看下jdbc realm的使用。
在pom.xml文件中引入数据库驱动包
```
       <dependency>
          <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>5.1.46</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid</artifactId>
            <version>1.1.6</version>
        </dependency>
```
#####新建数据库 db_shiro
 ```
create database db_shiro character set utf8;

use db_shiro;

-- 用户表
create table users(
  id int primary key auto_increment,
  username varchar(50),
  password varchar(50)
);

insert into users(username, password) values('admin', '123456');

-- 用户角色表
create table user_role(
  id int PRIMARY key auto_increment,
  user_name varchar(50),
  role_name varchar(50)
);

insert into user_role(user_name, role_name) values('admin', 'user');

-- 角色权限表
create table roles_permissions(
  id int PRIMARY key auto_increment,
  permission varchar(200),
  role_name varchar(50)
);

insert into roles_permissions(permission, role_name) values('user:add', 'user');
```
编写测试方法：
```
/**
 * Copyright (C), 2015-2018, XXX有限公司
 * 项目名称:
 * 文件名称:
 * 作者: wolf
 * 日期: 2018/6/19 23:08
 * 描述:
 * 版本: V1.0
 */
package com.pyy.test;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

/**
 * 〈〉
 *
 * @author wolf
 * @create 2018/6/19
 * @since 1.0.0
 */
public class JdbcRealmTest {

    DruidDataSource dataSource = new DruidDataSource();

    {
        dataSource.setUrl("jdbc:mysql://localhost:3306/db_shiro");
        dataSource.setUsername("root");
        dataSource.setPassword("123456");
    }

    @Test
    public void testAuthentication() {
        JdbcRealm jdbcRealm = new JdbcRealm();
        jdbcRealm.setDataSource(dataSource);
        jdbcRealm.setPermissionsLookupEnabled(true);//开启权限验证

        //自定义验证sql
        String sql = "select password from users where username = ?";
        jdbcRealm.setAuthenticationQuery(sql);

        //自定义角色查询
        String roleSql = "select role_name from user_role where user_name = ?";
        jdbcRealm.setUserRolesQuery(roleSql);
       //自定义权限认证

        String permissionSql = "select permission from roles_permissions where role_name = ?";
        jdbcRealm.setPermissionsQuery(permissionSql);

        //1. 构建SecurityManager 环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(jdbcRealm);

        //2. 主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("admin", "123456");
        subject.login(token);

        System.out.println("是否认证通过：" + subject.isAuthenticated());

        //3. 验证是否拥有指定角色
        subject.checkRole("user");

        //4. 验证用户权限
        subject.checkPermissions("user:add");
    }
}
```

###自定义Realm

```
package com.pyy.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
public class CustomRealm extends AuthorizingRealm{

    // 模拟用户数据库数据
    Map<String,String> userMap = new HashMap<String, String>(16);
    {
        userMap.put("admin", "123456");
        super.setName("costomRealm");
    }

    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) principalCollection.getPrimaryPrincipal();

        // 从数据库中根据用户名获取角色数据
        Set<String> roles = getRolesByUsername(username);
        // 从数据库中根据用户名获取权限数据
        Set<String> permissions = getPermissionbyUsername(username);

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setStringPermissions(permissions);
        simpleAuthorizationInfo.setRoles(roles);
        return simpleAuthorizationInfo;
    }

    /**
     * 模拟用户权限信息
     * @param username
     * @return
     */
    private Set<String> getPermissionbyUsername(String username) {
        Set<String> sets = new HashSet<String>();
        sets.add("user:delete");
        sets.add("user:add");
        return sets;
    }

    /**
     * 模拟根据用户名获取数据库中的角色数据
     * @param username
     * @return
     */
    private Set<String> getRolesByUsername(String username) {
        Set<String> sets = new HashSet<String>();
        sets.add("admin");
        sets.add("user");
        return sets;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 1.从主体传过来的认证信息中，获取用户名
        String username = (String) authenticationToken.getPrincipal();

        // 2.通过用户名去到数据库中获取凭证
        String password = getPasswordByUsername(username);
        if(password == null) {
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username, password, "costomRealm");
        return authenticationInfo;
    }

    /**
     * 模拟数据库查询凭证
     * @param username
     * @return
     */
    private String getPasswordByUsername(String username) {
        return userMap.get(username);
    }
}
```
测试类：
```
package com.pyy.test;

import com.pyy.shiro.realm.CustomRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
public class CostomRealmTest {

    @Test
    public void testAuthentication1() {
        CustomRealm costomRealm = new CustomRealm();

        //1. 构建SecurityManager 环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(costomRealm);

        //2. 主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("admin", "123456");
        subject.login(token);

        System.out.println("是否认证通过：" + subject.isAuthenticated());

        subject.checkPermission("user:add");
        subject.checkRole("admin");
    }

}
```
这里我们使用本地集合来模拟认证，真实开发中我们需要使用缓存或者数据库来完成。

###Shiro加密
![](https://upload-images.jianshu.io/upload_images/11464886-68202388121417a9.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

使用HashedCredentialsMatcher完成加密配置
```
/**
 * Created by Administrator on 2018/6/24 0024.
 */
public class CostomRealmTest {

    @Test
    public void testAuthentication1() {
        CustomRealm customRealm = new CustomRealm();

        //1. 构建SecurityManager 环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(customRealm);

        // 2.加密配置
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");//设置加密算法名称
        matcher.setHashIterations(1);//设置加密次数

        customRealm.setCredentialsMatcher(matcher);

        //3. 主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("admin", "123456");
        subject.login(token);

        System.out.println("是否认证通过：" + subject.isAuthenticated());
        subject.checkPermission("user:add");
        subject.checkRole("admin");
    }
}
```
在定义CostomRealm中设置对应的盐salt值：
```
package com.pyy.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
public class CustomRealm extends AuthorizingRealm{

    public static void main(String[] args) {
        // 加salt密码
        Md5Hash md5Hash = new Md5Hash("123456", "pyy");
        System.out.println(md5Hash);
    }
    // 模拟用户数据库数据
    Map<String,String> userMap = new HashMap<String, String>(16);
    {
        // 数据库中密码123456的md5密文
        userMap.put("admin", "5470decd768082c538a78fa7adae9e60");
        super.setName("costomRealm");
    }

    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) principalCollection.getPrimaryPrincipal();

        // 从数据库中根据用户名获取角色数据
        Set<String> roles = getRolesByUsername(username);
        // 从数据库中根据用户名获取权限数据
        Set<String> permissions = getPermissionbyUsername(username);

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setStringPermissions(permissions);
        simpleAuthorizationInfo.setRoles(roles);
        return simpleAuthorizationInfo;
    }

    /**
     * 模拟用户权限信息
     * @param username
     * @return
     */
    private Set<String> getPermissionbyUsername(String username) {
        Set<String> sets = new HashSet<String>();
        sets.add("user:delete");
        sets.add("user:add");
        return sets;
    }

    /**
     * 模拟根据用户名获取数据库中的角色数据
     * @param username
     * @return
     */
    private Set<String> getRolesByUsername(String username) {
        Set<String> sets = new HashSet<String>();
        sets.add("admin");
        sets.add("user");
        return sets;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 1.从主体传过来的认证信息中，获取用户名
        String username = (String) authenticationToken.getPrincipal();

        // 2.通过用户名去到数据库中获取凭证
        String password = getPasswordByUsername(username);
        if(password == null) {
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username, password, "costomRealm");
        authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("pyy"));//设置盐salt

        return authenticationInfo;
    }

    /**
     * 模拟数据库查询凭证
     * @param username
     * @return
     */
    private String getPasswordByUsername(String username) {
        return userMap.get(username);
    }
}
```

###SpringBoot整合Shiro
1. 新建springBoot工程
![](https://upload-images.jianshu.io/upload_images/11464886-41989a4edd7d93c6.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
2. 导出shiro依赖包
```
<!-- shiro权限控制框架 -->
<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<!-- shiro权限控制框架 -->
		<dependency>
			<groupId>org.apache.shiro</groupId>
			<artifactId>shiro-core</artifactId>
			<version>1.4.0</version>
		</dependency>
		<dependency>
			<groupId>org.apache.shiro</groupId>
			<artifactId>shiro-spring</artifactId>
			<version>1.3.2</version>
		</dependency>
```
3. 编写自定义Realm
```
package com.pyy.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
public class CustomRealm extends AuthorizingRealm{

    public static void main(String[] args) {
        // 加salt密码
        Md5Hash md5Hash = new Md5Hash("123456", "pyy");
        System.out.println(md5Hash);
    }
    // 模拟用户数据库数据
    Map<String,String> userMap = new HashMap<String, String>(16);
    {
        // 数据库中密码123456的md5密文
        userMap.put("admin", "5470decd768082c538a78fa7adae9e60");
        super.setName("costomRealm");
    }

    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) principalCollection.getPrimaryPrincipal();

        // 从数据库中根据用户名获取角色数据
        Set<String> roles = getRolesByUsername(username);
        // 从数据库中根据用户名获取权限数据
        Set<String> permissions = getPermissionbyUsername(username);

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setStringPermissions(permissions);
        simpleAuthorizationInfo.setRoles(roles);
        return simpleAuthorizationInfo;
    }

    /**
     * 模拟用户权限信息
     * @param username
     * @return
     */
    private Set<String> getPermissionbyUsername(String username) {
        Set<String> sets = new HashSet<String>();
        sets.add("user:delete");
        sets.add("user:add");
        return sets;
    }

    /**
     * 模拟根据用户名获取数据库中的角色数据
     * @param username
     * @return
     */
    private Set<String> getRolesByUsername(String username) {
        Set<String> sets = new HashSet<String>();
        sets.add("admin");
        sets.add("user");
        return sets;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 1.从主体传过来的认证信息中，获取用户名
        String username = (String) authenticationToken.getPrincipal();

        // 2.通过用户名去到数据库中获取凭证
        String password = getPasswordByUsername(username);
        if(password == null) {
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username, password, "costomRealm");
        authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("pyy"));//设置盐salt

        return authenticationInfo;
    }

    /**
     * 模拟数据库查询凭证
     * @param username
     * @return
     */
    private String getPasswordByUsername(String username) {
        return userMap.get(username);
    }
}
```

4. 配置shiro过滤器
```
package com.pyy.shiro.config;

import com.pyy.shiro.realm.CustomRealm;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
@Configuration
public class ShiroConfiguration {

    /**
     * ShiroFilterFactoryBean 处理拦截资源文件问题。
     * 注意：单独一个ShiroFilterFactoryBean配置是会报错的，因为在初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
     *
     * Filter Chain定义说明 1、一个URL可以配置多个Filter，使用逗号分隔 2、当设置多个过滤器时，全部验证通过，才视为通过
     * 3、部分过滤器可指定参数，如perms，roles
     *
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(org.apache.shiro.mgt.SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

        // 必须设置 SecurityManager
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setLoginUrl("/login.html");
        // 登录成功后要跳转的链接
        shiroFilterFactoryBean.setSuccessUrl("/index.html");
        // 未授权界面;
        shiroFilterFactoryBean.setUnauthorizedUrl("/403.html");

        //自定义拦截器
        Map<String, Filter> filtersMap = new LinkedHashMap<>();
        //限制同一帐号同时在线的个数。
        //filtersMap.put("kickout", kickoutSessionControlFilter());
        shiroFilterFactoryBean.setFilters(filtersMap);

        // 权限控制map.过滤器链
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/*", "authc");


        // 配置不会被拦截的链接 顺序判断
        // 配置退出过滤器,其中的具体的退出代码Shiro已经替我们实现了
        // 从数据库获取动态的权限
        // filterChainDefinitionMap.put("/add", "perms[权限添加]");
        // <!-- 过滤链定义，从上向下顺序执行，一般将 /**放在最为下边 -->:这是一个坑呢，一不小心代码就不好使了;
        // <!-- authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问-->
        //logout这个拦截器是shiro已经实现好了的。
        // 实际开发中需要从数据库获取
        /*
        List<SysPermissionInit> list = sysPermissionInitService.selectAll();

        for (SysPermissionInit sysPermissionInit : list) {
            filterChainDefinitionMap.put(sysPermissionInit.getUrl(), sysPermissionInit.getPermissionInit());
        }
        */

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    @Bean
    public org.apache.shiro.mgt.SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

        CustomRealm customRealm = new CustomRealm();

        // 2.加密配置
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");//设置加密算法名称
        matcher.setHashIterations(1);//设置加密次数
        customRealm.setCredentialsMatcher(matcher);

        // 设置Realm
        securityManager.setRealm(customRealm);
        return securityManager;
    }
}
```
5. 编写UserController类
```
package com.pyy.shiro.controller;

import com.pyy.shiro.vo.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
@RestController
public class UserController {

    @PostMapping("/login")
    public String login(User user) {
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(), user.getPassword());
        try {
            subject.login(token);
            return "登录成功";
        } catch (AuthenticationException e) {
            return e.getMessage();
        }
    }
}
```
6. 在postman中输入：http://localhost:8080/login完成测试
![](https://upload-images.jianshu.io/upload_images/11464886-5ede00ea551efb99.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

---
以上是使用springboot模拟shiro登录认证，下面使用数据库完成真实用户登录认证。

###SpringBoot整合Shiro从数据库获取认证数据
> 这里为了方便演示，使用spring-jdbc。真实项目中还是推荐使用Mybatis操作数据库。
1. 引入spring-jdbc依赖包
```
        <dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-jdbc</artifactId>
		</dependency>
		<dependency>
			<groupId>com.alibaba</groupId>
			<artifactId>druid</artifactId>
			<version>0.2.23</version>
		</dependency>
		<dependency>
			<groupId>mysql</groupId>
			<artifactId>mysql-connector-java</artifactId>
			<version>5.1.38</version>
		</dependency>
```
2. 配置数据源 application.yml
```
###### 设置数据源 :  ######
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/db_shiro?autoReconnect=true&useUnicode=true&characterEncoding=utf-8
    username: root
    password: 123456
    driver-class-name: com.mysql.jdbc.Driver
```

3. 编写UserDao接口和UserDaoImpl实现类
```
package com.pyy.shiro.dao;

import com.pyy.shiro.vo.User;

import java.util.List;

/**
 * Created by Administrator on 2018/6/24
 */
public interface UserDao {
    User findUserByUsername(String username);

    List<String> findRolesByUsername(String username);
}
```
4. 编写自定义CustomRelam认证类
```
package com.pyy.shiro.realm;

import com.pyy.shiro.dao.UserDao;
import com.pyy.shiro.vo.User;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.*;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
public class CustomRealm extends AuthorizingRealm{
    @Autowired
    private UserDao userDao;

    public static void main(String[] args) {
        // 加salt密码
        Md5Hash md5Hash = new Md5Hash("123456", "pyy");
        System.out.println(md5Hash);
    }

    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        String username = (String) principalCollection.getPrimaryPrincipal();

        // 从数据库中根据用户名获取角色数据
        Set<String> roles = getRolesByUsername(username);
        // 从数据库中根据用户名获取权限数据
        Set<String> permissions = getPermissionbyUsername(username);

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.setStringPermissions(permissions);
        simpleAuthorizationInfo.setRoles(roles);
        return simpleAuthorizationInfo;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 1.从主体传过来的认证信息中，获取用户名
        String username = (String) authenticationToken.getPrincipal();

        // 2.通过用户名去到数据库中获取凭证
        String password = getPasswordByUsername(username);
        if(password == null) {
            return null;
        }
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username, password, "costomRealm");
        authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("pyy"));//设置盐salt

        return authenticationInfo;
    }

    /**
     * 模拟数据库查询凭证
     * @param username
     * @return
     */
    private String getPasswordByUsername(String username) {
        User user = userDao.findUserByUsername(username);
        if(user == null){
            return null;
        }
        return user.getPassword();
    }

    /**
     * 模拟根据用户名获取数据库中的角色数据
     * @param username
     * @return
     */
    private Set<String> getRolesByUsername(String username) {
        List<String> list = userDao.findRolesByUsername(username);
        Set<String> sets = new HashSet<>(list);
        return sets;
    }
    /**
     * 模拟用户权限信息
     * @param username
     * @return
     */
    private Set<String> getPermissionbyUsername(String username) {
        Set<String> sets = new HashSet<String>();
        sets.add("user:delete");
        sets.add("user:add");
        return sets;
    }
}
```
5. 编写shiro过滤器配置
```
package com.pyy.shiro.config;

import com.pyy.shiro.dao.UserDao;
import com.pyy.shiro.realm.CustomRealm;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
@Configuration
public class ShiroConfiguration {
    /**
     * 身份认证realm; (这个需要自己写，账号密码校验；权限等)
     */
    @Bean
    public CustomRealm customRealm() {
        CustomRealm myRealm = new CustomRealm();
        return myRealm;
    }

    /**
     * ShiroFilterFactoryBean 处理拦截资源文件问题。
     * 注意：单独一个ShiroFilterFactoryBean配置是会报错的，因为在初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
     *
     * Filter Chain定义说明 1、一个URL可以配置多个Filter，使用逗号分隔 2、当设置多个过滤器时，全部验证通过，才视为通过
     * 3、部分过滤器可指定参数，如perms，roles
     *
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(org.apache.shiro.mgt.SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

        // 必须设置 SecurityManager
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setLoginUrl("/login.html");
        // 登录成功后要跳转的链接
        shiroFilterFactoryBean.setSuccessUrl("/index.html");
        // 未授权界面;
        shiroFilterFactoryBean.setUnauthorizedUrl("/403.html");

        //自定义拦截器
        Map<String, Filter> filtersMap = new LinkedHashMap<>();
        //限制同一帐号同时在线的个数。
        //filtersMap.put("kickout", kickoutSessionControlFilter());
        shiroFilterFactoryBean.setFilters(filtersMap);

        // 权限控制map.过滤器链
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/*", "authc");


        // 配置不会被拦截的链接 顺序判断
        // 配置退出过滤器,其中的具体的退出代码Shiro已经替我们实现了
        // 从数据库获取动态的权限
        // filterChainDefinitionMap.put("/add", "perms[权限添加]");
        // <!-- 过滤链定义，从上向下顺序执行，一般将 /**放在最为下边 -->:这是一个坑呢，一不小心代码就不好使了;
        // <!-- authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问-->
        //logout这个拦截器是shiro已经实现好了的。
        // 实际开发中需要从数据库获取
        /*
        List<SysPermissionInit> list = sysPermissionInitService.selectAll();

        for (SysPermissionInit sysPermissionInit : list) {
            filterChainDefinitionMap.put(sysPermissionInit.getUrl(), sysPermissionInit.getPermissionInit());
        }
        */

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    @Bean
    public org.apache.shiro.mgt.SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

        CustomRealm customRealm = customRealm();
        // 2.加密配置
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");//设置加密算法名称
        matcher.setHashIterations(1);//设置加密次数
        customRealm.setCredentialsMatcher(matcher);

        // 设置Realm
        securityManager.setRealm(customRealm);
        return securityManager;
    }
}

```
7.  编写UserController
```
package com.pyy.shiro.controller;

import com.pyy.shiro.vo.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
@RestController
public class UserController {

    @PostMapping("/login")
    public String login(User user) {
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(), user.getPassword());
        try {
            subject.login(token);
            return "登录成功";
        } catch (AuthenticationException e) {
            return e.getMessage();
        }
    }
}

```
8. 在postman中输入：http://localhost:8080/login完成测试
![](https://upload-images.jianshu.io/upload_images/11464886-5ede00ea551efb99.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

### 通过注解配置授权

1. 添加注解依赖包
```
<dependency>
			<groupId>org.aspectj</groupId>
			<artifactId>aspectjweaver</artifactId>
		</dependency>
```
2. 在ShiroConfiguration类中添加以下配置
```
 //Shiro生命周期处理器
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return  new LifecycleBeanPostProcessor();
    }

    /**
     * 开启Shiro的注解(如@RequiresRoles,@RequiresPermissions),需借助SpringAOP扫描使用Shiro注解的类,并在必要时进行安全逻辑验证
     * 配置以下两个bean(DefaultAdvisorAutoProxyCreator(可选)和AuthorizationAttributeSourceAdvisor)即可实现此功能
     * @return
     */
    @Bean
    @DependsOn({ "lifecycleBeanPostProcessor" })
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
```
3. 在UserController中使用注解完成权限测试
```
 @RequiresRoles("user")
    @GetMapping("/testRoles")
    public String testRoles(){
        return  "testRole success";
    }

    @RequiresPermissions({"user:add", "user:del"})
    @GetMapping("/testPermissions")
    public String testPermissions(){
        return  "testPermissions success";
    }
```
#####注释支持
- @RequiresAuthentication 验证用户是否登录，等同于方法subject.isAuthenticated() 结果为true时；
- @RequiresUser 验证用户是否被记忆，user有两种含义：一种是成功登录的（subject.isAuthenticated()结果为true)另外一种是被记忆的(subject.isRemembered()结果为true）；
- @RequiresGuest 验证是否为匿名请求；
- @RequiresRoles 必须要有角色；
- @RequiresPermissions 必须要有权限；

### Shiro过滤器
#####内置过滤器
**anon（匿名）：**  org.apache.shiro.web.filter.authc.AnonymousFilter
**authc（身份验证）：**       org.apache.shiro.web.filter.authc.FormAuthenticationFilter
**authcBasic：** （http基本验证）    org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter
**logout（退出）：**        org.apache.shiro.web.filter.authc.LogoutFilter
**noSessionCreation（不创建session）：** org.apache.shiro.web.filter.session.NoSessionCreationFilter
**perms(许可验证)  ：**org.apache.shiro.web.filter.authz.PermissionsAuthorizationFilter
**port（端口验证）：**   org.apache.shiro.web.filter.authz.PortFilter
**rest  (rest方面)  ：**org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter
**roles（权限验证）：**  org.apache.shiro.web.filter.authz.RolesAuthorizationFilter
**ssl （ssl方面）：**   org.apache.shiro.web.filter.authz.SslFilter
**user （用户方面）：**  org.apache.shiro.web.filter.authc.UserFilter

#####详细说明：
- rest:例子/admins/user/**=rest[user],根据请求的方法，相当于/admins/user/**=perms[user:method] ,其中method为post，get，delete等。
- port：例子/admins/user/**=port[8081],当请求的url的端口不是8081是跳转到schemal://serverName:8081?queryString,其中schmal是协议http或https等，serverName是你访问的host,8081是url配置里port的端口，queryString是你访问的url里的？后面的参数。
- perms：例子/admins/user/**=perms[user:add:*],perms参数可以写多个，多个时必须加上引号，并且参数之间用逗号分割，例如/admins/user/**=perms["user:add:*,user:modify:*"]，当有多个参数时每个参数都通过才通过，想当于isPermitedAll()方法。
- roles：例子/admins/user/** =roles[admin],参数可以写多个，多个时须加上引号，参数之间用逗号分割，当有多个参数时，
例如： /admins/user/**=roles["admin,guest"],每个参数通过才算通过，相当于hasAllRoles()方法。
- anon:例子/admins/**=anon 没有参数，表示可以匿名使用。
- authc:例如/admins/user/**=authc表示需要认证才能使用，没有参数。
- authcBasic：例如/admins/user/**=authcBasic没有参数表示httpBasic认证。
- ssl:例子/admins/user/**=ssl没有参数，表示安全的url请求，协议为https。
- user:例如/admins/user/**=user没有参数表示必须存在用户，当登入操作时不做检查。

这些过滤器分为两组，一组是认证过滤器，一组是授权过滤器。
**认证过滤器：**anon，authcBasic，auchc，user
**授权过滤器：**perms，roles，ssl，rest，port

### 自定义Shiro过滤器
自定义授权过滤器只需要继承AuthorizationFilter
自定义认证过滤器只需要继承

下面是一个自定义授权过滤器案例:

1. 编写自定义授权过滤器类
```
package com.pyy.shiro.filter;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authz.AuthorizationFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * 自定义授权过滤器
 * Created by Administrator on 2018/7/1 0001.
 */
public class RolesOrFilter extends AuthorizationFilter {
    @Override
    protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object o) throws Exception {
        Subject subject = getSubject(servletRequest, servletResponse);
        String[] roles = (String[])o;
        if(roles == null || roles.length == 0) {
            return true;
        }
        // 只要有一个角色符合条件即认证成功
        for(String role : roles) {
            if(subject.hasRole(role)){
                return true;
            }
        }
        return false;
    }
}
```
2. 配置过滤器链
```
 /**
     * ShiroFilterFactoryBean 处理拦截资源文件问题。
     * 注意：单独一个ShiroFilterFactoryBean配置是会报错的，因为在初始化ShiroFilterFactoryBean的时候需要注入：SecurityManager
     *
     * Filter Chain定义说明 1、一个URL可以配置多个Filter，使用逗号分隔 2、当设置多个过滤器时，全部验证通过，才视为通过
     * 3、部分过滤器可指定参数，如perms，roles
     *
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(org.apache.shiro.mgt.SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

        // 必须设置 SecurityManager
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        shiroFilterFactoryBean.setLoginUrl("/login.html");
        // 登录成功后要跳转的链接
        shiroFilterFactoryBean.setSuccessUrl("/index.html");
        // 未授权界面;
        shiroFilterFactoryBean.setUnauthorizedUrl("/403.html");

        //自定义拦截器
        Map<String, Filter> filtersMap = new LinkedHashMap<>();
        filtersMap.put("roleOr", new RolesOrFilter());
        shiroFilterFactoryBean.setFilters(filtersMap);

        // 权限控制map.过滤器链
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
        filterChainDefinitionMap.put("/login", "anon");
        filterChainDefinitionMap.put("/testRoles1", "roleOr[user]");
        filterChainDefinitionMap.put("/*", "authc");


        // 配置不会被拦截的链接 顺序判断
        // 配置退出过滤器,其中的具体的退出代码Shiro已经替我们实现了
        // 从数据库获取动态的权限
        // filterChainDefinitionMap.put("/add", "perms[权限添加]");
        // <!-- 过滤链定义，从上向下顺序执行，一般将 /**放在最为下边 -->:这是一个坑呢，一不小心代码就不好使了;
        // <!-- authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问-->
        //logout这个拦截器是shiro已经实现好了的。
        // 实际开发中需要从数据库获取
        /*
        List<SysPermissionInit> list = sysPermissionInitService.selectAll();

        for (SysPermissionInit sysPermissionInit : list) {
            filterChainDefinitionMap.put(sysPermissionInit.getUrl(), sysPermissionInit.getPermissionInit());
        }
        */

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }
```

###Shiro会话管理

![](https://upload-images.jianshu.io/upload_images/11464886-a34ca43d87ddbebb.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

这里我们使用Redis实现session共享所以
1. 首先导入redis依赖包
```
		<dependency>
			<groupId>redis.clients</groupId>
			<artifactId>jedis</artifactId>
			<version>2.9.0</version>
		</dependency>
```
2. Redis配置
```
 ##### redis 配置 ####
  redis:
    host: localhost
    password:
    port: 6379
    pool:
      max-idle: 100
      min-idle: 1
      max-active: 1000
      max-wait: -1
```
3.编写RedisUtil工具类方便操作redis缓存
```
package com.pyy.shiro.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;

import java.util.Set;

/**
 * Created by Administrator on 2018/7/1 0001.
 */
@Component
public class RedisUtil {

    @Autowired
    JedisPool jedisPool;

    private Jedis getResource() {
        return jedisPool.getResource();
    }

    public void set(byte[] key, byte[] value) {
        Jedis jedis = getResource();
        try {
            jedis.set(key, value);
        } finally{
            jedis.close();
        }
    }

    public void expire(byte[] key, int time) {
        Jedis jedis = getResource();
        try {
            jedis.expire(key, time);
        } finally{
            jedis.close();
        }
    }

    public byte[] get(byte[] key) {
        Jedis jedis = getResource();
        try {
            return jedis.get(key);
        } finally{
            jedis.close();
        }
    }

    public void del(byte[] key) {
        Jedis jedis = getResource();
        try {
            jedis.del(key);
        } finally{
            jedis.close();
        }
    }

    public Set<byte[]> keys(String shiroShiroPrefix) {
        Jedis jedis = getResource();
        try {
            return jedis.keys((shiroShiroPrefix + "*").getBytes());
        } finally{
            jedis.close();
        }
    }
}
```
4. RedisConfig配置类编写
```
package com.pyy.shiro.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

@Configuration
@EnableCaching
public class RedisConfig {

    @Value("${spring.redis.host}")
    private String host;

    @Value("${spring.redis.port}")
    private int port;

    @Value("${spring.redis.pool.max-idle}")
    private int maxIdle;

    @Value("${spring.redis.pool.max-wait}")
    private long maxWaitMillis;

    @Value("${spring.redis.password}")
    private String password;

    @Bean
    public JedisPool redisPoolFactory() {
        JedisPoolConfig jedisPoolConfig = new JedisPoolConfig();
        jedisPoolConfig.setMaxIdle(maxIdle);
        jedisPoolConfig.setMaxWaitMillis(maxWaitMillis);

        JedisPool jedisPool = new JedisPool(jedisPoolConfig, host, port);

        return jedisPool;
    }

}
```
5. 自定义SessionDAO，使用redis完成session的存取
```
package com.pyy.shiro.session;

import com.pyy.shiro.util.RedisUtil;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.eis.AbstractSessionDAO;
import org.apache.shiro.util.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.SerializationUtils;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by Administrator on 2018/7/1 0001.
 */
public class RedisSessionDAO extends AbstractSessionDAO {

    @Autowired
    private RedisUtil redisUtil;

    private static final String SHIRO_SHIRO_PREFIX = "pyy-session";

    /**
     * 使用sessionId + 前缀的二进制形式作为key
     * @param key
     * @return
     */
    private byte[] getKey(String key) {
        return (SHIRO_SHIRO_PREFIX + key).getBytes();
    }

    private void saveSession(Session session) {
        byte[] key = getKey(session.getId().toString());
        // 序列化为byte数组
        byte[] value = SerializationUtils.serialize(session);

        redisUtil.set(key, value);
        redisUtil.expire(key, 600);//10分钟
    }

    @Override
    protected Serializable doCreate(Session session) {
        Serializable sessionId = generateSessionId(session);
        assignSessionId(session, sessionId);
        saveSession(session);
        return sessionId;
    }



    @Override
    protected Session doReadSession(Serializable sessionId) {
        System.out.println("read session");
        if(sessionId == null) {
            return null;
        }
        byte[] key = getKey(sessionId.toString());
        byte[] value = redisUtil.get(key);
        // 反序列化为sesison对象
        return (Session) SerializationUtils.deserialize(value);
    }

    @Override
    public void update(Session session) throws UnknownSessionException {
        saveSession(session);
    }

    @Override
    public void delete(Session session) {
        if(session == null || session.getId() == null){
            return;
        }
        byte[] key = getKey(session.getId().toString());
        redisUtil.del(key);
    }

    @Override
    public Collection<Session> getActiveSessions() {
        Set<byte[]> keys = redisUtil.keys(SHIRO_SHIRO_PREFIX);
        Set<Session> sessions = new HashSet<>();
        if(CollectionUtils.isEmpty(keys)) {
            return sessions;
        }
        for(byte[] key : keys) {
            Session session = (Session) SerializationUtils.deserialize(redisUtil.get(key));
            sessions.add(session);
        }
        return sessions;
    }

}

```
6. 自定义SessionManager减少session读取次数
```
package com.pyy.shiro.session;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionKey;

import javax.servlet.ServletRequest;
import java.io.Serializable;

/**
 * 自定义sessionManager 用了减少多次访问redis问题
 * Created by Administrator on 2018/7/1 0001.
 */
public class CustomSessionManager extends DefaultWebSessionManager {
    @Override
    protected Session retrieveSession(SessionKey sessionKey) throws UnknownSessionException {
        Serializable sessionId = getSessionId(sessionKey);
        ServletRequest request = null;
        if(sessionKey instanceof WebSessionKey) {
            request = ((WebSessionKey)sessionKey).getServletRequest();
        }
        // 先从request中获取session
        if(request != null && sessionId != null){
            Session session = (Session) request.getAttribute(sessionId.toString());
            if(session != null) {
                return session;
            }
        }

        // 如果request中没有获取到，从原始方法（redis）中获取，存入到request中
        Session session = super.retrieveSession(sessionKey);
        if(request != null && sessionId != null) {
            request.setAttribute(sessionId.toString(), session);
        }

        return session;
    }
}
```
7. 配置SessionDAO和SessionManager
```
@Bean
    public SessionManager sessionManager(){
        CustomSessionManager sessionManager = new CustomSessionManager();
        sessionManager.setSessionDAO(redisSessionDAO());

        return sessionManager;
    }

    @Bean
    public RedisSessionDAO redisSessionDAO(){
        RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
        return redisSessionDAO;
    }
```

### Shiro缓存管理
![](https://upload-images.jianshu.io/upload_images/11464886-71c75b8d63d585c2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

使用Redis完成Shiro的cache案例：
1. 编写RedisCache类
```
package com.pyy.shiro.cache;

import com.pyy.shiro.util.RedisUtil;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.SerializationUtils;

import java.util.Collection;
import java.util.Set;

/**
 * Created by Administrator on 2018/7/2 0002.
 */
@Component
public class RedisCache<K, V> implements Cache<K, V>{

    private final String CACHE_PREFIX = "pyy-cache";

    @Autowired
    private RedisUtil redisUtil;

    private byte[] getKey(K k) {
        if(k instanceof String) {
            return (CACHE_PREFIX + k).getBytes();
        }
        return SerializationUtils.serialize(k);
    }

    @Override
    public V get(K k) throws CacheException {
        // 这里扩展可以加入echache二级缓存机制
        System.out.println("从redis中获取用户角色数据");
        byte[] value = redisUtil.get(getKey(k));
        if(value != null) {
            return (V) SerializationUtils.deserialize(value);
        }
        return null;
    }

    @Override
    public V put(K k, V v) throws CacheException {
        System.out.println("将获取用户角色数据存入到redis中");
        byte[] key = getKey(k);
        byte[] value = SerializationUtils.serialize(v);

        redisUtil.set(key, value);
        redisUtil.expire(key, 600);
        return v;
    }

    @Override
    public V remove(K k) throws CacheException {
        byte[] key = getKey(k);
        byte[] value = redisUtil.get(key);
        redisUtil.del(key);
        if(value != null) {
            return (V) SerializationUtils.deserialize(value);
        }
        return null;
    }

    @Override
    public void clear() throws CacheException {

    }

    @Override
    public int size() {
        return 0;
    }

    @Override
    public Set<K> keys() {
        return null;
    }

    @Override
    public Collection<V> values() {
        return null;
    }
}
```
2. 编写CacheManager类
```
package com.pyy.shiro.cache;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Created by Administrator on 2018/7/2 0002.
 */
public class RedisCacheManager implements CacheManager {

    @Autowired
    private RedisCache redisCache;

    @Override
    public <K, V> Cache<K, V> getCache(String s) throws CacheException {
        return redisCache;
    }
}
```
3. 配置CacheManager
```
    @Bean
    public org.apache.shiro.mgt.SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();

        CustomRealm customRealm = customRealm();
        // 2.加密配置
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");//设置加密算法名称
        matcher.setHashIterations(1);//设置加密次数
        customRealm.setCredentialsMatcher(matcher);

        // 设置Realm
        securityManager.setRealm(customRealm);
        // 设置sessionManager
        securityManager.setSessionManager(sessionManager());
        // 设置CacheManager
        securityManager.setCacheManager(redisCacheManager());
        return securityManager;
    }

```
此时系统如果是第一次进入，会先从数据库查询，会将查询结果存入到redis中，下次就会从redis缓存中获取。



