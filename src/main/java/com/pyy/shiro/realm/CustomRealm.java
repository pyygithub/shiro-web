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
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
@Component("customRealm")
public class CustomRealm extends AuthorizingRealm{

    @Autowired
    private UserDao userDao;

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
     * 数据库查询凭证
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
     * 根据用户名获取数据库中的角色数据
     * @param username
     * @return
     */
    private Set<String> getRolesByUsername(String username) {
        System.out.println("从数据库中获取用户角色数据");
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
