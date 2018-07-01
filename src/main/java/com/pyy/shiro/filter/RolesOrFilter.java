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
