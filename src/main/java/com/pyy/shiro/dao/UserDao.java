package com.pyy.shiro.dao;

import com.pyy.shiro.vo.User;

import java.util.List;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
public interface UserDao {
    User findUserByUsername(String username);

    List<String> findRolesByUsername(String username);
}
