package com.pyy.shiro.dao.impl;

import com.pyy.shiro.dao.UserDao;
import com.pyy.shiro.vo.User;
import org.apache.shiro.util.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Created by Administrator on 2018/6/24 0024.
 */
@Repository("userDao")
public class UserDaoImpl implements UserDao {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public User findUserByUsername(String username) {
        String sql = "select username, password from users where username = ?";
        List<User> list = jdbcTemplate.query(sql, new String[]{username}, (resultSet, i) -> {
                User user = new User();
                user.setUsername(resultSet.getString("username"));
                user.setPassword(resultSet.getString("password"));
                return user;
        });
        if(CollectionUtils.isEmpty(list)){
            return null;
        }
        return list.get(0);
    }

    @Override
    public List<String> findRolesByUsername(String username) {
        String sql = "select role_name from user_role where user_name = ?";
        return jdbcTemplate.query(sql, new String[]{username}, (resultSet, i) -> {
                return resultSet.getString("role_name");
        });
    }
}
