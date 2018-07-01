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
