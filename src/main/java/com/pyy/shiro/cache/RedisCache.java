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
