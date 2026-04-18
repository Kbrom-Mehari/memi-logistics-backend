package com.memilogistics.authservice.util;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Component;
import java.util.UUID;

@Component
public class RefreshTokenUtil {
    public String generateRawToken(){
        return UUID.randomUUID().toString() + UUID.randomUUID();
    }
    public String hash(String token){
        return DigestUtils.sha256Hex(token);
    }
}
