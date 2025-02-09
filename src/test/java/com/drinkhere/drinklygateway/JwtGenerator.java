package com.drinkhere.drinklygateway;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;

public class JwtGenerator {
    public static void main(String[] args) {
        String secretKey = "G8uh1hrk5x+VwOYlUapX0pQwA9myLE8dzhakNxLFZvc=";  // Gateway 서버에서 사용 중인 Secret Key 입력
//        String secretKey = "ThisIsMySuperSecureSecretKeyWithMoreThan32Bytes!";

        String jwt = Jwts.builder()
                .claim("user-id", "1")
                .setExpiration(new Date(System.currentTimeMillis() + 86400000)) // 1일 후 만료
                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes())
                .compact();

        System.out.println("Generated JWT: " + jwt);
    }
}
