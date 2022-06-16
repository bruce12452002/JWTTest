package home.bruce.JWTTest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.util.DigestUtils;

import java.sql.Date;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;

//@SpringBootTest
class JwtTestApplicationTests {
    private static final String SALT = "my salt";
    private static final Algorithm ALGORITHM = Algorithm.HMAC256(SALT);

    @Test
    void create() {
        Instant instant = LocalDateTime.now()
                .plusSeconds(30L)
                .toInstant(ZoneOffset.ofHours(8));

        String sign = JWT.create()
                .withClaim("id", 999)
                .withClaim("name", "monkey")
                .withExpiresAt(Date.from(instant))
                .sign(ALGORITHM);
        System.out.println(sign);
    }

    @Test
    void verify() {
        JWTVerifier jwtVerify = JWT.require(ALGORITHM).build();
        DecodedJWT decodeJWT = jwtVerify.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoibW9ua2V5IiwiaWQiOjk5OSwiZXhwIjoxNjU1Mjk3NjI3fQ.tWcB7aXnGtkVTChpyRV99QgoUP5EtMlTEXaEINFbX4s");
        decodeJWT.getClaims().forEach((k, v) ->
                System.out.println("key=" + k + ",value=" + v)
        );
        System.out.println(decodeJWT.getExpiresAt());
    }

    @Test
    void writeMyself() throws JSONException {
        Instant instant = LocalDateTime.now()
                .plusSeconds(30L)
                .toInstant(ZoneOffset.ofHours(8));

        JSONObject header = new JSONObject();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        JSONObject payload = new JSONObject();
        payload.put("id", 999);
        payload.put("name", "monkey");
        payload.put("exp", Date.from(instant));

        String jwtHeader = Base64.getEncoder().encodeToString(header.toString().getBytes());
        String jwtPayload = Base64.getEncoder().encodeToString(payload.toString().getBytes());

//        String signature = DigestUtils.md5DigestAsHex(payload.toString().getBytes());
        String signature = DigestUtils.md5DigestAsHex((payload + SALT).getBytes()); // 加鹽較難破解，所以鹽不可外流
        String jwt = jwtHeader + "." + jwtPayload + "." + signature;
        System.out.println(jwt);
    }

    @Test
    void md5() {
        final String test = "xxx";
        String signature = DigestUtils.md5DigestAsHex(test.getBytes());
        System.out.println(signature); // f561aaf6ef0bf14d4208bb46a4ccb3ad
        System.out.println(signature.equals(DigestUtils.md5DigestAsHex(test.getBytes())));
    }

    @Test
    void encodeBase64() {
        byte[] header = Base64.getDecoder().decode("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9");
        byte[] payload = Base64.getDecoder().decode("eyJuYW1lIjoibW9ua2V5IiwiaWQiOjk5OSwiZXhwIjoiVGh1IEp1biAxNiAxNTowNTo0NyBDU1QgMjAyMiJ9");

        System.out.println(new String(header));
        String p = new String(payload);
        System.out.println(p);
        final String signature = "272ebfa703ed05f96966cf8922f76b9e";
//        System.out.println(signature.equals(DigestUtils.md5DigestAsHex(payload)));
        System.out.println(signature.equals(DigestUtils.md5DigestAsHex((p + SALT).getBytes()))); // 鹽被知道就 GG 了
    }

}
