import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;

class JwtTokenUtil {
    private static SecretKey SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static int ACCESS_TOKEN_EXPIREATION = 86400000;
    private static int REFRESH_TOKEN_EXPIREATION = 86400000 * 7;

    private static String USER_ID = "userId";

    static public String createAccessToken(User user) {
        HashMap<String, Object> claims = createUserClaims(user);
        return createToken(claims, ACCESS_TOKEN_EXPIREATION);
    }

    static public String createRefreshToken(User user) {
        HashMap<String, Object> claims = createUserClaims(user);
        return createToken(claims, REFRESH_TOKEN_EXPIREATION);
    }

    static private HashMap<String, Object> createUserClaims(User user) {
        HashMap<String, Object> claims = new HashMap();
        claims.put(USER_ID, user.id);
        return claims;
    }

    static private String createToken(HashMap<String, Object> claims, int expirationTimeInMillis) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(now + expirationTimeInMillis))
                .setIssuedAt(new Date(now))
                .signWith(SECRET_KEY).compact();
    }

    static public int extractUserId(String token) {
        Claims claims = extractClaims(token);
        return (int) claims.get(USER_ID);
    }
    static private Claims extractClaims(String token) {
        try {
            return Jwts.parserBuilder().setSigningKey(SECRET_KEY).build()
                    .parseClaimsJws(token).getBody();
        } catch (JwtException ex) {
            throw ex;
        }
    }
}