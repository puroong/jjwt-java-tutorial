import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;

class Main {
    public static void main(String[] args) {
        User user = new User(1);
        String jwt = JwtTokenUtil.createAccessToken(user);
        System.out.println(jwt);
        System.out.println(JwtTokenUtil.extractUserId(jwt));
    }
}
