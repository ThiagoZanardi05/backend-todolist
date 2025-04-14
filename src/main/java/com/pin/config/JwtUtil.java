package com.pin.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component; // Importar Component
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component // Torna JwtUtil um bean gerenciado pelo Spring
public class JwtUtil {

    // Injete a chave secreta do application.properties (que por sua vez vem da variável de ambiente)
    @Value("${jwt.secret}")
    private String secret; // Nome da variável onde a chave será armazenada

    private static final long EXPIRATION_TIME = 10 * 24 * 60 * 60 * 1000; // 10 dias em milissegundos

    // Armazena a chave de assinatura gerada (cache)
    private Key signingKey;

    // Método para obter a chave de assinatura, gerando-a apenas uma vez
    private Key getSigningKey() {
        if (this.signingKey == null) {
            // Verifica se a chave foi injetada (não é nula ou vazia)
            if (secret == null || secret.isEmpty()) {
                throw new IllegalStateException("JWT secret key is not configured! Set the JWT_SECRET environment variable or jwt.secret property.");
            }
            // Converte a string da chave secreta em bytes usando UTF-8
            byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
            // Cria e retorna uma Key segura apropriada para HMAC-SHA
            this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        }
        return this.signingKey;
    }

    /**
     * Gera um token JWT para o usuário.
     * @param username O nome de usuário (será o 'subject' do token).
     * @param role O papel/role do usuário (será uma claim personalizada).
     * @return A string do token JWT compactado.
     */
    public String generateToken(String username, String role) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("role", role); // Adiciona o papel como claim

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + EXPIRATION_TIME);

        Key key = getSigningKey(); // Obtém a chave de assinatura

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256) // Assina com a Key e o algoritmo
                .compact();
    }

    /**
     * Extrai todas as claims (dados) de um token JWT, validando a assinatura.
     * Lança exceção se o token for inválido ou expirado.
     * @param token A string do token JWT.
     * @return Um objeto Claims contendo os dados do token.
     */
    public Claims extractAllClaims(String token) {
        Key key = getSigningKey(); // Obtém a chave para verificação

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Valida o token (verifica assinatura e expiração) e extrai o username (subject).
     * @param token A string do token JWT.
     * @return O username se o token for válido e não expirado, caso contrário null.
     */
    public String validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            // parseClaimsJws já valida a expiração
            return claims.getSubject();
        } catch (Exception e) {
            System.err.println("Token validation failed: " + e.getMessage());
            return null; // Token inválido por qualquer motivo
        }
    }

    /**
     * Extrai o papel (role) da claim personalizada no token.
     * @param token A string do token JWT.
     * @return A string do papel se o token for válido e a claim existir, caso contrário null.
     */
    public String extractRole(String token) {
        try {
            Claims claims = extractAllClaims(token);
            if (claims.containsKey("role")) {
                return claims.get("role", String.class);
            } else {
                System.err.println("Token extraction failed: Claim 'role' not found.");
                return null;
            }
        } catch (Exception e) {
            // O erro já foi logado por extractAllClaims se a validação falhou
            return null;
        }
    }
}