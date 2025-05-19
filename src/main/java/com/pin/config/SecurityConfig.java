package com.pin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true) // Habilita todas as anotações de segurança de método
public class SecurityConfig {

    // O PasswordEncoder não é mais necessário aqui se as senhas são gerenciadas pelo Keycloak
    // @Bean
    // public PasswordEncoder passwordEncoder() {
    //     return new BCryptPasswordEncoder();
    // }

    // O AuthenticationManager bean como configurado antes para autenticação com username/password
    // não é diretamente usado da mesma forma quando a autenticação é delegada ao Keycloak.
    // @Bean
    // public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
    //     return authenticationConfiguration.getAuthenticationManager();
    // }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable()) // CSRF geralmente desabilitado para APIs stateless
                .authorizeHttpRequests(authz -> authz
                        // Endpoints públicos (ex: documentação da API, se houver)
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/swagger-resources/**").permitAll()

                        // Exemplo: Permitir criação de usuário (UserEntity local) se você ainda tiver um endpoint para isso
                        // que não seja o processo de autenticação principal. Geralmente, isso não é necessário se os usuários
                        // são criados/sincronizados a partir do token do Keycloak.
                        // .requestMatchers(HttpMethod.POST, "/api/user/register-local-mirror").permitAll() // Endpoint hipotético

                        // Protegendo endpoints baseados em roles do Keycloak:
                        // Use os nomes exatos dos roles como definidos no Keycloak (ex: "ADMIN", "USER")
                        // Como usamos setAuthorityPrefix(""), não precisamos do prefixo "ROLE_".
                        .requestMatchers(HttpMethod.GET, "/api/user/findAll").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/user/auth/user-id").authenticated() // Exemplo de endpoint que requer autenticação

                        // Permissões para /api/item
                        .requestMatchers(HttpMethod.GET, "/api/item/findAll").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/item/save").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.GET, "/api/item/findById").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/item/update").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/item/delete").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/api/item/**").authenticated() // Catch-all para outros /api/item

                        // Permissões para /api/grupo
                        .requestMatchers("/api/grupo/**").hasAnyRole("USER", "ADMIN")

                        // Permissões para /api/evento
                        .requestMatchers("/api/evento/**").hasAnyRole("USER", "ADMIN")

                        // Qualquer outra requisição para /api/** deve ser autenticada
                        .requestMatchers("/api/**").authenticated()

                        // Permite qualquer outra requisição não listada (ajuste conforme sua política de segurança)
                        .anyRequest().permitAll() // CUIDADO: Em produção, talvez você queira .anyRequest().denyAll() ou .authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // Remove o prefixo padrão "SCOPE_" e "ROLE_"
        grantedAuthoritiesConverter.setAuthorityPrefix("");
        // Configura de onde pegar os nomes das authorities (roles).
        // Ajuste esta claim se você configurou diferente no Keycloak (ex: "resource_access.backend.roles" ou uma claim customizada "roles")
        grantedAuthoritiesConverter.setAuthoritiesClaimName("realm_access.roles");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        // Configura o Spring Security para usar a claim 'sub' (Subject - ID do usuário no Keycloak)
        // como o "name" do Principal no SecurityContext. Isso é útil para identificação única.
        jwtAuthenticationConverter.setPrincipalClaimName(JwtClaimNames.SUB);
        return jwtAuthenticationConverter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Permite requisições do seu frontend Angular (ajuste a porta se necessário)
        configuration.setAllowedOrigins(List.of("http://localhost:4200")); // URL do seu frontend Angular
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
        ));
        configuration.setExposedHeaders(Arrays.asList(
                "Origin",
                "Content-Type",
                "Accept",
                "Authorization",
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials"
        ));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L); // Cache das configurações de pre-flight request por 1 hora

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Aplica a configuração a todos os paths
        return source;
    }


}