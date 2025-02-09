package org.example.marketplacebackend.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.function.Supplier;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

  @Value("${ALLOWED_ORIGINS:http://localhost:3000}")
  private String allowedOrigins;

  @Value("${CSRF_DOMAIN:}")
  private String csrfDomain;

  @Value("${CSRF_SAME_SITE:Lax}")
  private String csrfSameSite;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.cors(Customizer.withDefaults());

    CookieCsrfTokenRepository csrfRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();
    csrfRepo.setCookieCustomizer(cookieCsrfToken -> {
      cookieCsrfToken.sameSite(csrfSameSite);
      cookieCsrfToken.domain(csrfDomain);
    });

    http.csrf(csrf -> csrf
            .csrfTokenRepository(csrfRepo)
            .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
        )
        .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);

    http.authorizeHttpRequests(auth -> auth
        // allow OPTION requests
        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
        // don't require auth for these endpoints
        .requestMatchers(
            "/v1/accounts/login",
            "/v1/accounts/logout",
            "/v1/accounts/register",
            "/v1/accounts/*",
            "/v1/categories",
            "/v1/products",
            "/v1/products/**",
            "/img/**"
        )
        .permitAll()
        // require auth to access these endpoints
        .requestMatchers(
            "/v1/inbox",
            "/v1/inbox/*",
            "/v1/accounts",
            "/v1/accounts/password",
            "/v1/accounts/me",
            "/v1/tests/username",
            "/v1/orders",
            "/v1/orders/**",
            "/v1/watchlist",
            "/v1/watchlist/**"
        )
        .hasRole("USER")
    );

    http.formLogin(loginForm -> loginForm
            .loginProcessingUrl("/v1/accounts/login")
            .successHandler(new LoginSuccessHandlerImpl())
            .failureHandler(new LoginFailureHandlerImpl())
        )
        .logout(logoutConfigurer -> logoutConfigurer
            .logoutUrl("/v1/accounts/logout")
            .logoutSuccessHandler(new LogoutSuccessHandlerImpl())
            .deleteCookies("JSESSIONID")
        );

    // return HTTP 401 when a user tries to access an endpoint that they don't have access to,
    // instead of trying to redirect them to the default login page
    http.exceptionHandling(exceptionHandling -> exceptionHandling
        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration corsConfig = new CorsConfiguration();
    corsConfig.setAllowedOrigins(List.of(allowedOrigins.split(",")));
    corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    corsConfig.setAllowCredentials(true);
    corsConfig.setAllowedHeaders(List.of("Content-Type", "X-XSRF-TOKEN"));

    UrlBasedCorsConfigurationSource config = new UrlBasedCorsConfigurationSource();
    config.registerCorsConfiguration("/**", corsConfig);

    return config;
  }

}

final class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {

  private final CsrfTokenRequestHandler delegate = new XorCsrfTokenRequestAttributeHandler();

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
      Supplier<CsrfToken> csrfToken) {
    /*
     * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of
     * the CsrfToken when it is rendered in the response body.
     */
    this.delegate.handle(request, response, csrfToken);
  }

  @Override
  public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
    /*
     * If the request contains a request header, use CsrfTokenRequestAttributeHandler
     * to resolve the CsrfToken. This applies when a single-page application includes
     * the header value automatically, which was obtained via a cookie containing the
     * raw CsrfToken.
     */
    if (StringUtils.hasText(request.getHeader(csrfToken.getHeaderName()))) {
      return super.resolveCsrfTokenValue(request, csrfToken);
    }
    /*
     * In all other cases (e.g. if the request contains a request parameter), use
     * XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies
     * when a server-side rendered form includes the _csrf request parameter as a
     * hidden input.
     */
    return this.delegate.resolveCsrfTokenValue(request, csrfToken);
  }
}

final class CsrfCookieFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response,
      FilterChain filterChain)
      throws ServletException, IOException {
    CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
    // Render the token value to a cookie by causing the deferred token to be loaded
    csrfToken.getToken();

    filterChain.doFilter(request, response);
  }
}