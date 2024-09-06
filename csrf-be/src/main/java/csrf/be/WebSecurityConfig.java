package csrf.be;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.*;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.function.Supplier;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    //http.csrf(q -> q.disable());
    CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
    cookieCsrfTokenRepository.setCookieCustomizer(q -> q.sameSite("strict"));
    http.csrf(q -> q.csrfTokenRepository(cookieCsrfTokenRepository).csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()));
    http.addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class);
    http.addFilterBefore(new CsrfCheckFilter(), CsrfFilter.class);

    http.cors(q -> q.disable());

    http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

    http.authorizeHttpRequests(auth -> auth.requestMatchers("/**").permitAll());
//    http.authorizeHttpRequests(auth -> auth
//            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
//            .requestMatchers(HttpMethod.GET, "/").permitAll()
//            .requestMatchers(HttpMethod.POST, "/").permitAll()
//            .requestMatchers("/**").denyAll());

    return http.build();
  }
}

final class SpaCsrfTokenRequestHandler extends CsrfTokenRequestAttributeHandler {
  private final CsrfTokenRequestHandler delegate = new XorCsrfTokenRequestAttributeHandler();

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
    this.delegate.handle(request, response, csrfToken);
  }

  @Override
  public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
    if (StringUtils.hasText(request.getHeader(csrfToken.getHeaderName()))) {
      return super.resolveCsrfTokenValue(request, csrfToken);
    }
    return this.delegate.resolveCsrfTokenValue(request, csrfToken);
  }
}

final class CsrfCookieFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
          throws ServletException, IOException {
    CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
    csrfToken.getToken();
    filterChain.doFilter(request, response);
  }
}

final class CsrfCheckFilter extends OncePerRequestFilter {
  private final Logger logger = LoggerFactory.getLogger(CsrfCheckFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
          throws ServletException, IOException {
    String key;
    key = "XSRF-TOKEN";
    logger.info("Header {}={}", key, request.getHeader(key));
    key = "X-CSRF-TOKEN";
    logger.info("Header {}={}", key, request.getHeader(key));

    if (request.getCookies() != null)
      Arrays.stream(request.getCookies())
            .filter(q -> q.getName().equals("XSRF-TOKEN"))
            .findFirst()
            .ifPresent(q -> logger.info("Cookie {}={}", q.getName(), q.getValue()));


    filterChain.doFilter(request, response);
  }
}
