package org.jt.tech_trekker.config;

import org.jt.tech_trekker.repository.WriterInfoRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import lombok.var;

@Configuration
public class Securityconfig {
    // Authentication
    @Bean
    UserDetailsService userDetailsService(WriterInfoRepository repository) {
        return username -> {
            var writer = repository.findByEmail(username).orElseThrow(
                    () -> new UsernameNotFoundException("user not found"));
            return User.builder()
                    .username(username).password(writer.getPassword())
                    .roles("")
                    .build();
        };
    }

    // Authorization
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                request -> request.requestMatchers("/", "/home", "/css/**", "/js/**", "/images/**")
                        .permitAll()
                        .requestMatchers("/", "/home", "/tech-trekker/*").permitAll()
                        .requestMatchers("/blog/image/*").permitAll()
                        .anyRequest().authenticated());

        http.formLogin(form -> form.loginPage("/login-page")
                .loginProcessingUrl("/login").permitAll());

        http.csrf(csrf -> csrf.ignoringRequestMatchers("/tech-trekker/signup", "/tech-trekker/view-all-search",
                "/login"));

        http.logout(logout -> logout.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                .logoutSuccessUrl("/").deleteCookies("JSESSIONID"));
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

}
