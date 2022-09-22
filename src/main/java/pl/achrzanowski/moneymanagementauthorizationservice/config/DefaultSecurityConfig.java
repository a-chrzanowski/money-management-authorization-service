package pl.achrzanowski.moneymanagementauthorizationservice.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.util.List;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class DefaultSecurityConfig {

    @Autowired
    private DataSource dataSource;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .anyRequest().authenticated()
                )
                .csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .formLogin(withDefaults());
        return httpSecurity.build();
    }

    @Bean
    @Profile("prod")
    UserDetailsManager userDetailsManager(){
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    @Profile({"dev","local"})
    UserDetailsManager userDetailsManagerWithUser(
            @Value("${dev-user.username}") String username,
            @Value("${dev-user.password}") String password,
            @Value("${dev-user.authority}") String authority){
        UserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        UserDetails userDetails = new User(username, password, List.of(new SimpleGrantedAuthority(authority)));
        jdbcUserDetailsManager.createUser(userDetails);
        return jdbcUserDetailsManager;
    }

}
