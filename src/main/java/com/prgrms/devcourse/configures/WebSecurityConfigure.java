package com.prgrms.devcourse.configures;

import com.prgrms.devcourse.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {

    private final Logger log = LoggerFactory.getLogger(getClass());

//        ==============JPA로 넘어오면서 필요 없어짐===============
//    private final DataSource dataSource;
//        ==============JPA로 넘어오면서 필요 없어짐===============

    private UserService userService;

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

//        ==============JPA로 넘어오면서 필요 없어짐===============
//    public WebSecurityConfigure(DataSource dataSource) {
//        this.dataSource = dataSource;
//    }
//        ==============JPA로 넘어오면서 필요 없어짐===============

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/assets/**", "/h2-console/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        ==============JPA로 넘어오면서 필요 없어짐===============
//        auth.jdbcAuthentication()
//                .dataSource(dataSource)
//                .usersByUsernameQuery(
//                        "SELECT " +
//                                "login_id, passwd, true " +
//                                "FROM " +
//                                "users " +
//                                "WHERE " +
//                                "login_id = ?"
//                )
//                .groupAuthoritiesByUsername(
//                        "SELECT " +
//                                "u.login_id, g.name, p.name " +
//                                "FROM " +
//                                "users u JOIN groups g ON u.group_id = g.id " +
//                                "LEFT JOIN group_permission gp ON g.id = gp.group_id " +
//                                "JOIN permissions p ON p.id = gp.permission_id " +
//                                "WHERE " +
//                                "u.login_id = ?"
//                )
//                .getUserDetailsService().setEnableAuthorities(false);
//        ==============JPA로 넘어오면서 필요 없어짐===============
        auth.userDetailsService(userService);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("ACCESS DENIED");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/me").hasAnyRole("USER", "ADMIN")
                .antMatchers("/admin").access("isFullyAuthenticated() and hasRole('ADMIN')")
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .defaultSuccessUrl("/")
                .permitAll()
                .and()
                /**
                 * Basic Authentication 설정
                 */
                .httpBasic()
                .and()
                /**
                 * remember me 설정
                 */
                .rememberMe()
                .rememberMeParameter("remember-me")
                .tokenValiditySeconds(300)
                .and()
                /**
                 * 로그아웃 설정
                 */
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .and()
                /**
                 * HTTP 요청을 HTTPS 요청으로 리다이렉트
                 */
                .requiresChannel()
                .anyRequest().requiresSecure()
                .and()
                /**
                 * 예외처리 핸들러
                 */
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler())
        ;
    }

}
