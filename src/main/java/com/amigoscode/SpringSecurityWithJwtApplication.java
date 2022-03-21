package com.amigoscode;

import com.amigoscode.domain.Role;
import com.amigoscode.domain.User;
import com.amigoscode.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityWithJwtApplication {

    public static void main(String[] args) {

        SpringApplication.run(SpringSecurityWithJwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //initial database user configurations
    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null, "User 1","user1","123", new ArrayList<>()));
            userService.saveUser(new User(null, "User 2","user2","123", new ArrayList<>()));
            userService.saveUser(new User(null, "User 3","user3","123", new ArrayList<>()));
            userService.saveUser(new User(null, "User 4","user4","123", new ArrayList<>()));

            userService.addRoleToUser("user1","ROLE_USER");
            userService.addRoleToUser("user1","ROLE_MANAGER");
            userService.addRoleToUser("user2","ROLE_MANAGER");
            userService.addRoleToUser("user3","ROLE_ADMIN");
            userService.addRoleToUser("user4","ROLE_SUPER_ADMIN");
            userService.addRoleToUser("user4","ROLE_ADMIN");
            userService.addRoleToUser("user4","ROLE_USER");

        };
    }

}
