package com.drinkhere.drinklygateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin("*")
@SpringBootApplication
public class DrinklyGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(DrinklyGatewayApplication.class, args);
    }

}
