package com.deekol.demomp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@SpringBootApplication
public class DemompApplication {

	@RequestMapping("/")
	public String hello(){
	    return "Test!";
	}
	
	public static void main(String[] args) {
		SpringApplication.run(DemompApplication.class, args);
	}

}
