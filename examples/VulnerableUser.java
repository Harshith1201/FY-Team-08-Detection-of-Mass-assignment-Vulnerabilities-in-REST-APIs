package com.example.demo.model;

import javax.persistence.Entity;
import javax.persistence.Id;
import lombok.Data;

@Entity
@Data  // VULNERABLE: Generates setters for ALL fields
public class User {
    
    @Id
    private Long id;
    
    private String username;
    private String email;
    private String password;
    
    // Sensitive fields that should NOT be mass-assignable
    private boolean isAdmin;
    private String role;
    private double creditLimit;
    private boolean isActive;
}

