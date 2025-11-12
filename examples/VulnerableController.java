package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;
import com.example.demo.model.User;
import com.example.demo.service.UserService;

@RestController
@RequestMapping("/api/users")
public class UserController {
    
    private final UserService userService;
    
    public UserController(UserService userService) {
        this.userService = userService;
    }
    
    @PostMapping
    public User createUser(@RequestBody User user) {  // VULNERABLE: Direct entity binding
        return userService.save(user);
    }
    
    @PutMapping("/{id}")
    public User updateUser(@PathVariable Long id, 
                          @RequestBody User user) {  // VULNERABLE: Direct entity binding + no validation
        user.setId(id);
        return userService.update(user);
    }
    
    @PatchMapping("/{id}")
    public User patchUser(@PathVariable Long id,
                         @RequestBody User user) {  // VULNERABLE
        return userService.patch(id, user);
    }
}

