package com.bezkoder.spring.security.mongodb.payload.request;

import lombok.Data;

import java.util.Set;

@Data
public class UpdateUserRolesRequest {
    private String username;
    private Set<String> roles;
}
