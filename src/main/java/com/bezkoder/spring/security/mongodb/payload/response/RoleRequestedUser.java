package com.bezkoder.spring.security.mongodb.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Set;

@Data
@AllArgsConstructor
public class RoleRequestedUser {
    private String id;
    private String username;
    private Set<String> requestedRoles;
}
