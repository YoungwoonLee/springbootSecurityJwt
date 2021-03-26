package com.chandler.security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SignupRequest {
	private String username;
	private String email;
	private String password;
	private String role;
}