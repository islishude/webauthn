package main

type userResponse struct {
	Email string `json:"email"`
}
type sessionResponse struct {
	Authenticated bool          `json:"authenticated"`
	User          *userResponse `json:"user,omitempty"`
}
type authenticationResponse struct {
	OK   bool         `json:"ok"`
	User userResponse `json:"user"`
}
type debugCredentialResponse struct {
	OK        bool   `json:"ok"`
	Email     string `json:"email"`
	SignCount uint32 `json:"signCount"`
}
type errorResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}
