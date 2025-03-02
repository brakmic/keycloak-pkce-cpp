/**
 * @file transport.hpp
 * @brief Network transport interfaces for HTTP communication
 * @version 1.0
 * 
 * Defines the abstract interfaces for HTTP transport implementations,
 * allowing different networking backends to be used interchangeably.
 */

 #pragma once
 #include <string>
 #include <string_view>
 #include <memory>
 #include <unordered_map>
 
 namespace keycloak::http {
 
 /**
  * @struct Response
  * @brief HTTP response data structure
  */
 struct Response {
     int status_code{0};                               ///< HTTP status code
     std::string body;                                 ///< Response body
     std::unordered_map<std::string, std::string> headers;  ///< Response headers
 };
 
 /**
  * @class ITransport
  * @brief Base interface for HTTP transport implementations
  * 
  * Provides a protocol-agnostic interface for sending HTTP requests
  * and receiving responses.
  */
 class ITransport {
 public:
     virtual ~ITransport() = default;
 
     /**
      * @brief Send an HTTP request
      * 
      * @param host Host name or IP address
      * @param port Network port
      * @param method HTTP method (GET, POST, etc.)
      * @param path Request path
      * @param body Request body
      * @param headers Request headers
      * @return Response object with status code, headers, and body
      */
     virtual Response send_request(
         std::string_view host,
         std::string_view port,
         std::string_view method,
         std::string_view path,
         std::string_view body,
         const std::unordered_map<std::string, std::string>& headers) = 0;
 };
 
 /**
  * @brief Factory function for creating transport instances
  * @return Unique pointer to a transport implementation
  */
 std::unique_ptr<ITransport> create_default_transport();
 
 } // namespace keycloak::http
 