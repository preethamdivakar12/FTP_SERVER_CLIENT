#include <stdio.h>                  
#include <string.h>                 
#include <sys/socket.h>             // Socket programming functions
#include <sys/stat.h>               // File status functions
#include <sys/sendfile.h>           // File transfer functions
#include <fcntl.h>                  // File control options
#include <arpa/inet.h>              // Definitions for internet operations
#include <unistd.h>                 // Symbolic constants and types
#include <stdlib.h>                 // Standard library functions
#include <stdbool.h>                // Boolean type and values
#include <pthread.h>                // POSIX thread functions
#include <dirent.h>                 // Directory entry functions
#include <openssl/ssl.h>            // OpenSSL SSL/TLS functions
#include <openssl/err.h>            // OpenSSL error handling functions

#define SERVER_PORT 12000           // Server port
#define MAX_FILES 1000              // Maximum number of files

struct Map {                        // Structure for mapping
    int key;                        // Key for mapping
    char val[100];                  // Value for mapping
} indexToFile[MAX_FILES];           // Mapping for index to file

int numberOfFiles = 0;              // Number of files

void* ConnectionHandler(void* ssl_desc); // Function to handle connections
bool authenticateUser(SSL* ssl);    // Function to authenticate user
char* GetFilenameFromRequest(char* request); // Function to extract filename from request
bool SendFileOverSocket(SSL* ssl, char* file_name); // Function to send file over socket
void* UploadHandler(SSL* ssl, char* file_name); // Function to handle file uploads
void listClientFiles(char* server_response); // Function to list client files
void listServerFiles(char* server_response); // Function to list server files

void listClientFiles(char* server_response) {
    DIR* d;                         // Directory stream
    struct dirent* dir;             // Directory entry structure
    d = opendir(".");               // Open current directory
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) { // If it is a regular file
                strcat(server_response, dir->d_name); // Append filename to response
                strcat(server_response, " "); // Append space
            }
        }
        closedir(d);                // Close directory stream
    }
}

void listServerFiles(char* server_response) {
    DIR* d;                         // Directory stream
    struct dirent* dir;             // Directory entry structure
    d = opendir(".");               // Open current directory
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG) { // If it is a regular file
                strcat(server_response, dir->d_name); // Append filename to response
                strcat(server_response, " "); // Append space
            }
        }
        closedir(d);                // Close directory stream
    }
}

int main(int argc, char** argv) {

    printf("Server started......!\n");
    printf("Waiting for client to connect..\n");
    // Initialize indexToFile with files in the server directory
    DIR* d;                         // Directory stream
    struct dirent* dir;             // Directory entry structure
    d = opendir("./server");        // Open server directory

    if (d) {
        while ((dir = readdir(d)) != NULL && numberOfFiles < MAX_FILES) {
            if (dir->d_type == DT_REG) { // If it is a regular file
                indexToFile[numberOfFiles].key = numberOfFiles + 1; // Map index to file
                strcpy(indexToFile[numberOfFiles].val, dir->d_name); // Store file name
                numberOfFiles++;        // Increment number of files
            }
        }
        closedir(d);                // Close directory stream
    }

    SSL_CTX* ctx;                   // SSL context
    SSL* ssl;                       // SSL object

    SSL_load_error_strings();       // Load SSL error strings
    SSL_library_init();             // Initialize SSL library

    ctx = SSL_CTX_new(SSLv23_server_method()); // Create new SSL context
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr); // Print SSL errors
        exit(1);                    // Exit program
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3); // Set SSL options
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); // Print SSL errors
        exit(1);                    // Exit program
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); // Print SSL errors
        exit(1);                    // Exit program
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n"); // Print error message
        exit(1);                    // Exit program
    }

    int socket_desc, socket_client, c = sizeof(struct sockaddr_in); // Socket descriptors
    struct sockaddr_in server, client; // Server and client address structures

    socket_desc = socket(AF_INET, SOCK_STREAM, 0); // Create socket
    if (socket_desc == -1) {
        perror("Could not create socket"); // Print error message
        return 1;                   // Return error
    }
    if (setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) // Set socket options
        perror("setsockopt(SO_REUSEADDR) failed");

    server.sin_family = AF_INET;    // Set address family
    server.sin_addr.s_addr = INADDR_ANY; // Set server IP
    server.sin_port = htons(SERVER_PORT); // Set server port

    if (bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0) { // Bind socket to address
        perror("Bind failed");      // Print error message
        return 1;                   // Return error
    }

    listen(socket_desc, 3);        // Listen for incoming connections
    while (socket_client = accept(socket_desc, (struct sockaddr*)&client, (socklen_t*)&c)) { // Accept incoming connection
        ssl = SSL_new(ctx);         // Create new SSL object
        SSL_set_fd(ssl, socket_client); // Set SSL file descriptor
        if (SSL_accept(ssl) <= 0) { // Perform SSL handshake
            ERR_print_errors_fp(stderr); // Print SSL errors
            close(socket_client);   // Close socket
            continue;               // Continue to next iteration
        }
        pthread_t sniffer_thread, client_thread; // Thread identifiers
        pthread_create(&sniffer_thread, NULL, ConnectionHandler, (void*)ssl); // Create thread for connection handler
    }

    if (socket_client < 0) {        // If accept failed
        perror("Accept failed");    // Print error message
        return 1;                   // Return error
    }
    
    SSL_CTX_free(ctx);              // Free SSL context
    return 0;                       // Return success
}

void* UploadHandler(SSL* ssl, char* file_name) {
    int file_size, file_desc;      // File size and descriptor
    char* data;                     // Data buffer
    SSL_read(ssl, &file_size, sizeof(int)); // Read file size
    data = malloc(file_size);       // Allocate memory for data
    file_desc = open(file_name, O_CREAT | O_EXCL | O_WRONLY, 0666); // Open file for writing
    //int bytesread = SSL_read(ssl, data, file_size); // Read file data
    int bytesread = recv(SSL_get_fd(ssl), data, file_size,0); // Read file data
    write(file_desc, data, file_size); // Write file data
    free(data);                     // Free data memory
    close(file_desc);               // Close file

    return 0;                       // Return success
}

void* ConnectionHandler(void* ssl_desc) {
    SSL* ssl = (SSL*)ssl_desc;      // SSL object
    char server_response[BUFSIZ], client_request[BUFSIZ], file_name[BUFSIZ]; // Buffers for communication
    struct sockaddr_in client;      // Client address structure
    
    if (!authenticateUser(ssl)) {   // Authenticate user
        printf("Authentication failed. Closing connection.\n"); // Print authentication failed message
        close(SSL_get_fd(ssl));     // Close SSL connection
        return 0;                   // Return
    }

   socklen_t len = sizeof(client); // Length of client address structure
    if (getpeername(SSL_get_fd(ssl), (struct sockaddr*)&client, &len) != -1) { // Get client address
        printf("Client connected. IP address: %s\n", inet_ntoa(client.sin_addr)); // Print client IP address
    }
    
    while (1) {
        bzero(client_request, sizeof(client_request)); // Clear request buffer
        if (SSL_read(ssl, client_request, sizeof(client_request)) == 0) { // Read client request
        printf("Client disconnected.\n"); 
            return 0;               // Return
	    //sleep(5);                // Sleep for 5 seconds
	    //continue;                // Continue loop
        }

        bzero(server_response, BUFSIZ); // Clear response buffer
        switch (client_request[0]) // Check request type
        {
            case 'l':               // List files
                {
                    if (client_request[1] == 's') { // List client files
                        char* file_name = strchr(client_request, ' '); // Get file name
                        if (strcmp(file_name + 1, "client") == 0) { // Check if client directory
                            listClientFiles(server_response); // List client files
                            printf("received ls from client, sending list of files in the ./client dir\n"); 
                        }
                        else if (strcmp(file_name + 1, "server") == 0) { // List server files
                            printf("received ls from client for server. Calling listServerFiles...\n"); 
                            listServerFiles(server_response); // List server files
                            printf("listServerFiles completed. Sending response to the client.\n"); 
                        }
                        SSL_write(ssl, server_response, strlen(server_response)); // Send response to client
                    }
                }
                break;

                case 'u':           // Upload file
                {
                    strcpy(file_name, GetFilenameFromRequest(client_request)); // Get filename from request
                    printf("received the file %s successfully\n", file_name);
                    UploadHandler(ssl, file_name); // Handle file upload
                }
                break;

                case 'd':           // Download file
                {
                    int file_index; // File index
                    if (sscanf(client_request, "Get %d", &file_index) == 1) { // Extract file index
                        if (file_index > 0 && file_index <= numberOfFiles)  { // Check if index is valid
                            file_index--; // Adjust index
                            strcpy(file_name, indexToFile[file_index].val); // Get filename
                            strcpy(server_response, "OK"); // Set response
                            SSL_write(ssl, server_response, strlen(server_response)); // Send response
                            SendFileOverSocket(ssl, file_name); // Send file
                        }
                        else {
                            strcpy(server_response, "NO"); // Set response
                            SSL_write(ssl, server_response, strlen(server_response)); // Send response
                        }
                    }
                }
                break;

                default:
                {
                    strcpy(file_name, GetFilenameFromRequest(client_request)); // Get filename from request
                    printf("Request received: %s\n", client_request); // Print request
                    if (access(file_name, F_OK) != -1) { // Check if file exists
                        strcpy(server_response, "OK"); // Set response
                        SSL_write(ssl, server_response, strlen(server_response)); // Send response
                        SendFileOverSocket(ssl, file_name); // Send file
                    } else {
                        strcpy(server_response, "NO"); // Set response
                        SSL_write(ssl, server_response, strlen(server_response)); // Send response
                    }
                }
                break;
         }
    }
    SSL_free(ssl);                  // Free SSL object
    
    // Client disconnected
    printf("Client disconnected.\n");
    return 0;                       // Return success
}

bool authenticateUser(SSL* ssl) {
    char username[BUFSIZ];          // Username buffer
    char password[BUFSIZ];          // Password buffer

    if (SSL_read(ssl, username, sizeof(username)) < 0) { // Read username
        perror("Error receiving username"); // Print error message
        return false;               // Return false
    }

    if (SSL_read(ssl, password, sizeof(password)) < 0) { // Read password
        perror("Error receiving password"); // Print error message
        return false;              
    }

    if (strcmp(username, "demo") == 0 && strcmp(password, "pass") == 0) { // Check credentials
        char auth_response[] = "OK"; // Authentication successful
        if (SSL_write(ssl, auth_response, sizeof(auth_response)) < 0) { // Send authentication response
            perror("Error sending authentication response"); // Print error message
            return false;      
        }
        return true;             
    } else {
        char auth_response[] = "NO"; // Authentication failed
        if (SSL_write(ssl, auth_response, sizeof(auth_response)) < 0) { // Send authentication response
            perror("Error sending authentication response"); 
            return false;          
        }
        return false;           
    }
}

char* GetFilenameFromRequest(char* request) {
    char* file_name = strchr(request, ' '); // Find first occurrence of space
    return file_name + 1;          // Return filename (excluding space)
}

bool SendFileOverSocket(SSL* ssl, char* file_name) {
    struct stat obj;                // File status structure
    int file_desc, file_size;       // File descriptor and size
    stat(file_name, &obj);          // Get file status
    file_desc = open(file_name, O_RDONLY); // Open file for reading
    file_size = obj.st_size;        // Get file size
    SSL_write(ssl, &file_size, sizeof(int)); // Send file size
    sendfile(SSL_get_fd(ssl), file_desc, NULL, file_size); // Send file
    close(file_desc);               // Close file

    return true;                    
}

