#include <stdio.h>               // Standard I/O library
#include <sys/socket.h>          // Socket programming library
#include <arpa/inet.h>           // Definitions for internet operations
#include <sys/stat.h>            // File status library
#include <sys/sendfile.h>        // Send file library
#include <unistd.h>              // Standard symbolic constants and types
#include <fcntl.h>               // File control options
#include <stdlib.h>              // Standard library
#include <string.h>              // String manipulation library
#include <dirent.h>              // Directory entry library
#include <stdbool.h>             // Boolean types library
#include <openssl/ssl.h>         // OpenSSL library for SSL/TLS
#include <openssl/err.h>         // OpenSSL error handling library

#define MAX_FILES 100        // Maximum number of files


// Structure to map index to file name
struct Map
{
    int key; // Index
    char val[100]; // File name
};

struct Map indexToFile[MAX_FILES]; // Mapping for remote server files
struct Map localindexToFile[MAX_FILES]; // Mapping for local client files

char downloadedFiles[MAX_FILES][100]; // Array to store downloaded file names
int numDownloadedFiles = 0;           // Number of downloaded files

char uploadedFiles[MAX_FILES][100]; // Array to store uploaded file names
int numUploadedFiles = 0;              // Number of uploaded files
                
void sendCredentials(SSL *ssl);     // Function prototype for sending credentials

// Function to list client files
void listClientFiles()
{
    DIR *d;                 // Directory stream
    struct dirent *dir;      // Directory entry
       
    // Open current directory
    d = opendir(".");
    if (d)
    {
        int count = 1; // Counter for files
        // Iterate through directory entries
        while ((dir = readdir(d)) != NULL)
        {
            // Check if the entry is a regular file
            if (dir->d_type == DT_REG)
            {
                // Print file name with index
                printf("%d. %s\n", count, dir->d_name);
                // Map index to file name for local files
                localindexToFile[count - 1].key = count;
                strcpy(localindexToFile[count - 1].val, dir->d_name);
                count++; // Increment file count
            }
        }
        closedir(d); // Close directory
    }
}


// Function to print and make directory structure
void printAndMakeDir(char *str)
{
    char *pch; // Token pointer
    pch = strtok(str, " "); // Get first token
    int count = 1; // Counter for tokens
    memset(indexToFile, 0, sizeof(indexToFile)); // Initialize indexToFile array
    // Iterate through tokens
    while (pch != NULL)
    {
        // Print token with index
        printf("%d. %s\n", count, pch);
        // Map index to file name for server files
        indexToFile[count - 1].key = count;
        strcpy(indexToFile[count - 1].val, pch);
        pch = strtok(NULL, "  "); // Get next token
        count++; // Increment token count
    }
}


// Function to send a file over SSL socket
bool SendFileOverSocket(SSL *ssl, char *file_name)
{
    struct stat obj; // File status structure
    int file_desc, file_size; // File descriptors and size

    // Get file status
    stat(file_name, &obj);
    // Open file for reading
    file_desc = open(file_name, O_RDONLY);
    // Get file size
    file_size = obj.st_size;

    // Write file size to socket
    SSL_write(ssl, &file_size, sizeof(int));

    off_t offset = 0; // File offset
    int remain_data = file_size; // Remaining data to send
    ssize_t sent_bytes; // Sent bytes counter

    // Send file data in chunks
    while (((sent_bytes = sendfile(SSL_get_fd(ssl), file_desc, &offset, BUFSIZ)) > 0) && remain_data > 0)
    {
        remain_data -= sent_bytes; // Update remaining data
    }

    return true; // Return success
}

int main(int argc, char **argv)
{
    

    int socket_desc; // Socket descriptor
    struct sockaddr_in server; // Server address structure
    char request_msg[BUFSIZ], reply_msg[BUFSIZ]; // Request and reply messages
    char SERVER_IP[100], FILENAME[100]; // Server IP and file name

    if (argc < 3)
    {
        printf("usage ./client <SERVER_IP> <SERVER_PORT>\n"); // Print usage message
        exit(0); // Exit program
    }

    strcpy(SERVER_IP, argv[1]); // Copy server IP from command line argument
    int SERVER_PORT = atoi(argv[2]); // Convert server port to integer
    printf("%s %d\n", SERVER_IP, SERVER_PORT); // Print server IP and port
    int file_size, file_desc; // File size and descriptor
    char *data; // Data buffer

   

    SSL_CTX *ctx;               // SSL context
    SSL *ssl;                   // SSL structure

    SSL_load_error_strings();     // Load SSL error strings
    SSL_library_init();            // Initialize SSL library

    ctx = SSL_CTX_new(SSLv23_client_method()); // Create new SSL context
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr); // Print SSL errors
        exit(1);                    // Exit program
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2); // Set SSL options
    ssl = SSL_new(ctx);                        // Create new SSL structure

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);  // Create socket
    if (socket_desc == -1)
    {
        perror("Could not create socket");  // Print error message
        return 1;                           // Exit program
    }

    server.sin_addr.s_addr = inet_addr(SERVER_IP);  // Set server IP
    server.sin_family = AF_INET;                   // Set address family
    server.sin_port = htons(SERVER_PORT);           // Set server port

    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("Connection failed");                  // Print error message
        return 1;                                       // Exit program
    }

    SSL_set_fd(ssl, socket_desc);   // Set SSL file descriptor
    if (SSL_connect(ssl) != 1)
    {
        ERR_print_errors_fp(stderr);  // Print SSL errors
        exit(1);                     // Exit program
    }

    printf("----User Authentication:----  \n"); // Print connection success message

    while (1) {
        sendCredentials(ssl);                          // Send credentials to server
        SSL_read(ssl, reply_msg, sizeof(reply_msg));   // Read server response

        if (strcmp(reply_msg, "OK") == 0)              // Check if authentication is successful
        {
            printf("Authentication successful.\n");    // Print authentication success message
            
             printf("SSL connection established successfully with the ftp server.\n");
            printf("------------------------------------------\n");
            printf("S.No|  Setup process   \n");
            printf("------------------------------------------\n");
             printf("1. Directory listing - ls client\n");
             printf("2. Directory listing - ls server\n");
             printf("3. Upload files      - u\n");
             printf("4. Download files    - d\n");
             printf("5. EXIT              - bye\n");
            break; // Exit loop
        }
        else
        {
            printf("Authentication failed. Please try again.\n"); // Print authentication failure message
        }
    }

    while (1) {
        // Your existing code here...

        bzero(request_msg, sizeof(request_msg)); // Clear request message buffer
        printf("ftp>"); // Print FTP prompt
        fgets(request_msg, sizeof(request_msg), stdin); // Read user input
        request_msg[strcspn(request_msg, "\n")] = '\0'; // Remove newline character

        bzero(reply_msg, sizeof(reply_msg)); // Clear reply message buffer
	
	    switch (request_msg[0]) // Check the first character of the request message
	    {
	        case 'l': // List directory
                if (request_msg[1] == 's') { // Check for 'ls' command
                    char *file_name = strchr(request_msg, ' '); // Find the first space in the request message

                    if (file_name!=NULL) { // Check if file name is found
                        if (strcmp(file_name + 1, "client") == 0) { // Check if client directory is requested
                            listClientFiles(); // List client files
                        }
                        else if (strcmp(file_name + 1, "server") == 0) { // Check if server directory is requested
                            SSL_write(ssl, request_msg, strlen(request_msg)); // Write request message to server
                            SSL_read(ssl, reply_msg, sizeof(reply_msg)); // Read server response
                            //printf("Server response:\n%s\n", reply_msg); // Print server response
                            printAndMakeDir(reply_msg); // Print and make directory
                        }
                    }
                }
		break;

            case 'd': // Download file
		{
                    char *str = strchr(request_msg, ' ');     // Find the first space in the request message
                    int index = atoi(str + 1);               // Convert the index after the space to integer
                    strcpy(FILENAME, indexToFile[index - 1].val); // Copy the file name corresponding to the index
                    strcpy(request_msg, "Get ");             // Prepare the request message to download the file
                    strcat(request_msg, FILENAME);           // Append the file name to the request message

                    int bytessent = SSL_write(ssl, request_msg, strlen(request_msg)); // Write request message to server
                    int bytesrecvd = SSL_read(ssl, reply_msg, 2);                  // Read server response
         
                    if (strcmp(reply_msg, "OK") == 0) {                           // Check if server response is "OK"
                        int bytesrecvd = SSL_read(ssl, &file_size, sizeof(int)); // Read file size
                        data = malloc(file_size);                                // Allocate memory for file data
                        file_desc = open(FILENAME, O_CREAT | O_EXCL | O_WRONLY, 0666); // Open file for writing
                                                                    //bytesrecvd = SSL_read(ssl, data, file_size); // Read file data
                        bytesrecvd = recv(SSL_get_fd(ssl), data, file_size,0);    // Read file data
                        write(file_desc, data, file_size);                         // Write file data to file
                        printf("ftp>File %s downloaded successfully %d bytes received \n", FILENAME, file_size); // Print download success message
                        close(file_desc); // Close file

                        strcpy(downloadedFiles[numDownloadedFiles++], FILENAME);  // Store the downloaded file
                    } 
		    else {
                        fprintf(stderr, "Bad request\n");   // Print error message
                    }
                    bzero(FILENAME, sizeof(FILENAME));      // Clear file name buffer
                }
                break;

		case 'u':                                // Upload file
             { 
                 char *str = strchr(request_msg, ' ');             // Find the first space in the request message
                 int index = atoi(str + 1);                        // Convert the index after the space to an integer
                 strcpy(FILENAME, localindexToFile[index - 1].val);  // Copy the file name corresponding to the index
                 strcpy(request_msg, "u ");                         // Prepare the request message to upload the file
                 strcat(request_msg, FILENAME);                     // Append the file name to the request message

                 struct stat st;
                 stat(FILENAME, &st);
                 int file_size = st.st_size;                         // Get the file size

                 SSL_write(ssl, request_msg, strlen(request_msg));    // Write request message to the server
                 SendFileOverSocket(ssl, FILENAME);                   // Send file over the socket
                 printf("ftp>File %s uploaded successfully %d bytes \n", FILENAME, file_size); // Print upload success message
                                                    // Add the uploaded file to the list
                 strcpy(uploadedFiles[numUploadedFiles++], FILENAME); // Store the uploaded file
                 break;
               }


		case 'b': // Bye
		{
                    if (request_msg[1] == 'y' && request_msg[2] == 'e') { // Check for 'bye' command
                        printf("Closing the connection\n");             // Print closing connection message
                        close(socket_desc);                                 // Close socket
                        SSL_shutdown(ssl);                              // Shutdown SSL connection
                        SSL_free(ssl);                                    // Free SSL structure
                        SSL_CTX_free(ctx);                                     // Free SSL context
                        return 0;                                          
		    }
		}
		break;

		default:
                    fprintf(stderr, "Bad request\n"); // Print error message
		break;
	    }
        
    }

    return 0; // Exit program
}

// Function to send credentials over SSL
void sendCredentials(SSL *ssl)
{
    char username[BUFSIZ]; // Username buffer
    char password[BUFSIZ]; // Password buffer

    // Get username from user
    printf("Enter username: ");
    scanf("%s", username);
    getchar(); // Consume newline

    // Get password from user
    printf("Enter password: ");
    scanf("%s", password);
    getchar(); // Consume newline

    // Send username and password over SSL
    SSL_write(ssl, username, sizeof(username));
    SSL_write(ssl, password, sizeof(password));
}

