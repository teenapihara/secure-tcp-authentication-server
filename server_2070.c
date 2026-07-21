#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>

#define PORT 50070
#define SID "1020"
#define MAX_PAYLOAD 4096
#define MAX_BUF 8192
#define STORAGE_PATH "/srv/ie2102/IT24102070/"
#define LOG_FILE "server_IT24102070.log"

typedef struct {
    char username[50];
    char salted_hash[150];
    int failed_attempts;
    time_t lockout_time;
} User;

User users[100];
int user_count = 0;


// Persistent audit logging
void write_log(const char *ip, int port, const char *user, const char *cmd, const char *res) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    time_t now = time(NULL);
    char *ts = ctime(&now);
    ts[strlen(ts)-1] = '\0'; 
    fprintf(f, "[%s] %s:%d | PID:%d | User:%s | CMD:%s | RES:%s\n", 
            ts, ip, port, getpid(), (user && strlen(user) > 0) ? user : "GUEST", cmd, res);
    fclose(f);
}


// Response formatting
void send_res(int sock, const char *status, int code, const char *msg) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s %d SID:%s %s\n", status, code, SID, msg);
    send(sock, buf, strlen(buf), 0);
}


// Salted Hashing
void generate_salt(char *salt, int len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < len; i++)
        salt[i] = charset[rand() % 36];
    salt[len] = '\0';
}

void hash_pass(const char *pass, const char *salt, char *out) {
    unsigned long hash = 5381;
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", pass, salt);
    for (int i = 0; combined[i] != '\0'; i++) {
        hash = ((hash << 5) + hash) + combined[i];
    }
    snprintf(out, 150, "%s:%lu", salt, hash);
}


// Persistence: Disk I/O
void save_user_to_disk(int idx) {
    char path[300], folder[200];
    snprintf(folder, sizeof(folder), "%s%s", STORAGE_PATH, users[idx].username);
    mkdir(folder, 0755);
    snprintf(path, sizeof(path), "%s/user.dat", folder);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n%s\n%d\n%ld\n", users[idx].username, users[idx].salted_hash, 
                users[idx].failed_attempts, (long)users[idx].lockout_time);
        fclose(f);
    }
}

void load_all_users() {
    DIR *dir = opendir(STORAGE_PATH);
    struct dirent *entry;
    if (!dir) return;
    while ((entry = readdir(dir)) != NULL && user_count < 100) {
        if (entry->d_name[0] == '.') continue;
        char path[300];
        snprintf(path, sizeof(path), "%s%s/user.dat", STORAGE_PATH, entry->d_name);
        FILE *f = fopen(path, "r");
        if (f) {
            fscanf(f, "%49s\n%149s\n%d\n%ld", users[user_count].username, users[user_count].salted_hash, 
                   &users[user_count].failed_attempts, &users[user_count].lockout_time);
            user_count++;
            fclose(f);
        }
    }
    closedir(dir);
}


// Username validation
int is_valid_name(const char *name) {
    int len = strlen(name);
    if (len < 3 || len > 20) return 0;
    for (int i = 0; i < len; i++) if (!isalnum(name[i])) return 0;
    return 1;
}


// Command processing
void process_payload(int sock, char *payload, char *ip, int port, char *token, char *current_user, time_t *last_act) {
    char cmd[50], arg1[50], arg2[50];
    int n = sscanf(payload, "%s %s %s", cmd, arg1, arg2);
    if (n < 1) return;

    for (int i = 0; cmd[i]; i++) cmd[i] = toupper(cmd[i]);

    // Session timeout (5 mins)
    if (strlen(token) > 0 && (time(NULL) - *last_act > 300)) {
        memset(token, 0, 100);
        memset(current_user, 0, 50);
        send_res(sock, "ERR", 401, "Session Expired");
        return;
    }
    *last_act = time(NULL);

    // REGISTER
    if (strcmp(cmd, "REGISTER") == 0 && n == 3) {
        if (!is_valid_name(arg1)) {
            send_res(sock, "ERR", 400, "Invalid Username");
            return;
        }
        char salt[17]; generate_salt(salt, 16);
        strcpy(users[user_count].username, arg1);
        hash_pass(arg2, salt, users[user_count].salted_hash);
        save_user_to_disk(user_count++);
        send_res(sock, "OK", 200, "Registered");
        write_log(ip, port, arg1, "REGISTER", "SUCCESS");
    } 

    // LOGIN
    else if (strcmp(cmd, "LOGIN") == 0 && n == 3) {
        User temp_user;
        int user_exists = 0;
        char user_path[300];
    
        snprintf(user_path, sizeof(user_path), "%s%s/user.dat", STORAGE_PATH, arg1);
        FILE *uf = fopen(user_path, "r");
    
        if (uf) {
            fscanf(uf, "%49s\n%149s\n%d\n%ld", 
                temp_user.username, 
                temp_user.salted_hash, 
                &temp_user.failed_attempts, 
                &temp_user.lockout_time);
            fclose(uf);
            user_exists = 1;
        }
    
        if (!user_exists) {
            send_res(sock, "ERR", 401, "User not found");
            write_log(ip, port, arg1, "LOGIN", "FAILED - User not found");
            return;
        }
    
        if (temp_user.lockout_time > time(NULL)) {
            send_res(sock, "ERR", 403, "Account locked. Try again later");
            write_log(ip, port, arg1, "LOGIN", "FAILED - Account locked");
            return;
        }

        for (int i = 0; i < user_count; i++) {
            if (strcmp(users[i].username, arg1) == 0) {
                char temp[150], check_hash[150];
                strcpy(temp, users[i].salted_hash);
                char *s = strtok(temp, ":");
                hash_pass(arg2, s, check_hash);

                if (strcmp(check_hash, users[i].salted_hash) == 0) {
                    snprintf(token, 100, "TK_%ld_%d", time(NULL), rand()%1000);
                    strcpy(current_user, users[i].username);
                    users[i].failed_attempts = 0;
                    save_user_to_disk(i);
                    send_res(sock, "OK", 200, token);
                    write_log(ip, port, arg1, "LOGIN", "SUCCESS");
                    return;
                } else {
                    users[i].failed_attempts++;
                    if (users[i].failed_attempts >= 3)
                        users[i].lockout_time = time(NULL) + 300;
                    save_user_to_disk(i);
                }
            }
        }
        send_res(sock, "ERR", 401, "Auth Failed");
        write_log(ip, port, arg1, "LOGIN", "FAILED");
    }

    // WHOAMI
    else if (strcmp(cmd, "WHOAMI") == 0) {
        if (strlen(token) == 0) {
            send_res(sock, "ERR", 401, "Login Required");
        } else {
            char msg[128];
            snprintf(msg, sizeof(msg), "User: %s (Session Active)", current_user);
            send_res(sock, "OK", 200, msg);
            write_log(ip, port, current_user, "WHOAMI", "SUCCESS");
        }
    }

    // LOGOUT
    else if (strcmp(cmd, "LOGOUT") == 0) {
        write_log(ip, port, current_user, "LOGOUT", "SUCCESS");
        memset(token, 0, 100);
        memset(current_user, 0, 50);
        send_res(sock, "OK", 200, "Logged Out");
    }

    else
        send_res(sock, "ERR", 400, "Unknown Command");
}


// Client handler
void handle_client(int c_sock, struct sockaddr_in c_addr) {
    char buf[MAX_BUF];
    int total_rec = 0;
    char token[100] = "", current_user[50] = "", ip_str[16];
    time_t last_act = time(NULL);
    int c_port = ntohs(c_addr.sin_port);
    inet_ntop(AF_INET, &c_addr.sin_addr, ip_str, 16);

    int req_count = 0;
    time_t start_win = time(NULL);

    while (1) {
        int n = recv(c_sock, buf + total_rec, MAX_BUF - total_rec - 1, 0);
        if (n <= 0) break;
        total_rec += n;
        buf[total_rec] = '\0';

        char *ptr = buf;
        while (1) {
            char *len_ptr = strstr(ptr, "LEN:");
            if (!len_ptr) break;

            int p_len = atoi(len_ptr + 4);
            char *nl = strchr(len_ptr, '\n');
            if (!nl) break; 

            char *p_start = nl + 1;
            if (buf + total_rec < p_start + p_len) break; 

            if (time(NULL) - start_win > 60) {
                start_win = time(NULL); req_count = 0;
            }
            if (++req_count > 20) {
                send_res(c_sock, "ERR", 429, "Too Many Requests");
            }
            else {
                char payload[MAX_PAYLOAD + 1];
                strncpy(payload, p_start, p_len);
                payload[p_len] = '\0';
                process_payload(c_sock, payload, ip_str, c_port, token, current_user, &last_act);
            }
            ptr = p_start + p_len;
        }
        int remaining = (buf + total_rec) - ptr;
        if (remaining > 0) 
            memmove(buf, ptr, remaining);
        total_rec = remaining;
    }
    close(c_sock);
}


// Zombie cleanup
void sigchld_handler(int s) { while(waitpid(-1, NULL, WNOHANG) > 0); }


// MAIN
int main() {
    int s_sock, c_sock;
    struct sockaddr_in s_addr, c_addr;
    socklen_t len = sizeof(c_addr);

    signal(SIGCHLD, sigchld_handler);
    srand(time(NULL));
    mkdir(STORAGE_PATH, 0755);
    load_all_users();

    s_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(PORT);

    if (bind(s_sock, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0) { 
        perror("Bind failed"); 
        exit(1);
    }
    listen(s_sock, 15);

    printf("SERVER IT24102070 (SID:%s) ACTIVE ON %d\n", SID, PORT);

    while (1) {
        c_sock = accept(s_sock, (struct sockaddr*)&c_addr, &len);
        if (fork() == 0) { 
            close(s_sock);
            handle_client(c_sock, c_addr);
            exit(0);
        }
        close(c_sock);
    }
    return 0;
}
